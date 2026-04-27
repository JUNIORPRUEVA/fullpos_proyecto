import { PrismaClient } from '@prisma/client';
import { ElectronicInvoicingAuditService } from './electronic-invoicing-audit.service';
import { buildEcf } from '../utils/validation.utils';
import { CreateSequenceDto } from '../dto/sequence.dto';

export class SequenceService {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly audit: ElectronicInvoicingAuditService,
  ) {}

  async upsertSequence(companyId: number, dto: CreateSequenceDto, username: string, requestId?: string) {
    const prefix = `E${dto.documentTypeCode}`;
    const endNumber = dto.endNumber ?? dto.maxNumber;

    if (!endNumber) {
      throw {
        status: 400,
        message: 'El límite autorizado de la secuencia es requerido',
        errorCode: 'SEQUENCE_LIMIT_INVALID',
      };
    }

    if (dto.prefix && dto.prefix.trim().toUpperCase() !== prefix) {
      throw {
        status: 400,
        message: `El prefijo debe ser ${prefix} para el tipo ${dto.documentTypeCode}`,
        errorCode: 'SEQUENCE_PREFIX_INVALID',
      };
    }

    if (dto.startNumber < 1 || dto.currentNumber < 0 || endNumber <= dto.currentNumber || endNumber < dto.startNumber) {
      throw {
        status: 400,
        message: 'Revise el rango autorizado de la secuencia',
        errorCode: 'SEQUENCE_RANGE_INVALID',
      };
    }

    if (endNumber > 9999999999) {
      throw {
        status: 400,
        message: 'maxNumber no puede exceder 10 dígitos',
        errorCode: 'SEQUENCE_LIMIT_INVALID',
      };
    }

    const sequence = await this.prisma.electronicSequence.upsert({
      where: {
        companyId_branchId_documentTypeCode: {
          companyId,
          branchId: dto.branchId,
          documentTypeCode: dto.documentTypeCode,
        },
      },
      update: {
        prefix,
        currentNumber: dto.currentNumber,
        maxNumber: endNumber,
        status: dto.currentNumber >= endNumber ? 'EXHAUSTED' : dto.status,
      },
      create: {
        companyId,
        branchId: dto.branchId,
        documentTypeCode: dto.documentTypeCode,
        prefix,
        currentNumber: dto.currentNumber,
        maxNumber: endNumber,
        status: dto.currentNumber >= endNumber ? 'EXHAUSTED' : dto.status,
      },
    });

    await this.audit.log({
      companyId,
      eventType: 'sequence.upserted',
      eventSource: 'ADMIN',
      message: `Secuencia ${prefix} actualizada por ${username}`,
      payload: {
        branchId: dto.branchId,
        documentTypeCode: dto.documentTypeCode,
        startNumber: dto.startNumber,
        currentNumber: dto.currentNumber,
        endNumber,
        maxNumber: endNumber,
        status: sequence.status,
      },
      requestId,
    });

    return {
      ...sequence,
      startNumber: dto.startNumber,
      endNumber: sequence.maxNumber,
      maxNumber: sequence.maxNumber,
    };
  }

  async allocate(companyId: number, branchId: number, documentTypeCode: string, requestId?: string) {
    console.info('[electronic-invoicing.sequence] sequence.allocate_started', {
      companyId,
      branchId,
      documentTypeCode,
      currentNumber: null,
      endNumber: null,
      nextNumber: null,
      requestId,
    });

    for (let attempt = 0; attempt < 8; attempt += 1) {
      const sequence = await this.prisma.electronicSequence.findUnique({
        where: {
          companyId_branchId_documentTypeCode: {
            companyId,
            branchId,
            documentTypeCode,
          },
        },
      });

      if (!sequence) {
        throw {
          status: 404,
          message: `No existe secuencia para el tipo ${documentTypeCode}`,
          errorCode: 'SEQUENCE_NOT_FOUND',
        };
      }

      console.info('[electronic-invoicing.sequence] sequence.allocate_state', {
        companyId,
        branchId,
        documentTypeCode,
        currentNumber: sequence.currentNumber,
        endNumber: sequence.maxNumber,
        status: sequence.status,
        attempt,
      });

      if (sequence.status !== 'ACTIVE') {
        throw {
          status: 409,
          message: `La secuencia ${sequence.prefix} no está activa`,
          errorCode: 'SEQUENCE_NOT_ACTIVE',
        };
      }

      const nextNumber = sequence.currentNumber + 1;
      console.info('[electronic-invoicing.sequence] sequence.allocate_next_number', {
        companyId,
        branchId,
        documentTypeCode,
        currentNumber: sequence.currentNumber,
        endNumber: sequence.maxNumber,
        nextNumber,
      });

      if (nextNumber > sequence.maxNumber) {
        await this.prisma.electronicSequence.update({
          where: { id: sequence.id },
          data: { status: 'EXHAUSTED' },
        });

        console.warn('[electronic-invoicing.sequence] sequence.allocate_exhausted', {
          companyId,
          branchId,
          documentTypeCode,
          currentNumber: sequence.currentNumber,
          endNumber: sequence.maxNumber,
          nextNumber,
        });

        throw {
          status: 409,
          message: `La secuencia ${sequence.prefix} se agotó`,
          errorCode: 'SEQUENCE_EXHAUSTED',
        };
      }

      const status = nextNumber >= sequence.maxNumber ? 'EXHAUSTED' : 'ACTIVE';
      const updated = await this.prisma.electronicSequence.updateMany({
        where: {
          id: sequence.id,
          currentNumber: sequence.currentNumber,
          status: 'ACTIVE',
        },
        data: {
          currentNumber: nextNumber,
          status,
        },
      });

      if (updated.count !== 1) {
        continue;
      }

      const ecf = buildEcf(sequence.prefix, nextNumber);
      console.info('[electronic-invoicing.sequence] sequence.allocate_success', {
        companyId,
        branchId,
        documentTypeCode,
        currentNumber: sequence.currentNumber,
        endNumber: sequence.maxNumber,
        nextNumber,
        ecf,
      });

      await this.audit.log({
        companyId,
        eventType: 'sequence.allocated',
        eventSource: 'SYSTEM',
        message: `Secuencia ${sequence.prefix} asignó ${ecf}`,
        payload: {
          branchId,
          documentTypeCode,
          sequenceNumber: nextNumber,
        },
        requestId,
      });

      return {
        ecf,
        prefix: sequence.prefix,
        sequenceNumber: nextNumber,
      };
    }

    throw {
      status: 409,
      message: 'No se pudo asignar la secuencia por contención concurrente',
      errorCode: 'SEQUENCE_CONTENTION',
    };
  }
}
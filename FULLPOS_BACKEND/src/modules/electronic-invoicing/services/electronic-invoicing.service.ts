import crypto from 'crypto';
import { PrismaClient } from '@prisma/client';
import env from '../../../config/env';
import { DgiiXmlBuilderService } from './dgii-xml-builder.service';
import { DgiiSignatureService } from './dgii-signature.service';
import { DgiiSubmissionService } from './dgii-submission.service';
import { DgiiResultService } from './dgii-result.service';
import { ElectronicInvoicingMapperService } from './electronic-invoicing-mapper.service';
import { ElectronicInvoicingAuditService } from './electronic-invoicing-audit.service';
import { SequenceService } from './sequence.service';
import {
  loadPkcs12Certificate,
  loadPkcs12CertificateFromBuffer,
  resolveCertificateFilePath,
  assertCertificateIsCurrentlyValid,
} from '../utils/certificate.utils';
import { sha256Hex } from '../utils/hash.utils';
import { RegisterCertificateDto } from '../dto/certificate.dto';
import { CreateSequenceDto } from '../dto/sequence.dto';
import { CreateEcfDto } from '../dto/create-ecf.dto';
import { SendEcfDto } from '../dto/send-ecf.dto';
import { CreateCreditNoteDto } from '../dto/credit-note.dto';
import { OutboundInvoiceListFilters, SupportedDocumentTypeCode } from '../types/electronic-invoice.types';
import { UpsertElectronicConfigDto } from '../dto/config.dto';

const INLINE_CERTIFICATE_PREFIX = 'inline-p12:';

const ALLOWED_TRANSITIONS: Record<string, string[]> = {
  DRAFT: ['GENERATED', 'ERROR'],
  GENERATED: ['SIGNED', 'ERROR'],
  SIGNED: ['SUBMISSION_PENDING', 'ERROR'],
  SUBMISSION_PENDING: ['SUBMITTED', 'ACCEPTED', 'ACCEPTED_CONDITIONAL', 'REJECTED', 'ERROR'],
  SUBMITTED: ['ACCEPTED', 'ACCEPTED_CONDITIONAL', 'REJECTED', 'COMMERCIAL_APPROVED', 'COMMERCIAL_REJECTED', 'ERROR'],
  ACCEPTED: ['COMMERCIAL_APPROVED', 'COMMERCIAL_REJECTED', 'VOID_PENDING', 'ERROR'],
  ACCEPTED_CONDITIONAL: ['COMMERCIAL_APPROVED', 'COMMERCIAL_REJECTED', 'REJECTED', 'ERROR'],
  REJECTED: ['ERROR'],
  COMMERCIAL_APPROVED: ['VOID_PENDING', 'ERROR'],
  COMMERCIAL_REJECTED: ['ERROR'],
  VOID_PENDING: ['VOIDED', 'ERROR'],
  VOIDED: [],
  ERROR: ['GENERATED', 'SIGNED', 'SUBMISSION_PENDING'],
};

function getRequiredFeMasterKey() {
  const key = process.env.FE_MASTER_ENCRYPTION_KEY?.trim() || env.FE_MASTER_ENCRYPTION_KEY?.trim();
  if (!key) {
    throw {
      status: 503,
      message: 'La facturación electrónica requiere FE_MASTER_ENCRYPTION_KEY configurada',
      errorCode: 'FE_MASTER_ENCRYPTION_KEY_MISSING',
    };
  }

  return key;
}

function money(value: number) {
  return Math.round(value * 100) / 100;
}

function deriveSecretKey() {
  return crypto.createHash('sha256').update(getRequiredFeMasterKey()).digest();
}

function encryptSecret(secret: string) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', deriveSecretKey(), iv);
  const encrypted = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('base64')}.${tag.toString('base64')}.${encrypted.toString('base64')}`;
}

function decryptSecret(secret: string) {
  const [ivB64, tagB64, payloadB64] = secret.split('.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', deriveSecretKey(), Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(payloadB64, 'base64')),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}

function encryptBinarySecret(buffer: Buffer) {
  return encryptSecret(buffer.toString('base64'));
}

function decryptBinarySecret(secret: string) {
  return Buffer.from(decryptSecret(secret), 'base64');
}

function normalizeCertificateParseError(error: unknown) {
  const message = error instanceof Error ? error.message : String(error ?? 'Error desconocido');
  const lower = message.toLowerCase();

  if (lower.includes('invalid password') || lower.includes('mac could not be verified')) {
    return {
      status: 400,
      message: 'La contraseña del certificado es incorrecta',
      errorCode: 'ELECTRONIC_CERTIFICATE_PASSWORD_INVALID',
    };
  }

  return {
    status: 400,
    message: 'Archivo de certificado inválido o no legible',
    errorCode: 'ELECTRONIC_CERTIFICATE_INVALID_FILE',
  };
}

function isInlineCertificateReference(secretReference?: string | null) {
  return !!secretReference?.startsWith(INLINE_CERTIFICATE_PREFIX);
}

export class ElectronicInvoicingService {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly mapper: ElectronicInvoicingMapperService,
    private readonly sequenceService: SequenceService,
    private readonly xmlBuilder: DgiiXmlBuilderService,
    private readonly signatureService: DgiiSignatureService,
    private readonly submissionService: DgiiSubmissionService,
    private readonly resultService: DgiiResultService,
    private readonly audit: ElectronicInvoicingAuditService,
  ) {}

  private toJsonValue(value: unknown) {
    return value == null ? null : JSON.parse(JSON.stringify(value));
  }

  private async getEndpointConfig(companyId: number, branchId: number) {
    const config = await this.prisma.electronicInboundEndpointConfig.findUnique({
      where: { companyId_branchId: { companyId, branchId } },
    });
    if (!config) {
      throw {
        status: 409,
        message: 'La compañía no tiene configuración de facturación electrónica',
        errorCode: 'ELECTRONIC_CONFIG_MISSING',
      };
    }
    return config;
  }

  private async createStatusHistory(
    electronicInvoiceId: number,
    fromStatus: string | null,
    toStatus: string,
    note: string,
    createdBy: string,
    rawPayloadJson?: unknown,
  ) {
    await this.prisma.electronicInvoiceStatusHistory.create({
      data: {
        electronicInvoiceId,
        fromStatus,
        toStatus,
        note,
        rawPayloadJson: this.toJsonValue(rawPayloadJson),
        createdBy,
      },
    });
  }

  private async transitionInternalStatus(
    invoiceId: number,
    nextStatus: string,
    note: string,
    createdBy: string,
    patch: Record<string, unknown> = {},
    rawPayloadJson?: unknown,
  ) {
    const current = await this.prisma.electronicInvoice.findUnique({ where: { id: invoiceId } });
    if (!current) {
      throw { status: 404, message: 'Documento electrónico no encontrado', errorCode: 'ELECTRONIC_INVOICE_NOT_FOUND' };
    }

    const allowed = ALLOWED_TRANSITIONS[current.internalStatus] ?? [];
    if (current.internalStatus !== nextStatus && !allowed.includes(nextStatus)) {
      throw {
        status: 409,
        message: `Transición inválida ${current.internalStatus} -> ${nextStatus}`,
        errorCode: 'INVALID_STATUS_TRANSITION',
      };
    }

    const updated = await this.prisma.electronicInvoice.update({
      where: { id: invoiceId },
      data: {
        internalStatus: nextStatus as any,
        ...patch,
      },
    });
    await this.createStatusHistory(invoiceId, current.internalStatus, nextStatus, note, createdBy, rawPayloadJson);
    return updated;
  }

  async getConfig(companyId: number, branchId = 0) {
    return this.prisma.electronicInboundEndpointConfig.findUnique({
      where: { companyId_branchId: { companyId, branchId } },
    });
  }

  async upsertConfig(companyId: number, dto: UpsertElectronicConfigDto, username: string, requestId?: string) {
    const config = await this.prisma.electronicInboundEndpointConfig.upsert({
      where: { companyId_branchId: { companyId, branchId: dto.branchId } },
      update: { ...dto },
      create: { companyId, ...dto },
    });

    await this.audit.log({
      companyId,
      eventType: 'config.upserted',
      eventSource: 'ADMIN',
      message: `Configuración FE actualizada por ${username}`,
      payload: dto,
      requestId,
    });

    return config;
  }

  async resolveCertificateCompanyId(dto: RegisterCertificateDto) {
    if (dto.companyId != null) {
      const company = await this.prisma.company.findUnique({
        where: { id: dto.companyId },
        select: { id: true },
      });
      if (company) return company.id;
    }

    const companyCloudId = dto.companyCloudId?.trim();
    if (companyCloudId != null && companyCloudId.length > 0) {
      const company = await this.prisma.company.findFirst({
        where: { cloudCompanyId: companyCloudId },
        select: { id: true },
      });
      if (company) return company.id;
    }

    const companyRnc = dto.companyRnc?.trim();
    if (companyRnc != null && companyRnc.length > 0) {
      const company = await this.prisma.company.findFirst({
        where: { rnc: companyRnc },
        select: { id: true },
      });
      if (company) return company.id;
    }

    throw {
      status: 400,
      message: 'No se pudo identificar la empresa para el certificado',
      errorCode: 'ELECTRONIC_CERTIFICATE_COMPANY_REQUIRED',
    };
  }

  async registerCertificate(companyId: number, dto: RegisterCertificateDto, username: string, requestId?: string) {
    console.info('[electronic-invoicing.certificates] parsing_started', {
      companyId,
      alias: dto.alias,
      source: dto.certificateBuffer ? 'multipart' : dto.filePath ? 'filePath' : 'secretReference',
      originalName: dto.originalName ?? null,
      mimeType: dto.mimeType ?? null,
    });

    let loaded;
    try {
      if (dto.certificateBuffer) {
        loaded = loadPkcs12CertificateFromBuffer(dto.certificateBuffer, dto.password);
      } else {
        const certificatePath = resolveCertificateFilePath(dto.filePath, dto.secretReference);
        loaded = loadPkcs12Certificate(certificatePath, dto.password);
      }
    } catch (error) {
      const normalized = normalizeCertificateParseError(error);
      console.warn('[electronic-invoicing.certificates] parsing_failure', {
        companyId,
        alias: dto.alias,
        source: dto.certificateBuffer ? 'multipart' : dto.filePath ? 'filePath' : 'secretReference',
        originalName: dto.originalName ?? null,
        errorCode: normalized.errorCode,
        message: normalized.message,
      });
      throw normalized;
    }

    console.info('[electronic-invoicing.certificates] parsing_success', {
      companyId,
      alias: dto.alias,
      serial: loaded.serialNumber,
      validFrom: loaded.validFrom.toISOString(),
      validTo: loaded.validTo.toISOString(),
    });

    let status: 'ACTIVE' | 'EXPIRED' = 'ACTIVE';
    try {
      assertCertificateIsCurrentlyValid(loaded.validFrom, loaded.validTo);
    } catch {
      status = 'EXPIRED';
    }

    console.info('[electronic-invoicing.certificates] validation_result', {
      companyId,
      alias: dto.alias,
      status,
      expired: status === 'EXPIRED',
      validFrom: loaded.validFrom.toISOString(),
      validTo: loaded.validTo.toISOString(),
    });

    const storedSecretReference = dto.certificateBuffer
      ? `${INLINE_CERTIFICATE_PREFIX}${encryptBinarySecret(dto.certificateBuffer)}`
      : dto.secretReference ?? null;
    const storedFilePath = dto.certificateBuffer ? null : dto.filePath ?? null;

    const record = await this.prisma.electronicCertificate.upsert({
      where: { companyId_alias: { companyId, alias: dto.alias } },
      update: {
        filePath: storedFilePath,
        secretReference: storedSecretReference,
        passwordEncrypted: encryptSecret(dto.password),
        serialNumber: loaded.serialNumber,
        issuer: loaded.issuer,
        subject: loaded.subject,
        validFrom: loaded.validFrom,
        validTo: loaded.validTo,
        status,
      },
      create: {
        companyId,
        alias: dto.alias,
        filePath: storedFilePath,
        secretReference: storedSecretReference,
        passwordEncrypted: encryptSecret(dto.password),
        serialNumber: loaded.serialNumber,
        issuer: loaded.issuer,
        subject: loaded.subject,
        validFrom: loaded.validFrom,
        validTo: loaded.validTo,
        status,
      },
    });

    await this.audit.log({
      companyId,
      eventType: 'certificate.registered',
      eventSource: 'ADMIN',
      message: `Certificado ${dto.alias} registrado por ${username}`,
      payload: {
        alias: dto.alias,
        serialNumber: loaded.serialNumber,
        subject: loaded.subject,
        validFrom: loaded.validFrom,
        validTo: loaded.validTo,
        status,
        source: dto.certificateBuffer ? 'multipart' : 'reference',
      },
      requestId,
    });

    return {
      success: true,
      alias: record.alias,
      serial: record.serialNumber,
      validFrom: record.validFrom,
      validTo: record.validTo,
      ...(record.status === 'EXPIRED' ? { warning: 'El certificado está expirado, pero fue registrado' } : {}),
    };
  }

  upsertSequence(companyId: number, dto: CreateSequenceDto, username: string, requestId?: string) {
    return this.sequenceService.upsertSequence(companyId, dto, username, requestId);
  }

  private async createDraftInvoice(
    companyId: number,
    branchId: number,
    saleId: number | null,
    documentTypeCode: SupportedDocumentTypeCode,
    issuerRnc: string,
    issuerName: string,
    buyerRnc: string | null | undefined,
    buyerName: string | null | undefined,
    issueDate: Date,
    totalAmount: number,
    taxAmount: number,
    currencyCode: string,
    originalInvoiceId?: number | null,
  ) {
    const draft = await this.prisma.electronicInvoice.create({
      data: {
        companyId,
        branchId,
        saleId,
        originalInvoiceId: originalInvoiceId ?? null,
        direction: 'outbound',
        documentTypeCode,
        ecf: `PENDING-${Date.now()}`,
        sequenceNumber: 0,
        issuerRnc,
        issuerName,
        buyerRnc: buyerRnc ?? null,
        buyerName: buyerName ?? null,
        issueDate,
        totalAmount: money(totalAmount),
        taxAmount: money(taxAmount),
        currencyCode,
        dgiiStatus: 'NOT_SENT',
        commercialStatus: 'NONE',
        internalStatus: 'DRAFT',
      },
    });
    await this.createStatusHistory(draft.id, null, 'DRAFT', 'Borrador creado', 'system');
    return draft;
  }

  async generateOutbound(
    companyId: number,
    dto: CreateEcfDto & {
      saleLocalCode?: string | null;
      companyCloudId?: string | null;
      companyRnc?: string | null;
    },
    username: string,
    requestId?: string,
  ) {
    const config = await this.getEndpointConfig(companyId, dto.branchId);
    if (!config.outboundEnabled || !config.active) {
      throw {
        status: 409,
        message: 'La facturación electrónica real está deshabilitada para la compañía',
        errorCode: 'REAL_EI_DISABLED',
      };
    }

    const normalizedSaleLocalCode = dto.saleLocalCode?.trim() || null;
    const normalizedCompanyCloudId = dto.companyCloudId?.trim() || null;
    const normalizedCompanyRnc = dto.companyRnc?.trim() || null;

    console.info('[electronic-invoicing.outbound] generate_request_received', {
      companyId,
      saleId: dto.saleId,
      saleLocalCode: normalizedSaleLocalCode,
      documentTypeCode: dto.documentTypeCode,
      branchId: dto.branchId,
      requestId,
      payloadNormalized: {
        companyId,
        saleId: dto.saleId,
        saleLocalCode: normalizedSaleLocalCode,
        documentTypeCode: dto.documentTypeCode,
        branchId: dto.branchId,
        companyCloudId: normalizedCompanyCloudId,
        companyRnc: normalizedCompanyRnc,
      },
    });

    let mapped;
    try {
      mapped = await this.mapper.mapSaleToOutbound(
        companyId,
        dto.saleId,
        dto.documentTypeCode,
        {
          localCode: normalizedSaleLocalCode,
          companyCloudId: normalizedCompanyCloudId,
          companyRnc: normalizedCompanyRnc,
        },
      );
    } catch (error: any) {
      const errorCode = error?.errorCode ?? 'UNKNOWN_ERROR';
      const errorMessage = error?.message ?? 'Error desconocido';
      if (errorCode === 'SALE_NOT_FOUND') {
        console.error('[electronic-invoicing.outbound] sale_not_found_on_generate', {
          companyId,
          saleId: dto.saleId,
          saleLocalCode: normalizedSaleLocalCode,
          companyCloudId: normalizedCompanyCloudId,
          companyRnc: normalizedCompanyRnc,
          documentTypeCode: dto.documentTypeCode,
          branchId: dto.branchId,
          requestId,
          searchCriteria: {
            preferredByLocalCode: normalizedSaleLocalCode,
            fallbackById: dto.saleId,
            searchedByCompanyId: companyId,
          },
          errorMessage,
          errorCode,
        });
        throw {
          status: 404,
          message: `Venta no encontrada. saleId=${dto.saleId}, localCode=${normalizedSaleLocalCode || 'N/A'}, companyId=${companyId}, criterios=companyId+localCode -> companyId+id`,
          errorCode: 'SALE_NOT_FOUND',
          context: {
            saleId: dto.saleId,
            saleLocalCode: normalizedSaleLocalCode,
            companyId,
          },
        };
      }
      throw error;
    }
    const resolvedSaleId = mapped.saleIdResolved ?? dto.saleId;

    const existing = await this.prisma.electronicInvoice.findFirst({
      where: {
        companyId,
        saleId: resolvedSaleId,
        direction: 'outbound',
        documentTypeCode: dto.documentTypeCode,
        internalStatus: { notIn: ['VOIDED'] },
      },
    });
    if (existing) {
      throw {
        status: 409,
        message: 'Ya existe un documento electrónico generado para esta venta y tipo',
        errorCode: 'OUTBOUND_ALREADY_EXISTS',
      };
    }

    console.info('[electronic-invoicing.outbound] sale_found_and_mapped', { companyId, saleIdRequested: dto.saleId, saleIdResolved: resolvedSaleId, documentTypeCode: dto.documentTypeCode, mapped: { issuerRnc: mapped.issuer.rnc, issuerName: mapped.issuer.name, buyerRnc: mapped.buyer.rnc, buyerName: mapped.buyer.name, totalAmount: mapped.totalAmount, lineCount: mapped.lines.length } });
    const draft = await this.createDraftInvoice(
      companyId,
      dto.branchId,
      resolvedSaleId,
      dto.documentTypeCode,
      mapped.issuer.rnc ?? '',
      mapped.issuer.name,
      mapped.buyer.rnc,
      mapped.buyer.name,
      mapped.issueDate,
      mapped.totalAmount,
      mapped.taxAmount,
      mapped.currencyCode,
    );
    const allocation = await this.sequenceService.allocate(companyId, dto.branchId, dto.documentTypeCode, requestId);
    const xmlUnsigned = this.xmlBuilder.build({ ...mapped, ecf: allocation.ecf });

    const updated = await this.transitionInternalStatus(
      draft.id,
      'GENERATED',
      `XML generado para ${allocation.ecf}`,
      username,
      {
        ecf: allocation.ecf,
        sequenceNumber: allocation.sequenceNumber,
        xmlUnsigned,
      },
      { saleId: resolvedSaleId, requestedSaleId: dto.saleId, documentTypeCode: dto.documentTypeCode },
    );

    await this.audit.log({
      companyId,
      invoiceId: updated.id,
      eventType: 'outbound.generated',
      eventSource: 'ADMIN',
      message: `Documento ${updated.ecf} generado desde venta ${resolvedSaleId}`,
      payload: dto,
      requestId,
    });

    return updated;
  }

  private async getActiveCertificate(companyId: number) {
    const certificate = await this.prisma.electronicCertificate.findFirst({
      where: { companyId, status: 'ACTIVE' },
      orderBy: { updatedAt: 'desc' },
    });
    if (!certificate) {
      throw {
        status: 409,
        message: 'La compañía no tiene un certificado electrónico activo',
        errorCode: 'CERTIFICATE_NOT_FOUND',
      };
    }
    return certificate;
  }

  async signOutbound(companyId: number, dto: SendEcfDto, username: string, requestId?: string) {
    const invoice = await this.prisma.electronicInvoice.findFirst({
      where: { id: dto.invoiceId, companyId, direction: 'outbound' },
    });
    if (!invoice) {
      throw { status: 404, message: 'Documento electrónico no encontrado', errorCode: 'OUTBOUND_NOT_FOUND' };
    }
    if (!invoice.xmlUnsigned) {
      throw { status: 409, message: 'El documento no tiene XML sin firmar', errorCode: 'XML_UNSIGNED_MISSING' };
    }

    const certificate = await this.getActiveCertificate(companyId);
    const password = decryptSecret(certificate.passwordEncrypted);
    const loaded = isInlineCertificateReference(certificate.secretReference)
      ? loadPkcs12CertificateFromBuffer(
          decryptBinarySecret(certificate.secretReference!.slice(INLINE_CERTIFICATE_PREFIX.length)),
          password,
        )
      : loadPkcs12Certificate(resolveCertificateFilePath(certificate.filePath, certificate.secretReference), password);
    assertCertificateIsCurrentlyValid(loaded.validFrom, loaded.validTo);

    const xmlSigned = this.signatureService.signXml(invoice.xmlUnsigned, loaded.privateKeyPem, loaded.certPem);
    const xmlHash = sha256Hex(xmlSigned);

    const updated = await this.transitionInternalStatus(
      invoice.id,
      'SIGNED',
      'XML firmado digitalmente',
      username,
      {
        xmlSigned,
        xmlHash,
        certificateId: certificate.id,
        signedAt: new Date(),
      },
      { certificateId: certificate.id },
    );

    await this.audit.log({
      companyId,
      invoiceId: invoice.id,
      eventType: 'outbound.signed',
      eventSource: 'ADMIN',
      message: `Documento ${updated.ecf} firmado`,
      payload: { certificateId: certificate.id },
      requestId,
    });

    return updated;
  }

  private async applyDgiiOutcome(invoiceId: number, username: string, outcome: {
    normalizedStatus: 'accepted' | 'accepted_conditional' | 'rejected' | 'pending' | 'error';
    trackId?: string;
    code?: string;
    message?: string;
    raw: unknown;
  }) {
    const invoice = await this.prisma.electronicInvoice.findUnique({ where: { id: invoiceId } });
    if (!invoice) throw { status: 404, message: 'Documento electrónico no encontrado', errorCode: 'OUTBOUND_NOT_FOUND' };

    const now = new Date();
    switch (outcome.normalizedStatus) {
      case 'accepted':
        return this.transitionInternalStatus(
          invoiceId,
          'ACCEPTED',
          'DGII aceptó el documento',
          username,
          {
            dgiiStatus: 'ACCEPTED',
            dgiiTrackId: outcome.trackId ?? invoice.dgiiTrackId,
            rejectionCode: null,
            rejectionMessage: outcome.message ?? null,
            dgiiRawResponseJson: outcome.raw,
            submittedAt: invoice.submittedAt ?? now,
            acceptedAt: now,
          } as Record<string, unknown>,
          outcome.raw,
        );
      case 'accepted_conditional':
        return this.transitionInternalStatus(
          invoiceId,
          'ACCEPTED_CONDITIONAL',
          'DGII aceptó condicionalmente el documento',
          username,
          {
            dgiiStatus: 'ACCEPTED_CONDITIONAL',
            dgiiTrackId: outcome.trackId ?? invoice.dgiiTrackId,
            rejectionMessage: outcome.message ?? null,
            dgiiRawResponseJson: outcome.raw,
            submittedAt: invoice.submittedAt ?? now,
            acceptedAt: now,
          },
          outcome.raw,
        );
      case 'rejected':
        return this.transitionInternalStatus(
          invoiceId,
          'REJECTED',
          'DGII rechazó el documento',
          username,
          {
            dgiiStatus: 'REJECTED',
            dgiiTrackId: outcome.trackId ?? invoice.dgiiTrackId,
            rejectionCode: outcome.code ?? null,
            rejectionMessage: outcome.message ?? null,
            dgiiRawResponseJson: outcome.raw,
            submittedAt: invoice.submittedAt ?? now,
            rejectedAt: now,
          },
          outcome.raw,
        );
      case 'pending':
        return this.transitionInternalStatus(
          invoiceId,
          'SUBMITTED',
          'Documento enviado a DGII y pendiente de resultado final',
          username,
          {
            dgiiStatus: 'IN_PROCESS',
            dgiiTrackId: outcome.trackId ?? invoice.dgiiTrackId,
            rejectionMessage: outcome.message ?? null,
            dgiiRawResponseJson: outcome.raw,
            submittedAt: invoice.submittedAt ?? now,
          },
          outcome.raw,
        );
      default:
        return this.transitionInternalStatus(
          invoiceId,
          'ERROR',
          'Error en la comunicación con DGII',
          username,
          {
            dgiiStatus: 'ERROR',
            dgiiTrackId: outcome.trackId ?? invoice.dgiiTrackId,
            rejectionCode: outcome.code ?? null,
            rejectionMessage: outcome.message ?? null,
            dgiiRawResponseJson: outcome.raw,
          },
          outcome.raw,
        );
    }
  }

  async submitOutbound(companyId: number, dto: SendEcfDto, username: string, requestId?: string) {
    const invoice = await this.prisma.electronicInvoice.findFirst({
      where: { id: dto.invoiceId, companyId, direction: 'outbound' },
    });
    if (!invoice) {
      throw { status: 404, message: 'Documento electrónico no encontrado', errorCode: 'OUTBOUND_NOT_FOUND' };
    }
    if (!invoice.xmlSigned) {
      throw { status: 409, message: 'El documento aún no está firmado', errorCode: 'XML_SIGNED_MISSING' };
    }
    if (!dto.force && !['SIGNED', 'ERROR'].includes(invoice.internalStatus)) {
      throw {
        status: 409,
        message: `No se puede enviar un documento en estado ${invoice.internalStatus}`,
        errorCode: 'OUTBOUND_STATUS_NOT_SUBMITTABLE',
      };
    }

    const config = await this.getEndpointConfig(companyId, invoice.branchId);
    if (!config.outboundEnabled || !config.active) {
      throw { status: 409, message: 'La salida real a DGII está deshabilitada', errorCode: 'REAL_EI_DISABLED' };
    }

    await this.transitionInternalStatus(
      invoice.id,
      'SUBMISSION_PENDING',
      'Preparando envío a DGII',
      username,
      {
        dgiiStatus: 'RECEIVED',
      },
    );

    const result = await this.submissionService.submit(config.environment as any, invoice.xmlSigned);
    const updated = await this.applyDgiiOutcome(invoice.id, username, result);

    await this.audit.log({
      companyId,
      invoiceId: invoice.id,
      eventType: 'outbound.submitted',
      eventSource: 'DGII',
      message: `Documento ${updated.ecf} enviado a DGII`,
      payload: result,
      requestId,
    });

    return updated;
  }

  async queryOutboundResult(companyId: number, trackId: string, username: string, requestId?: string) {
    const invoice = await this.prisma.electronicInvoice.findFirst({
      where: { companyId, dgiiTrackId: trackId, direction: 'outbound' },
    });
    if (!invoice) {
      throw { status: 404, message: 'TrackId no asociado a un documento', errorCode: 'TRACK_NOT_FOUND' };
    }

    const config = await this.getEndpointConfig(companyId, invoice.branchId);
    const result = await this.resultService.query(config.environment as any, trackId);
    const updated = await this.applyDgiiOutcome(invoice.id, username, result);

    await this.audit.log({
      companyId,
      invoiceId: invoice.id,
      eventType: 'outbound.result.queried',
      eventSource: 'DGII',
      message: `TrackId ${trackId} consultado`,
      payload: result,
      requestId,
    });

    return { invoice: updated, result };
  }

  async getOutboundInvoice(companyId: number, invoiceId: number) {
    const invoice = await this.prisma.electronicInvoice.findFirst({
      where: { id: invoiceId, companyId, direction: 'outbound' },
      include: {
        statusHistory: { orderBy: { createdAt: 'asc' } },
      },
    });
    if (!invoice) {
      throw { status: 404, message: 'Documento electrónico no encontrado', errorCode: 'OUTBOUND_NOT_FOUND' };
    }
    return invoice;
  }

  async listOutboundInvoices(companyId: number, filters: OutboundInvoiceListFilters) {
    return this.prisma.electronicInvoice.findMany({
      where: {
        companyId,
        direction: 'outbound',
        ...(filters.documentTypeCode ? { documentTypeCode: filters.documentTypeCode } : {}),
        ...(filters.internalStatus ? { internalStatus: filters.internalStatus as any } : {}),
        ...(filters.dgiiStatus ? { dgiiStatus: filters.dgiiStatus as any } : {}),
        ...(filters.search
          ? {
              OR: [
                { ecf: { contains: filters.search, mode: 'insensitive' } },
                { buyerName: { contains: filters.search, mode: 'insensitive' } },
                { issuerName: { contains: filters.search, mode: 'insensitive' } },
                { dgiiTrackId: { contains: filters.search, mode: 'insensitive' } },
              ],
            }
          : {}),
        ...(filters.fromDate || filters.toDate
          ? {
              createdAt: {
                ...(filters.fromDate ? { gte: filters.fromDate } : {}),
                ...(filters.toDate ? { lte: filters.toDate } : {}),
              },
            }
          : {}),
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  getAuditTimeline(companyId: number, invoiceId: number) {
    return Promise.all([
      this.prisma.electronicInvoiceStatusHistory.findMany({
        where: { electronicInvoiceId: invoiceId },
        orderBy: { createdAt: 'asc' },
      }),
      this.audit.listInvoiceAudit(companyId, invoiceId),
    ]).then(([statusHistory, auditLogs]) => ({ statusHistory, auditLogs }));
  }

  async createCreditNote(companyId: number, dto: CreateCreditNoteDto, username: string, requestId?: string) {
    const config = await this.getEndpointConfig(companyId, dto.branchId);
    if (!config.outboundEnabled || !config.active) {
      throw { status: 409, message: 'La salida real a DGII está deshabilitada', errorCode: 'REAL_EI_DISABLED' };
    }

    const mapped = await this.mapper.mapCreditNoteToOutbound(companyId, dto.originalInvoiceId, dto.saleId, dto.reason);
    const draft = await this.createDraftInvoice(
      companyId,
      dto.branchId,
      dto.saleId,
      '34',
      mapped.issuer.rnc ?? '',
      mapped.issuer.name,
      mapped.buyer.rnc,
      mapped.buyer.name,
      mapped.issueDate,
      mapped.totalAmount,
      mapped.taxAmount,
      mapped.currencyCode,
      dto.originalInvoiceId,
    );
    const allocation = await this.sequenceService.allocate(companyId, dto.branchId, '34', requestId);
    const xmlUnsigned = this.xmlBuilder.build({ ...mapped, ecf: allocation.ecf });

    const updated = await this.transitionInternalStatus(
      draft.id,
      'GENERATED',
      `Nota de crédito ${allocation.ecf} generada`,
      username,
      {
        ecf: allocation.ecf,
        sequenceNumber: allocation.sequenceNumber,
        xmlUnsigned,
      },
      { originalInvoiceId: dto.originalInvoiceId, saleId: dto.saleId, reason: dto.reason },
    );

    await this.audit.log({
      companyId,
      invoiceId: updated.id,
      eventType: 'credit-note.generated',
      eventSource: 'ADMIN',
      message: `Nota de crédito ${updated.ecf} generada`,
      payload: dto,
      requestId,
    });

    return updated;
  }

  async getXmlVariant(companyId: number, invoiceId: number, variant: 'unsigned' | 'signed') {
    const invoice = await this.getOutboundInvoice(companyId, invoiceId);
    const xml = variant === 'unsigned' ? invoice.xmlUnsigned : invoice.xmlSigned;
    if (!xml) {
      throw {
        status: 404,
        message: `XML ${variant === 'unsigned' ? 'sin firmar' : 'firmado'} no disponible`,
        errorCode: 'XML_VARIANT_NOT_FOUND',
      };
    }

    return { filename: `${invoice.ecf}-${variant}.xml`, xml };
  }
}
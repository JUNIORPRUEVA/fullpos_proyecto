import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import env from '../../../config/env';
import { DgiiSignatureService } from './dgii-signature.service';
import { ElectronicInvoicingAuditService } from './electronic-invoicing-audit.service';
import { ElectronicInvoicingMapperService } from './electronic-invoicing-mapper.service';
import { buildXmlDocument, deepFindFirstString, parseXml } from '../utils/xml.utils';
import { hashForStorage, sha256Hex } from '../utils/hash.utils';

function getRequiredFeMasterKey() {
  const key = env.FE_MASTER_ENCRYPTION_KEY?.trim();
  if (!key) {
    throw {
      status: 503,
      message: 'La facturación electrónica requiere FE_MASTER_ENCRYPTION_KEY configurada',
      errorCode: 'FE_MASTER_ENCRYPTION_KEY_MISSING',
    };
  }

  return key;
}

function tokenSecret() {
  return sha256Hex(getRequiredFeMasterKey());
}

export class DgiiAuthService {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly mapper: ElectronicInvoicingMapperService,
    private readonly signatureService: DgiiSignatureService,
    private readonly audit: ElectronicInvoicingAuditService,
  ) {}

  async createSeed(companyRnc: string | undefined, companyCloudId: string | undefined, branchId: number, requestId?: string) {
    const company = await this.mapper.resolveCompanyOrThrow(companyRnc, companyCloudId);
    const nonce = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + env.FE_SEED_TTL_SECONDS * 1000);

    const seed = await this.prisma.electronicAuthSeed.create({
      data: {
        companyId: company.id,
        nonce,
        challengeHash: hashForStorage(`${company.id}:${branchId}:${nonce}`),
        expiresAt,
      },
    });

    const xml = buildXmlDocument('Semilla', {
      Id: seed.id,
      Empresa: {
        RNC: company.rnc ?? '',
        Nombre: company.name,
      },
      BranchId: String(branchId),
      Nonce: nonce,
      EmitidaEn: new Date().toISOString(),
      ExpiraEn: expiresAt.toISOString(),
    });

    await this.audit.log({
      companyId: company.id,
      eventType: 'auth.seed.created',
      eventSource: 'PUBLIC_API',
      message: `Semilla emitida para ${company.name}`,
      payload: { seedId: seed.id, branchId, expiresAt },
      requestId,
    });

    return { seedId: seed.id, xml, expiresAt };
  }

  async validateSignedSeed(
    companyRnc: string | undefined,
    companyCloudId: string | undefined,
    branchId: number,
    signedSeedXml: string,
    requestId?: string,
  ) {
    const company = await this.mapper.resolveCompanyOrThrow(companyRnc, companyCloudId);
    const verification = this.signatureService.verifySignedXml(signedSeedXml);
    if (!verification.valid || !verification.certificatePem) {
      throw {
        status: 401,
        message: 'La firma de la semilla no es válida',
        errorCode: 'INVALID_SEED_SIGNATURE',
        details: { errors: verification.errors },
      };
    }

    const parsedSeed = parseXml(signedSeedXml);
    const seedId = deepFindFirstString(parsedSeed, ['Id']);
    const nonce = deepFindFirstString(parsedSeed, ['Nonce']);
    if (!seedId || !nonce) {
      throw { status: 400, message: 'Semilla firmada inválida', errorCode: 'INVALID_SIGNED_SEED_XML' };
    }

    const seed = await this.prisma.electronicAuthSeed.findFirst({
      where: { id: seedId, companyId: company.id },
    });

    if (!seed) {
      throw { status: 404, message: 'Semilla no encontrada', errorCode: 'SEED_NOT_FOUND' };
    }
    if (seed.expiresAt.getTime() < Date.now()) {
      throw { status: 401, message: 'La semilla expiró', errorCode: 'SEED_EXPIRED' };
    }

    const expectedHash = hashForStorage(`${company.id}:${branchId}:${nonce}`);
    if (seed.challengeHash !== expectedHash) {
      throw { status: 401, message: 'La semilla no coincide con el desafío emitido', errorCode: 'SEED_CHALLENGE_MISMATCH' };
    }

    const certificateSerialNumber = verification.certificatePem
      .replace(/\s+/g, '')
      .slice(-32);
    const subject = 'signed-seed';

    const token = jwt.sign(
      {
        companyId: company.id,
        branchId,
        seedId: seed.id,
        certificateSerialNumber,
        subject,
      },
      tokenSecret(),
      { expiresIn: env.FE_PUBLIC_TOKEN_TTL_SECONDS },
    );

    await this.prisma.electronicAuthSeed.update({
      where: { id: seed.id },
      data: {
        validatedAt: new Date(),
        tokenHash: hashForStorage(token),
      },
    });

    await this.audit.log({
      companyId: company.id,
      eventType: 'auth.seed.validated',
      eventSource: 'PUBLIC_API',
      message: `Semilla validada para ${company.name}`,
      payload: { seedId: seed.id, branchId },
      requestId,
    });

    return {
      accessToken: token,
      expiresIn: env.FE_PUBLIC_TOKEN_TTL_SECONDS,
      tokenType: 'Bearer',
    };
  }

  async assertInboundToken(companyId: number, branchId: number, authHeader: string | undefined) {
    const config = await this.prisma.electronicInboundEndpointConfig.findUnique({
      where: { companyId_branchId: { companyId, branchId } },
    });

    if (!config?.authEnabled) {
      return;
    }

    if (!authHeader?.startsWith('Bearer ')) {
      throw { status: 401, message: 'Token FE requerido', errorCode: 'FE_TOKEN_REQUIRED' };
    }

    const token = authHeader.slice(7).trim();
    try {
      const payload = jwt.verify(token, tokenSecret()) as {
        companyId: number;
        branchId: number;
      };

      if (payload.companyId !== companyId || payload.branchId !== branchId) {
        throw new Error('Token FE emitido para otra compañía o sucursal');
      }
    } catch (error) {
      throw {
        status: 401,
        message: error instanceof Error ? error.message : 'Token FE inválido',
        errorCode: 'FE_TOKEN_INVALID',
      };
    }
  }
}
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import env from '../../../config/env';
import { DgiiSignatureService } from './dgii-signature.service';
import { ElectronicInvoicingAuditService } from './electronic-invoicing-audit.service';
import { ElectronicInvoicingMapperService } from './electronic-invoicing-mapper.service';
import { DgiiDirectoryService } from './dgii-directory.service';
import { buildXmlDocument, deepFindFirstString, parseXml } from '../utils/xml.utils';
import { hashForStorage, sha256Hex } from '../utils/hash.utils';
import {
  assertCertificateIsCurrentlyValid,
  loadPkcs12Certificate,
  loadPkcs12CertificateFromBuffer,
  resolveCertificateFilePath,
} from '../utils/certificate.utils';
import {
  decryptBinarySecret,
  decryptSecret,
  encryptSecret,
  INLINE_CERTIFICATE_PREFIX,
  isInlineCertificateReference,
} from '../utils/credential-crypto.utils';
import { DgiiEnvironment } from '../types/dgii.types';

export type DgiiTokenSource = 'manual' | 'cache' | 'env' | 'auto';

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

function parseSeconds(value: string | undefined) {
  if (!value) return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

function extractAuthorizationToken(response: Response) {
  const authHeader = response.headers.get('authorization') ?? response.headers.get('x-access-token') ?? undefined;
  if (!authHeader) return undefined;
  return authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : authHeader.trim();
}

async function parseDgiiResponse(response: Response) {
  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('application/json')) {
    return { raw: await response.json(), rawText: null as string | null };
  }

  const text = await response.text();
  if (!text.trim()) return { raw: {}, rawText: '' };

  try {
    return { raw: parseXml(text), rawText: text };
  } catch {
    return { raw: { rawText: text }, rawText: text };
  }
}

function summarizeRawText(rawText: string | null, maxLength = 400) {
  const text = (rawText ?? '').trim();
  if (!text) return null;
  return text.length > maxLength ? `${text.slice(0, maxLength)}...` : text;
}

function extractDgiiSeedXml(raw: unknown, rawText: string | null) {
  if (rawText?.trim().startsWith('<')) {
    return rawText.trim();
  }

  if (typeof raw === 'object' && raw) {
    const record = raw as Record<string, unknown>;
    for (const key of ['xml', 'XML', 'semillaXml', 'SemillaXml', 'seedXml', 'SeedXml', 'semilla', 'Semilla']) {
      const value = record[key];
      if (typeof value === 'string' && value.trim().startsWith('<')) {
        return value.trim();
      }
    }
  }

  throw {
    status: 502,
    message: 'DGII no devolvió una semilla utilizable',
    errorCode: 'DGII_AUTH_SEED_INVALID',
  };
}

function extractDgiiToken(raw: unknown, response: Response) {
  const headerToken = extractAuthorizationToken(response);
  if (headerToken) return headerToken;

  return deepFindFirstString(raw, [
    'token',
    'Token',
    'accessToken',
    'AccessToken',
    'bearerToken',
    'BearerToken',
    'jwt',
    'JWT',
  ]);
}

function extractDgiiExpiry(raw: unknown, token: string) {
  const now = Date.now();
  const expiresIn = parseSeconds(
    deepFindFirstString(raw, ['expiresIn', 'ExpiresIn', 'expires_in', 'expiraEnSegundos', 'ExpiraEnSegundos']),
  );
  if (expiresIn) {
    return new Date(now + expiresIn * 1000);
  }

  const explicitDate = deepFindFirstString(raw, ['expiresAt', 'ExpiresAt', 'expiraEn', 'ExpiraEn']);
  if (explicitDate) {
    const parsed = new Date(explicitDate);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed;
    }
  }

  const jwtParts = token.split('.');
  if (jwtParts.length === 3) {
    try {
      const payload = JSON.parse(Buffer.from(jwtParts[1], 'base64url').toString('utf8')) as { exp?: number };
      if (payload.exp) {
        return new Date(payload.exp * 1000);
      }
    } catch {
      // ignore non-JWT tokens
    }
  }

  return new Date(now + 5 * 60 * 1000);
}

export class DgiiAuthService {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly mapper: ElectronicInvoicingMapperService,
    private readonly signatureService: DgiiSignatureService,
    private readonly audit: ElectronicInvoicingAuditService,
    private readonly directory: DgiiDirectoryService,
  ) {}

  private getLegacyEnvironmentToken(environment: DgiiEnvironment) {
    const token = (
      environment === 'production'
        ? process.env.DGII_PRODUCTION_BEARER_TOKEN?.trim() || env.DGII_PRODUCTION_BEARER_TOKEN?.trim()
        : process.env.DGII_PRECERT_BEARER_TOKEN?.trim() || env.DGII_PRECERT_BEARER_TOKEN?.trim()
    )?.trim();
    return token || undefined;
  }

  private async getActiveCertificate(companyId: number) {
    const certificate = await this.prisma.electronicCertificate.findFirst({
      where: { companyId, status: 'ACTIVE' },
      orderBy: { updatedAt: 'desc' },
    });

    if (!certificate) {
      throw {
        status: 409,
        message: 'La compañía no tiene un certificado electrónico activo para autenticarse con DGII',
        errorCode: 'CERTIFICATE_NOT_FOUND',
      };
    }

    return certificate;
  }

  private async loadCompanyCertificate(companyId: number) {
    const certificate = await this.getActiveCertificate(companyId);
    const password = decryptSecret(certificate.passwordEncrypted);
    const loaded = isInlineCertificateReference(certificate.secretReference)
      ? loadPkcs12CertificateFromBuffer(
          decryptBinarySecret(certificate.secretReference!.slice(INLINE_CERTIFICATE_PREFIX.length)),
          password,
        )
      : loadPkcs12Certificate(resolveCertificateFilePath(certificate.filePath, certificate.secretReference), password);

    assertCertificateIsCurrentlyValid(loaded.validFrom, loaded.validTo);
    return { certificate, loaded };
  }

  private async readCachedToken(companyId: number, environment: DgiiEnvironment) {
    const cached = await this.prisma.electronicDgiiTokenCache.findUnique({
      where: { companyId_environment: { companyId, environment } },
    });

    if (!cached) return null;
    if (cached.expiresAt.getTime() <= Date.now() + env.DGII_TOKEN_CACHE_SKEW_SECONDS * 1000) {
      return null;
    }

    return { ...cached, token: decryptSecret(cached.tokenEncrypted) };
  }

  async invalidateCompanyBearerToken(companyId: number, environment: DgiiEnvironment, reason?: string) {
    await this.prisma.electronicDgiiTokenCache.deleteMany({
      where: { companyId, environment },
    });

    await this.audit.log({
      companyId,
      eventType: 'auth.dgii.token.invalidated',
      eventSource: 'DGII',
      message: 'Token DGII invalidado para forzar renovación',
      payload: { environment, reason: reason ?? null },
    });
  }

  async getCompanyBearerToken(
    companyId: number,
    environment: DgiiEnvironment,
    requestId?: string,
    options?: { forceRefresh?: boolean; manualToken?: string },
  ) {
    const tokenMeta = await this.getCompanyBearerTokenWithMeta(companyId, environment, requestId, options);
    return tokenMeta.token;
  }

  async getCompanyBearerTokenWithMeta(
    companyId: number,
    environment: DgiiEnvironment,
    requestId?: string,
    options?: { forceRefresh?: boolean; manualToken?: string },
  ): Promise<{ token: string; source: DgiiTokenSource }> {
    const manualToken = options?.manualToken?.trim();
    if (manualToken) {
      return { token: manualToken, source: 'manual' };
    }

    if (!options?.forceRefresh) {
      const cached = await this.readCachedToken(companyId, environment);
      if (cached?.token) {
        return { token: cached.token, source: 'cache' };
      }
    }

    const config = this.directory.getEnvironmentConfig(environment);
    if (!config.authSeedUrl || !config.authValidateUrl) {
      const legacyToken = this.getLegacyEnvironmentToken(environment);
      if (legacyToken) {
        return { token: legacyToken, source: 'env' };
      }

      throw {
        status: 503,
        message: `Configuración de autenticación DGII incompleta para ambiente ${environment}`,
        errorCode: 'DGII_AUTH_CONFIG_MISSING',
      };
    }

    const { loaded } = await this.loadCompanyCertificate(companyId);
    const seedResponse = await this.requestDgiiSeed(companyId, environment, config.authSeedUrl, config.userAgent, config.timeoutMs);
    const signedSeedXml = this.signatureService.signXml(seedResponse.seedXml, loaded.privateKeyPem, loaded.certPem);
    const validated = await this.validateDgiiSeed(
      companyId,
      environment,
      config.authValidateUrl,
      config.userAgent,
      config.timeoutMs,
      signedSeedXml,
    );

    await this.prisma.electronicDgiiTokenCache.upsert({
      where: { companyId_environment: { companyId, environment } },
      update: {
        tokenEncrypted: encryptSecret(validated.token),
        issuedAt: validated.issuedAt,
        expiresAt: validated.expiresAt,
        lastValidatedAt: validated.validatedAt,
        lastErrorCode: null,
        lastErrorMessage: null,
      },
      create: {
        companyId,
        environment,
        tokenEncrypted: encryptSecret(validated.token),
        issuedAt: validated.issuedAt,
        expiresAt: validated.expiresAt,
        lastValidatedAt: validated.validatedAt,
      },
    });

    await this.audit.log({
      companyId,
      eventType: 'auth.dgii.token.refreshed',
      eventSource: 'DGII',
      message: `Token DGII renovado automáticamente para ${environment}`,
      payload: {
        environment,
        expiresAt: validated.expiresAt,
      },
      requestId,
    });

    return { token: validated.token, source: 'auto' };
  }

  private async requestDgiiSeed(
    companyId: number,
    environment: DgiiEnvironment,
    url: string,
    userAgent: string,
    timeoutMs: number,
  ) {
    const callSeed = async (method: 'POST' | 'GET') => {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);

      try {
        const response = await fetch(url, {
          method,
          headers: {
            accept: 'application/json, application/xml, text/xml;q=0.9, */*;q=0.8',
            'user-agent': userAgent,
          },
          signal: controller.signal,
        });
        clearTimeout(timeout);

        const { raw, rawText } = await parseDgiiResponse(response);
        return { response, raw, rawText, method };
      } catch (error) {
        clearTimeout(timeout);
        throw error;
      }
    };

    try {
      const primary = await callSeed('POST');

      if (!primary.response.ok && (primary.response.status === 405 || primary.response.status === 404)) {
        const fallback = await callSeed('GET');
        if (!fallback.response.ok) {
          throw {
            status: 502,
            message:
              deepFindFirstString(fallback.raw, ['Mensaje', 'mensaje', 'Message', 'message']) ||
              deepFindFirstString(primary.raw, ['Mensaje', 'mensaje', 'Message', 'message']) ||
              `DGII rechazó la solicitud de semilla (POST=${primary.response.status}, GET=${fallback.response.status})`,
            errorCode: 'DGII_AUTH_SEED_FAILED',
            details: {
              environment,
              methodTried: ['POST', 'GET'],
              httpStatus: fallback.response.status,
              fallbackHttpStatus: primary.response.status,
              raw: fallback.raw,
              rawTextSummary: summarizeRawText(fallback.rawText),
              primaryRawTextSummary: summarizeRawText(primary.rawText),
            },
          };
        }

        return { seedXml: extractDgiiSeedXml(fallback.raw, fallback.rawText), raw: fallback.raw };
      }

      if (!primary.response.ok) {
        throw {
          status: 502,
          message:
            deepFindFirstString(primary.raw, ['Mensaje', 'mensaje', 'Message', 'message']) ||
            `DGII rechazó la solicitud de semilla (HTTP ${primary.response.status})`,
          errorCode: 'DGII_AUTH_SEED_FAILED',
          details: {
            environment,
            methodTried: ['POST'],
            httpStatus: primary.response.status,
            raw: primary.raw,
            rawTextSummary: summarizeRawText(primary.rawText),
          },
        };
      }

      return { seedXml: extractDgiiSeedXml(primary.raw, primary.rawText), raw: primary.raw };
    } catch (error) {
      await this.prisma.electronicDgiiTokenCache.upsert({
        where: { companyId_environment: { companyId, environment } },
        update: {
          lastErrorCode: (error as any)?.errorCode ?? 'DGII_AUTH_SEED_FAILED',
          lastErrorMessage: error instanceof Error ? error.message : String((error as any)?.message ?? error),
        },
        create: {
          companyId,
          environment,
          tokenEncrypted: encryptSecret('seed-error-placeholder'),
          issuedAt: new Date(),
          expiresAt: new Date(Date.now() - 1000),
          lastErrorCode: (error as any)?.errorCode ?? 'DGII_AUTH_SEED_FAILED',
          lastErrorMessage: error instanceof Error ? error.message : String((error as any)?.message ?? error),
        },
      });
      throw error;
    }
  }

  private async validateDgiiSeed(
    companyId: number,
    environment: DgiiEnvironment,
    url: string,
    userAgent: string,
    timeoutMs: number,
    signedSeedXml: string,
  ) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          accept: 'application/json, application/xml, text/xml;q=0.9, */*;q=0.8',
          'content-type': 'application/xml; charset=utf-8',
          'user-agent': userAgent,
        },
        body: signedSeedXml,
        signal: controller.signal,
      });
      clearTimeout(timeout);

      const { raw } = await parseDgiiResponse(response);
      const token = extractDgiiToken(raw, response);
      if (!response.ok || !token) {
        throw {
          status: 502,
          message: deepFindFirstString(raw, ['Mensaje', 'mensaje', 'Message', 'message']) || 'DGII no devolvió token válido',
          errorCode: token ? 'DGII_AUTH_VALIDATE_FAILED' : 'DGII_TOKEN_MISSING',
          details: { environment, httpStatus: response.status, raw },
        };
      }

      return {
        token,
        issuedAt: new Date(),
        expiresAt: extractDgiiExpiry(raw, token),
        validatedAt: new Date(),
      };
    } catch (error) {
      clearTimeout(timeout);
      await this.prisma.electronicDgiiTokenCache.upsert({
        where: { companyId_environment: { companyId, environment } },
        update: {
          lastErrorCode: (error as any)?.errorCode ?? 'DGII_AUTH_VALIDATE_FAILED',
          lastErrorMessage: error instanceof Error ? error.message : String((error as any)?.message ?? error),
        },
        create: {
          companyId,
          environment,
          tokenEncrypted: encryptSecret('validation-error-placeholder'),
          issuedAt: new Date(),
          expiresAt: new Date(Date.now() - 1000),
          lastErrorCode: (error as any)?.errorCode ?? 'DGII_AUTH_VALIDATE_FAILED',
          lastErrorMessage: error instanceof Error ? error.message : String((error as any)?.message ?? error),
        },
      });
      throw error;
    }
  }

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
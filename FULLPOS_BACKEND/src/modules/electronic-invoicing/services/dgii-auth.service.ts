import crypto from 'crypto';
import fs from 'fs';
import jwt from 'jsonwebtoken';
import path from 'path';
import { PrismaClient } from '@prisma/client';
import { DOMParser } from '@xmldom/xmldom';
import env from '../../../config/env';
import { DgiiSignatureService, SEED_SIGNATURE_MODES, SeedSignatureMode, SignedXmlDiagnostics } from './dgii-signature.service';
import { ElectronicInvoicingAuditService } from './electronic-invoicing-audit.service';
import { ElectronicInvoicingMapperService } from './electronic-invoicing-mapper.service';
import { DgiiDirectoryService } from './dgii-directory.service';
import { buildXmlDocument, deepFindFirstString, parseXml } from '../utils/xml.utils';
import { hashForStorage, sha256Hex } from '../utils/hash.utils';
import {
  analyzeCertificateForDgii,
  assertCertificateIsCurrentlyValid,
  CertificateSubjectAnalysis,
  extractCertificateIdentity,
  loadPkcs12Certificate,
  loadPkcs12CertificateFromBuffer,
  normalizeSignerDocumentNumber,
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

export type DgiiTokenSource = 'manual' | 'manual-cache' | 'cache' | 'env' | 'auto';

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

function classifyDgiiSeedValidationFailure(
  message: string,
  diagnostics: Partial<ValidateSeedMeta>,
) {
  const normalized = message.toLowerCase();
  if (diagnostics.signedXmlHasIdAttributeOnRoot || (diagnostics.signatureReferenceUri ?? '') !== '') {
    return 'SEED_XML_SIGNATURE_STRUCTURE_MISMATCH';
  }
  if (
    normalized.includes('firma del certificado inválida') ||
    normalized.includes('firma del certificado invalida')
  ) {
    return 'DGII_CERTIFICATE_SIGNATURE_REJECTED';
  }
  if (normalized.includes('certificado') || normalized.includes('certificate')) {
    return 'DGII_CERTIFICATE_VALIDATION_REJECTED';
  }
  return null;
}

function buildCertificateCompatibilityWarning(analysis: CertificateSubjectAnalysis) {
  if (analysis.isNaturalPerson && !analysis.rncMatchesCompany) {
    return 'CERTIFICATE_RNC_AUTHORIZATION_MISMATCH';
  }
  if (analysis.isNaturalPerson) {
    return 'CERTIFICATE_IS_NATURAL_PERSON';
  }
  if (!analysis.rncMatchesCompany && analysis.rncInCertificate) {
    return 'CERTIFICATE_SUBJECT_DOES_NOT_MATCH_COMPANY_RNC';
  }
  if (!analysis.rncInCertificate) {
    return 'CERTIFICATE_NOT_ACCEPTED_BY_DGII';
  }
  return null;
}

function buildUserFacingSeedValidationMessage(rawMessage: string) {
  return `DGII rechazó la firma del certificado al validar la semilla. Esto normalmente significa que el certificado no está autorizado para este RNC en DGII, no corresponde a la empresa, o la firma XML no está en el formato que DGII espera. DGII: ${rawMessage}`;
}

function normalizeComparableName(value: string | null | undefined) {
  if (!value) return '';
  return value
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

function namesAreCompatible(a: string | null | undefined, b: string | null | undefined) {
  const left = normalizeComparableName(a);
  const right = normalizeComparableName(b);
  if (!left || !right) return false;
  return left === right || left.includes(right) || right.includes(left);
}

function maskDocumentNumber(value: string | null | undefined) {
  const normalized = normalizeSignerDocumentNumber(value ?? null);
  if (!normalized) return null;
  if (normalized.length <= 4) return `***${normalized}`;
  return `${'*'.repeat(Math.max(0, normalized.length - 4))}${normalized.slice(-4)}`;
}

type SeedRequestMeta = {
  authSeedUrl: string;
  methodUsed: 'POST' | 'GET';
  httpStatus: number;
  contentType: string;
  xmlSize: number;
  rootElement: string | null;
  containsSemillaModel: boolean;
  containsValor: boolean;
  containsFecha: boolean;
  rawTextSummary: string | null;
  seedHead: string;
  seedTail: string;
};

type ValidateSeedMeta = {
  originalSeedRoot: string | null;
  validateUrl: string;
  requestContentType: string;
  payloadMode: 'multipart' | 'form-urlencoded' | 'raw-xml';
  fieldName: 'raw-xml' | 'xml' | 'archivo' | 'file' | 'x-www-form-urlencoded';
  httpStatus: number;
  responseContentType: string;
  rawTextSummary: string | null;
  dgiiSafeResponse: string | null;
  signedXmlRoot: string | null;
  signedXmlHasSignature: boolean;
  signedXmlHasBom: boolean;
  signedXmlHasDeclaration: boolean;
  signedXmlHasIdAttributeOnRoot: boolean;
  signedXmlHasRootIdAttribute: boolean;
  signatureReferenceUri: string | null;
  signatureReferenceUriBeforeSanitize: string | null;
  signatureReferenceUriAfterSanitize: string | null;
  canonicalizationAlgorithm: string | null;
  signatureAlgorithm: string | null;
  digestAlgorithm: string | null;
  signedXmlRootId: string | null;
  rootIdBeforeSanitize: string | null;
  rootIdAfterSanitize: string | null;
  signedXmlSize: number;
  signedXmlSizeBeforeSanitize: number;
  finalXmlSize: number;
  finalXmlStartsWith: string;
  finalXmlRootAfterSanitize: string | null;
  xmlDeclarationBeforeSanitize: boolean;
  xmlDeclarationAfterSanitize: boolean;
};

type SignedSeedSanitizerDiagnostics = {
  originalSeedRoot: string | null;
  signedXmlHasBomBeforeSanitize: boolean;
  signedXmlHasBomAfterSanitize: boolean;
  signedXmlHasDeclarationBeforeSanitize: boolean;
  signedXmlHasDeclarationAfterSanitize: boolean;
  signedXmlRootBeforeSanitize: string | null;
  signedXmlRootAfterSanitize: string | null;
  signedXmlHasRootIdAttributeBeforeSanitize: boolean;
  signedXmlHasRootIdAttributeAfterSanitize: boolean;
  rootIdBeforeSanitize: string | null;
  rootIdAfterSanitize: string | null;
  signatureReferenceUriBeforeSanitize: string | null;
  signatureReferenceUriAfterSanitize: string | null;
  signedXmlSizeBeforeSanitize: number;
  finalXmlSize: number;
  finalXmlStartsWith: string;
};

type ValidateSeedAttempt = {
  requestContentType: string;
  payloadMode: ValidateSeedMeta['payloadMode'];
  fieldName: ValidateSeedMeta['fieldName'];
  body: BodyInit;
  headers: Record<string, string>;
};

type DiagnosticMatrixEntry = {
  signatureMode: string;
  canonicalization: string;
  signatureAlgorithm: string;
  digestAlgorithm: string;
  referenceUri: string;
  keyInfoMode: 'leaf-only' | 'chain';
  payloadMode: ValidateSeedMeta['payloadMode'];
  fieldName: ValidateSeedMeta['fieldName'];
  httpStatus: number | null;
  tokenFound: boolean;
  safeResponse: string | null;
  succeeded: boolean;
};

type DgiiBearerTokenResult = {
  token: string;
  source: DgiiTokenSource;
  meta?: Partial<ValidateSeedMeta>;
};

function extractXmlRootName(rawText: string | null) {
  const text = (rawText ?? '').trim();
  if (!text.startsWith('<')) return null;
  const match = text.match(/^<\?xml[^>]*>\s*<([\w:-]+)/i) ?? text.match(/^<([\w:-]+)/i);
  return match?.[1] ?? null;
}

function hasXmlNode(rawText: string | null, nodeName: string) {
  const text = (rawText ?? '').toLowerCase();
  if (!text) return false;
  const normalized = nodeName.toLowerCase();
  return text.includes(`<${normalized}`) || text.includes(`:${normalized}`);
}

function xmlEdgePreview(rawText: string, size = 120) {
  const normalized = rawText.replace(/\s+/g, ' ').trim();
  return {
    head: normalized.slice(0, size),
    tail: normalized.slice(Math.max(0, normalized.length - size)),
  };
}

function hasUtf8Bom(value: string) {
  return value.charCodeAt(0) === 0xfeff;
}

function hasXmlDeclaration(value: string) {
  return /^\uFEFF?\s*<\?xml\s/i.test(value);
}

function xmlStartsWithPreview(value: string, size = 120) {
  return value.slice(0, size).replace(/\s+/g, ' ').trim();
}

function findFirstElementByLocalName(node: any, localName: string): Element | null {
  const current = node as Element;
  if (current.nodeType === 1 && (current.localName === localName || current.nodeName.split(':').pop() === localName)) {
    return current;
  }

  for (let i = 0; i < node.childNodes.length; i += 1) {
    const found = findFirstElementByLocalName(node.childNodes[i], localName);
    if (found) return found;
  }

  return null;
}

function inspectSignedSeedBasics(xml: string) {
  const document = new DOMParser().parseFromString(xml.replace(/^\uFEFF/, ''), 'text/xml');
  const root = document.documentElement;
  const reference = findFirstElementByLocalName(document, 'Reference');
  return {
    rootName: root?.localName || root?.nodeName || null,
    hasRootIdAttribute: !!root?.hasAttribute('Id') || !!root?.hasAttribute('ID') || !!root?.hasAttribute('id'),
    rootId: root?.getAttribute('Id') ?? root?.getAttribute('ID') ?? root?.getAttribute('id') ?? null,
    signatureReferenceUri: reference?.getAttribute('URI') ?? null,
  };
}

function inspectSignedSeedXmlForDgiiWithoutMutation(signedXml: string, originalSeedXml: string): { xml: string; diagnostics: SignedSeedSanitizerDiagnostics } {
  const inspected = inspectSignedSeedBasics(signedXml);
  const signedXmlSizeBeforeSanitize = signedXml.length;
  const signedXmlHasBomBeforeSanitize = hasUtf8Bom(signedXml);
  const signedXmlHasDeclarationBeforeSanitize = hasXmlDeclaration(signedXml);

  return {
    xml: signedXml,
    diagnostics: {
      originalSeedRoot: extractXmlRootName(originalSeedXml),
      signedXmlHasBomBeforeSanitize,
      signedXmlHasBomAfterSanitize: signedXmlHasBomBeforeSanitize,
      signedXmlHasDeclarationBeforeSanitize,
      signedXmlHasDeclarationAfterSanitize: signedXmlHasDeclarationBeforeSanitize,
      signedXmlRootBeforeSanitize: inspected.rootName,
      signedXmlRootAfterSanitize: inspected.rootName,
      signedXmlHasRootIdAttributeBeforeSanitize: inspected.hasRootIdAttribute,
      signedXmlHasRootIdAttributeAfterSanitize: inspected.hasRootIdAttribute,
      rootIdBeforeSanitize: inspected.rootId,
      rootIdAfterSanitize: inspected.rootId,
      signatureReferenceUriBeforeSanitize: inspected.signatureReferenceUri,
      signatureReferenceUriAfterSanitize: inspected.signatureReferenceUri,
      signedXmlSizeBeforeSanitize,
      finalXmlSize: signedXml.length,
      finalXmlStartsWith: xmlStartsWithPreview(signedXml),
    },
  };
}

function saveSignedSeedXmlForDebug(xml: string) {
  if (process.env.DGII_DEBUG_SAVE_SIGNED_SEED_XML !== 'true') return null;
  const debugDir = path.resolve(process.cwd(), 'debug', 'dgii');
  const filePath = path.join(debugDir, 'last-signed-seed.xml');
  fs.mkdirSync(debugDir, { recursive: true });
  fs.writeFileSync(filePath, xml, { encoding: 'utf8' });
  return filePath;
}

function inspectDgiiSeedXsdStructure(xml: string) {
  const document = new DOMParser().parseFromString(xml.replace(/^\uFEFF/, ''), 'text/xml');
  const root = document.documentElement;
  const rootName = root?.localName || root?.nodeName || null;
  const rootAttributes = root
    ? Array.from({ length: root.attributes.length }, (_, index) => root.attributes.item(index)!)
        .filter(Boolean)
        .map((attr) => ({ name: attr.name, value: attr.value }))
    : [];
  const rootNonNamespaceAttributes = rootAttributes.filter(
    (attr) => attr.name !== 'xmlns:xsi' && attr.name !== 'xmlns:xsd' && attr.name !== 'xmlns' && attr.name !== 'xsi:schemaLocation',
  );
  const childElements = root
    ? Array.from({ length: root.childNodes.length }, (_, index) => root.childNodes.item(index))
        .filter((node) => !!node && node.nodeType === 1)
        .map((node) => (node as any).localName || (node as any).nodeName)
    : [];
  const nonSignatureChildren = childElements.filter((name) => name !== 'Signature');
  const signatureIndex = childElements.indexOf('Signature');
  const expectedSeedChildren = ['valor', 'fecha'];

  return {
    officialSeedRootExpected: 'SemillaModel',
    officialSeedChildrenExpected: expectedSeedChildren,
    rootName,
    rootAttributes,
    rootNonNamespaceAttributes,
    childElements,
    nonSignatureChildren,
    rootMatchesOfficialSeed: rootName === 'SemillaModel',
    seedElementOrderMatchesOfficialSeed:
      nonSignatureChildren.length === expectedSeedChildren.length &&
      expectedSeedChildren.every((name, index) => nonSignatureChildren[index] === name),
    hasRootIdAttribute: !!root?.hasAttribute('Id') || !!root?.hasAttribute('ID') || !!root?.hasAttribute('id'),
    hasOnlyNamespaceRootAttributes: rootNonNamespaceAttributes.length === 0,
    signatureIsEnvelopedAsLastChild: signatureIndex >= 0 && signatureIndex === childElements.length - 1,
    hasSchemaLocation: !!root?.hasAttribute('xsi:schemaLocation'),
  };
}

function matchesOfficialDgiiSeedSignatureShape(xml: string, diagnostics: SignedXmlDiagnostics) {
  const transformAlgorithms = [...xml.matchAll(/<Transform\s+Algorithm="([^"]+)"/g)].map((match) => match[1]);
  const transformShapeMatches =
    transformAlgorithms.length === 1
      ? transformAlgorithms[0] === 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
      : transformAlgorithms.length === 2 &&
        transformAlgorithms[0] === 'http://www.w3.org/2000/09/xmldsig#enveloped-signature' &&
        transformAlgorithms[1] === 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
  return (
    diagnostics.signedXmlRoot === 'SemillaModel' &&
    diagnostics.signedXmlHasSignature &&
    !diagnostics.signedXmlHasIdAttributeOnRoot &&
    diagnostics.signatureReferenceUri === '' &&
    diagnostics.canonicalizationAlgorithm === 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315' &&
    diagnostics.signatureAlgorithm === 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' &&
    diagnostics.digestAlgorithm === 'http://www.w3.org/2001/04/xmlenc#sha256' &&
    transformShapeMatches &&
    !/<KeyValue|<RSAKeyValue|<Exponent>/.test(xml)
  );
}

function validateSignedSeedXmlForDgii(signedSeedXml: string) {
  if (typeof signedSeedXml !== 'string' || signedSeedXml.trim().length === 0) {
    throw {
      status: 400,
      message: 'Semilla firmada vacía',
      errorCode: 'DGII_SEED_SIGNED_XML_INVALID',
    };
  }

  const inspectableXml = signedSeedXml.replace(/^\uFEFF/, '');
  const firstNonWhitespace = inspectableXml.search(/\S/);
  const startsLikeXml =
    firstNonWhitespace >= 0 &&
    (inspectableXml.slice(firstNonWhitespace).startsWith('<?xml') || inspectableXml.slice(firstNonWhitespace).startsWith('<'));
  if (!startsLikeXml) {
    throw {
      status: 400,
      message: 'La semilla firmada no tiene formato XML crudo',
      errorCode: 'DGII_SEED_SIGNED_XML_INVALID',
      details: {
        startsLikeXml,
        firstChars: inspectableXml.slice(0, 60),
      },
    };
  }

  if (inspectableXml.includes('\\"') || inspectableXml.includes('[object Object]')) {
    throw {
      status: 400,
      message: 'La semilla firmada parece serializada/escapada incorrectamente',
      errorCode: 'DGII_SEED_SIGNED_XML_INVALID',
    };
  }

  if (inspectableXml.includes('&lt;') && inspectableXml.includes('&gt;')) {
    throw {
      status: 400,
      message: 'La semilla firmada está escapada como texto en lugar de XML',
      errorCode: 'DGII_SEED_SIGNED_XML_INVALID',
    };
  }

  try {
    parseXml(inspectableXml);
  } catch {
    throw {
      status: 400,
      message: 'La semilla firmada no es parseable como XML',
      errorCode: 'DGII_SEED_SIGNED_XML_INVALID',
    };
  }

  const root = extractXmlRootName(inspectableXml);
  const rootNormalized = (root ?? '').toLowerCase();
  if (rootNormalized !== 'semillamodel') {
    throw {
      status: 400,
      message: 'La semilla firmada no conserva raíz SemillaModel',
      errorCode: 'DGII_SEED_SIGNED_XML_INVALID',
      details: { signedXmlRoot: root ?? null },
    };
  }

  const hasSignature = hasXmlNode(inspectableXml, 'Signature');
  const hasValor = hasXmlNode(inspectableXml, 'valor');
  const hasFecha = hasXmlNode(inspectableXml, 'fecha');
  if (!hasSignature || !hasValor || !hasFecha) {
    throw {
      status: 400,
      message: 'La semilla firmada perdió nodos obligatorios',
      errorCode: 'DGII_SEED_SIGNED_XML_INVALID',
      details: {
        hasSignature,
        hasValor,
        hasFecha,
        signedXmlRoot: root ?? null,
      },
    };
  }

  const structure = inspectDgiiSeedXsdStructure(inspectableXml);
  if (
    !structure.rootMatchesOfficialSeed ||
    !structure.seedElementOrderMatchesOfficialSeed ||
    structure.hasRootIdAttribute ||
    !structure.signatureIsEnvelopedAsLastChild
  ) {
    throw {
      status: 400,
      message: 'La semilla firmada no cumple la estructura SemillaModel oficial esperada por DGII',
      errorCode: 'DGII_SEED_SIGNED_XML_STRUCTURE_INVALID',
      details: { structure },
    };
  }

  return {
    signedXml: signedSeedXml,
    signedXmlRoot: root,
    signedXmlHasSignature: hasSignature,
    signedXmlSize: signedSeedXml.length,
  };
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
    'TOKEN',
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
    deepFindFirstString(raw, [
      'expiresIn',
      'ExpiresIn',
      'expires_in',
      'expiraEnSegundos',
      'ExpiraEnSegundos',
      'expira',
      'Expira',
      'expiracion',
      'Expiracion',
      'fechaExpiracion',
      'FechaExpiracion',
    ]),
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
  private preferredSeedSignatureMode: SeedSignatureMode = SEED_SIGNATURE_MODES[0];
  private preferredValidatePayload: Pick<ValidateSeedAttempt, 'payloadMode' | 'fieldName'> = {
    payloadMode: 'multipart',
    fieldName: 'xml',
  };

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

  private buildValidateAttempt(
    signedSeedXml: string,
    payloadMode: ValidateSeedMeta['payloadMode'],
    fieldName: ValidateSeedMeta['fieldName'],
  ): ValidateSeedAttempt {
    if (payloadMode === 'form-urlencoded') {
      return {
        requestContentType: 'application/x-www-form-urlencoded',
        payloadMode,
        fieldName,
        body: new URLSearchParams({ xml: signedSeedXml }).toString(),
        headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
      };
    }

    if (payloadMode === 'raw-xml') {
      return {
        requestContentType: 'application/xml',
        payloadMode,
        fieldName,
        body: signedSeedXml,
        headers: { 'content-type': 'application/xml; charset=utf-8' },
      };
    }

    const form = new FormData();
    form.append(fieldName, new Blob([signedSeedXml], { type: 'text/xml' }), 'semilla.xml');
    return {
      requestContentType: 'multipart/form-data',
      payloadMode,
      fieldName,
      body: form,
      headers: {},
    };
  }

  private async callValidateAttempt(
    validateUrl: string,
    userAgent: string,
    timeoutMs: number,
    payload: ValidateSeedAttempt,
    validatedXml: ReturnType<typeof validateSignedSeedXmlForDgii>,
    signedXmlDiagnostics: SignedXmlDiagnostics,
    sanitizerDiagnostics?: SignedSeedSanitizerDiagnostics,
  ) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(validateUrl, {
        method: 'POST',
        headers: {
          accept: 'application/json, application/xml, text/xml;q=0.9, */*;q=0.8',
          'user-agent': userAgent,
          ...payload.headers,
        },
        body: payload.body,
        signal: controller.signal,
      });

      const { raw, rawText } = await parseDgiiResponse(response);
      const token = extractDgiiToken(raw, response);
      const dgiiSafeResponse =
        deepFindFirstString(raw, ['Mensaje', 'mensaje', 'Message', 'message', 'descripcion', 'Descripcion']) ||
        summarizeRawText(rawText, 300);
      return {
        response,
        raw,
        rawText,
        token,
        meta: {
          originalSeedRoot: sanitizerDiagnostics?.originalSeedRoot ?? null,
          validateUrl,
          requestContentType: payload.requestContentType,
          payloadMode: payload.payloadMode,
          fieldName: payload.fieldName,
          httpStatus: response.status,
          responseContentType: response.headers.get('content-type') ?? '',
          rawTextSummary: summarizeRawText(rawText),
          dgiiSafeResponse,
          signedXmlRoot: signedXmlDiagnostics.signedXmlRoot ?? validatedXml.signedXmlRoot,
          signedXmlHasSignature: signedXmlDiagnostics.signedXmlHasSignature,
          signedXmlHasBom: sanitizerDiagnostics?.signedXmlHasBomAfterSanitize ?? hasUtf8Bom(validatedXml.signedXml),
          signedXmlHasDeclaration: sanitizerDiagnostics?.signedXmlHasDeclarationAfterSanitize ?? hasXmlDeclaration(validatedXml.signedXml),
          signedXmlHasIdAttributeOnRoot: signedXmlDiagnostics.signedXmlHasIdAttributeOnRoot,
          signedXmlHasRootIdAttribute: signedXmlDiagnostics.signedXmlHasIdAttributeOnRoot,
          signatureReferenceUri: signedXmlDiagnostics.signatureReferenceUri,
          signatureReferenceUriBeforeSanitize: sanitizerDiagnostics?.signatureReferenceUriBeforeSanitize ?? signedXmlDiagnostics.signatureReferenceUri,
          signatureReferenceUriAfterSanitize: sanitizerDiagnostics?.signatureReferenceUriAfterSanitize ?? signedXmlDiagnostics.signatureReferenceUri,
          canonicalizationAlgorithm: signedXmlDiagnostics.canonicalizationAlgorithm,
          signatureAlgorithm: signedXmlDiagnostics.signatureAlgorithm,
          digestAlgorithm: signedXmlDiagnostics.digestAlgorithm,
          signedXmlRootId: signedXmlDiagnostics.signedXmlRootId,
          rootIdBeforeSanitize: sanitizerDiagnostics?.rootIdBeforeSanitize ?? signedXmlDiagnostics.signedXmlRootId,
          rootIdAfterSanitize: sanitizerDiagnostics?.rootIdAfterSanitize ?? signedXmlDiagnostics.signedXmlRootId,
          signedXmlSize: validatedXml.signedXmlSize,
          signedXmlSizeBeforeSanitize: sanitizerDiagnostics?.signedXmlSizeBeforeSanitize ?? validatedXml.signedXmlSize,
          finalXmlSize: sanitizerDiagnostics?.finalXmlSize ?? validatedXml.signedXmlSize,
          finalXmlStartsWith: sanitizerDiagnostics?.finalXmlStartsWith ?? xmlStartsWithPreview(validatedXml.signedXml),
          finalXmlRootAfterSanitize: sanitizerDiagnostics?.signedXmlRootAfterSanitize ?? signedXmlDiagnostics.signedXmlRoot ?? validatedXml.signedXmlRoot,
          xmlDeclarationBeforeSanitize: sanitizerDiagnostics?.signedXmlHasDeclarationBeforeSanitize ?? hasXmlDeclaration(validatedXml.signedXml),
          xmlDeclarationAfterSanitize: sanitizerDiagnostics?.signedXmlHasDeclarationAfterSanitize ?? hasXmlDeclaration(validatedXml.signedXml),
        } satisfies ValidateSeedMeta,
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  private async runSeedDiagnosticMatrix(
    companyId: number,
    companyRnc: string | null,
    environment: DgiiEnvironment,
    requestId?: string,
  ): Promise<DiagnosticMatrixEntry[]> {
    const config = this.directory.getEnvironmentConfig(environment);
    if (!config.authSeedUrl || !config.authValidateUrl) {
      return [];
    }

    const { loaded } = await this.loadCompanyCertificate(companyId);
    const validateUrl = buildValidateUrlCandidates(config.authValidateUrl)[0] ?? config.authValidateUrl;
    const baseMode = SEED_SIGNATURE_MODES[0];
    const payloadVariants: Array<{
      mode: SeedSignatureMode;
      payloadMode: ValidateSeedMeta['payloadMode'];
      fieldName: ValidateSeedMeta['fieldName'];
    }> = [
      ...SEED_SIGNATURE_MODES.map((mode) => ({ mode, payloadMode: 'multipart' as const, fieldName: 'xml' as const })),
      { mode: baseMode, payloadMode: 'multipart', fieldName: 'archivo' },
      { mode: baseMode, payloadMode: 'multipart', fieldName: 'file' },
      { mode: baseMode, payloadMode: 'form-urlencoded', fieldName: 'x-www-form-urlencoded' },
      { mode: baseMode, payloadMode: 'raw-xml', fieldName: 'raw-xml' },
    ];
    const matrix: DiagnosticMatrixEntry[] = [];

    for (const variant of payloadVariants) {
      try {
        const seed = await this.requestDgiiSeed(companyId, environment, config.authSeedUrl, config.userAgent, config.timeoutMs);
        const signedXml = this.signatureService.signSeedXmlWithMode(
          seed.seedXml,
          loaded.privateKeyPem,
          loaded.certPem,
          loaded.chainPems,
          variant.mode,
        );
        const validatedXml = validateSignedSeedXmlForDgii(signedXml);
        const diagnostics = this.signatureService.inspectSignedXml(validatedXml.signedXml);
        const result = await this.callValidateAttempt(
          validateUrl,
          config.userAgent,
          config.timeoutMs,
          this.buildValidateAttempt(validatedXml.signedXml, variant.payloadMode, variant.fieldName),
          validatedXml,
          diagnostics,
        );
        const safeResponse =
          deepFindFirstString(result.raw, ['Mensaje', 'mensaje', 'Message', 'message', 'descripcion', 'Descripcion']) ||
          summarizeRawText(result.rawText, 300);
        matrix.push({
          signatureMode: variant.mode.label,
          canonicalization: variant.mode.canonicalizationAlgorithm,
          signatureAlgorithm: variant.mode.signatureAlgorithm,
          digestAlgorithm: variant.mode.digestAlgorithm,
          referenceUri: diagnostics.signatureReferenceUri ?? '',
          keyInfoMode: variant.mode.keyInfoMode,
          payloadMode: variant.payloadMode,
          fieldName: variant.fieldName,
          httpStatus: result.response.status,
          tokenFound: !!result.token,
          safeResponse,
          succeeded: result.response.ok && !!result.token,
        });
        if (result.response.ok && result.token) {
          this.preferredSeedSignatureMode = variant.mode;
          this.preferredValidatePayload = {
            payloadMode: variant.payloadMode,
            fieldName: variant.fieldName,
          };
        }
      } catch (error) {
        matrix.push({
          signatureMode: variant.mode.label,
          canonicalization: variant.mode.canonicalizationAlgorithm,
          signatureAlgorithm: variant.mode.signatureAlgorithm,
          digestAlgorithm: variant.mode.digestAlgorithm,
          referenceUri: '',
          keyInfoMode: variant.mode.keyInfoMode,
          payloadMode: variant.payloadMode,
          fieldName: variant.fieldName,
          httpStatus: typeof (error as any)?.status === 'number' ? (error as any)?.status : null,
          tokenFound: false,
          safeResponse: summarizeRawText(String((error as any)?.message ?? error), 300),
          succeeded: false,
        });
      }
    }

    console.info('[electronic-invoicing.dgii.auth] diagnostic.matrix', {
      requestId,
      companyId,
      companyRnc,
      environment,
      matrix,
    });

    return matrix;
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

  private async readAnyCachedToken(companyId: number, environment: DgiiEnvironment) {
    const cached = await this.prisma.electronicDgiiTokenCache.findUnique({
      where: { companyId_environment: { companyId, environment } },
    });
    if (!cached?.tokenEncrypted) return null;
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

  async requestManualSeedForSigning(
    companyId: number,
    environment: DgiiEnvironment,
    requestId?: string,
  ) {
    const config = this.directory.getEnvironmentConfig(environment);
    if (!config.authSeedUrl) {
      throw {
        status: 503,
        message: `Configuración de semilla DGII incompleta para ambiente ${environment}`,
        errorCode: 'DGII_AUTH_SEED_CONFIG_MISSING',
      };
    }

    const seed = await this.requestDgiiSeed(
      companyId,
      environment,
      config.authSeedUrl,
      config.userAgent,
      config.timeoutMs,
    );

    console.info('[electronic-invoicing.dgii.auth] manual_seed.downloaded', {
      requestId,
      companyId,
      environment,
      authSeedUrl: seed.meta.authSeedUrl,
      methodUsed: seed.meta.methodUsed,
      httpStatus: seed.meta.httpStatus,
      rootElement: seed.meta.rootElement,
      xmlSize: seed.meta.xmlSize,
    });

    return {
      seedXml: seed.seedXml,
      meta: seed.meta,
    };
  }

  async validateManualSignedSeed(
    companyId: number,
    environment: DgiiEnvironment,
    signedSeedXml: string,
    requestId?: string,
  ) {
    const config = this.directory.getEnvironmentConfig(environment);
    if (!config.authValidateUrl) {
      throw {
        status: 503,
        message: `Configuración de validación DGII incompleta para ambiente ${environment}`,
        errorCode: 'DGII_AUTH_VALIDATE_CONFIG_MISSING',
      };
    }

    const diagnostics = this.signatureService.inspectSignedXml(signedSeedXml);
    const root = diagnostics.signedXmlRoot ?? extractXmlRootName(signedSeedXml);
    if (!root || !root.toLowerCase().endsWith('semillamodel')) {
      throw {
        status: 400,
        message: 'El XML subido no parece ser una semilla DGII firmada. Descarga la semilla desde FULLPOS, fírmala con la app DGII y sube ese archivo.',
        errorCode: 'DGII_SIGNED_SEED_XML_EXPECTED',
        details: {
          signedXmlRoot: root,
          signedXmlHasSignature: diagnostics.signedXmlHasSignature,
        },
      };
    }
    if (!diagnostics.signedXmlHasSignature) {
      throw {
        status: 400,
        message: 'La semilla DGII subida no contiene firma digital.',
        errorCode: 'DGII_SIGNED_SEED_SIGNATURE_MISSING',
        details: { signedXmlRoot: root },
      };
    }

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
      eventType: 'auth.dgii.token.manual_seed_validated',
      eventSource: 'DGII',
      message: `Token DGII obtenido con semilla firmada manualmente para ${environment}`,
      payload: {
        environment,
        expiresAt: validated.expiresAt,
        validateUrl: validated.meta.validateUrl,
        signedXmlRoot: validated.meta.signedXmlRoot,
      },
      requestId,
    });

    console.info('[electronic-invoicing.dgii.auth] manual_seed.validated', {
      requestId,
      companyId,
      environment,
      validateUrl: validated.meta.validateUrl,
      httpStatus: validated.meta.httpStatus,
      tokenFound: !!validated.token,
      expiresAt: validated.expiresAt.toISOString(),
      signedXmlRoot: validated.meta.signedXmlRoot,
      signedXmlHasSignature: validated.meta.signedXmlHasSignature,
    });

    return {
      tokenAccepted: true,
      environment,
      issuedAt: validated.issuedAt.toISOString(),
      expiresAt: validated.expiresAt.toISOString(),
      validatedAt: validated.validatedAt.toISOString(),
      signedXmlRoot: validated.meta.signedXmlRoot,
      signedXmlHasSignature: validated.meta.signedXmlHasSignature,
      validateUrl: validated.meta.validateUrl,
      payloadMode: validated.meta.payloadMode,
      fieldName: validated.meta.fieldName,
      message: 'Semilla firmada validada por DGII. Token listo para enviar un caso de prueba.',
    };
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
  ): Promise<DgiiBearerTokenResult> {
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

    if (options?.forceRefresh) {
      const cached = await this.readAnyCachedToken(companyId, environment);
      const lastValidatedAt = cached?.lastValidatedAt?.getTime() ?? 0;
      const hasManualToken = !!cached?.token && lastValidatedAt > 0;
      if (hasManualToken) {
        const ageMs = Date.now() - lastValidatedAt;
        const maxManualTokenAgeMs = 23 * 60 * 60 * 1000;
        if (ageMs <= maxManualTokenAgeMs) {
          console.warn('[electronic-invoicing.dgii.auth] manual_cache.reused_on_force_refresh', {
            requestId,
            companyId,
            environment,
            lastValidatedAt: cached!.lastValidatedAt,
            expiresAt: cached!.expiresAt,
          });
          return { token: cached!.token, source: 'manual-cache' };
        }
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

    const companyIdentity = await this.prisma.company.findUnique({
      where: { id: companyId },
      select: { rnc: true },
    });

    const { certificate, loaded } = await this.loadCompanyCertificate(companyId);
    const seedResponse = await this.requestDgiiSeed(companyId, environment, config.authSeedUrl, config.userAgent, config.timeoutMs);

    console.info('[electronic-invoicing.dgii.auth] seed.response', {
      requestId,
      companyId,
      companyRnc: companyIdentity?.rnc ?? null,
      environment,
      authSeedUrl: seedResponse.meta.authSeedUrl,
      methodUsed: seedResponse.meta.methodUsed,
      httpStatus: seedResponse.meta.httpStatus,
      contentType: seedResponse.meta.contentType,
      xmlSize: seedResponse.meta.xmlSize,
      rootElement: seedResponse.meta.rootElement,
      containsSemillaModel: seedResponse.meta.containsSemillaModel,
      containsValor: seedResponse.meta.containsValor,
      containsFecha: seedResponse.meta.containsFecha,
      seedHead: seedResponse.meta.seedHead,
      seedTail: seedResponse.meta.seedTail,
    });

    const seedRootBefore = extractXmlRootName(seedResponse.seedXml);
    let signedSeedXml = '';
    try {
      signedSeedXml = this.signatureService.signSeedXmlWithMode(
        seedResponse.seedXml,
        loaded.privateKeyPem,
        loaded.certPem,
        loaded.chainPems,
        this.preferredSeedSignatureMode,
      );
    } catch (error) {
      throw {
        status: 502,
        message: error instanceof Error ? error.message : 'No se pudo firmar la semilla DGII',
        errorCode: 'DGII_SEED_SIGN_FAILED',
        details: {
          environment,
          companyId,
          companyRnc: companyIdentity?.rnc ?? null,
          certificateAlias: certificate.alias,
          rootBefore: seedRootBefore,
        },
      };
    }

    const certificateAnalysis = analyzeCertificateForDgii(
      loaded.subject,
      loaded.issuer,
      companyIdentity?.rnc ?? null,
      loaded.chainPems.length,
    );
    const seedRootAfter = extractXmlRootName(signedSeedXml);
    const signedSeedFinalXml = inspectSignedSeedXmlForDgiiWithoutMutation(signedSeedXml, seedResponse.seedXml);
    signedSeedXml = signedSeedFinalXml.xml;
    const signedXmlValidation = validateSignedSeedXmlForDgii(signedSeedXml);
    const signedXmlDiagnostics = this.signatureService.inspectSignedXml(signedXmlValidation.signedXml);
    const selfVerify = this.signatureService.verifySignedXml(signedXmlValidation.signedXml);
    const officialSeedSignatureShape = matchesOfficialDgiiSeedSignatureShape(signedXmlValidation.signedXml, signedXmlDiagnostics);
    if (!selfVerify.valid && !officialSeedSignatureShape) {
      throw {
        status: 502,
        message: 'La semilla DGII firmada no pasó la verificación local XMLDSig',
        errorCode: 'DGII_SEED_LOCAL_VERIFY_FAILED',
        details: {
          environment,
          companyId,
          companyRnc: companyIdentity?.rnc ?? null,
          certificateAlias: certificate.alias,
          selfVerifyValid: selfVerify.valid,
          selfVerifyErrors: selfVerify.errors,
          signedXmlRoot: signedXmlDiagnostics.signedXmlRoot,
          signedXmlHasSignature: signedXmlDiagnostics.signedXmlHasSignature,
          signedXmlHasIdAttributeOnRoot: signedXmlDiagnostics.signedXmlHasIdAttributeOnRoot,
          signatureReferenceUri: signedXmlDiagnostics.signatureReferenceUri,
          signedXmlRootId: signedXmlDiagnostics.signedXmlRootId,
          canonicalizationAlgorithm: signedXmlDiagnostics.canonicalizationAlgorithm,
          signatureAlgorithm: signedXmlDiagnostics.signatureAlgorithm,
          digestAlgorithm: signedXmlDiagnostics.digestAlgorithm,
        },
      };
    }
    if (!selfVerify.valid && officialSeedSignatureShape) {
      console.warn('[electronic-invoicing.dgii.auth] seed.local_verify_skipped_for_official_shape', {
        requestId,
        companyId,
        companyRnc: companyIdentity?.rnc ?? null,
        reason: 'xml-crypto local verifier can reject namespaced DGII seed XML when Reference declares only enveloped-signature; exact XML is still sent unchanged to DGII',
        selfVerifyErrors: selfVerify.errors,
      });
    }
    console.info('[electronic-invoicing.dgii.auth] seed.signed', {
      requestId,
      companyId,
      companyRnc: companyIdentity?.rnc ?? null,
      certificateAlias: certificate.alias,
      certificateSubject: loaded.subject,
      certificateIssuer: loaded.issuer,
      certificateSerialNumber: loaded.serialNumber,
      certificateValidTo: loaded.validTo.toISOString(),
      certificateChainCount: loaded.chainPems.length,
      certificateRncInSubject: certificateAnalysis.rncInCertificate,
      certificateIsNaturalPerson: certificateAnalysis.isNaturalPerson,
      certificateCompatibilityWarning: buildCertificateCompatibilityWarning(certificateAnalysis),
      signatureMode: this.preferredSeedSignatureMode.label,
      selfVerifyValid: selfVerify.valid,
      selfVerifyErrors: selfVerify.errors,
      rootBefore: seedRootBefore,
      rootAfter: seedRootAfter,
      signedXmlSize: signedXmlValidation.signedXmlSize,
      containsSignature: signedXmlValidation.signedXmlHasSignature,
      signedXmlHasIdAttributeOnRoot: signedXmlDiagnostics.signedXmlHasIdAttributeOnRoot,
      signatureReferenceUri: signedXmlDiagnostics.signatureReferenceUri,
      canonicalizationAlgorithm: signedXmlDiagnostics.canonicalizationAlgorithm,
      signatureAlgorithm: signedXmlDiagnostics.signatureAlgorithm,
      digestAlgorithm: signedXmlDiagnostics.digestAlgorithm,
      signedXmlRootId: signedXmlDiagnostics.signedXmlRootId,
      signedXmlHasBom: signedSeedFinalXml.diagnostics.signedXmlHasBomAfterSanitize,
      signedXmlHasDeclaration: signedSeedFinalXml.diagnostics.signedXmlHasDeclarationAfterSanitize,
      signedXmlHasRootIdAttribute: signedSeedFinalXml.diagnostics.signedXmlHasRootIdAttributeAfterSanitize,
      signatureReferenceUriBeforeSanitize: signedSeedFinalXml.diagnostics.signatureReferenceUriBeforeSanitize,
      signatureReferenceUriAfterSanitize: signedSeedFinalXml.diagnostics.signatureReferenceUriAfterSanitize,
      rootIdBeforeSanitize: signedSeedFinalXml.diagnostics.rootIdBeforeSanitize,
      rootIdAfterSanitize: signedSeedFinalXml.diagnostics.rootIdAfterSanitize,
      xmlDeclarationBeforeSanitize: signedSeedFinalXml.diagnostics.signedXmlHasDeclarationBeforeSanitize,
      xmlDeclarationAfterSanitize: signedSeedFinalXml.diagnostics.signedXmlHasDeclarationAfterSanitize,
      finalXmlSize: signedSeedFinalXml.diagnostics.finalXmlSize,
      finalXmlStartsWith: signedSeedFinalXml.diagnostics.finalXmlStartsWith,
      finalXmlRootAfterSanitize: signedSeedFinalXml.diagnostics.signedXmlRootAfterSanitize,
    });

    const debugSavedPath = saveSignedSeedXmlForDebug(signedXmlValidation.signedXml);
    console.info('[electronic-invoicing.dgii.auth] seed.signed.sanitize_diagnostics', {
      requestId,
      companyId,
      companyRnc: companyIdentity?.rnc ?? null,
      debugXmlSaved: !!debugSavedPath,
      debugXmlPath: debugSavedPath,
      diagnostics: signedSeedFinalXml.diagnostics,
      structure: inspectDgiiSeedXsdStructure(signedXmlValidation.signedXml),
    });

    let validated;
    try {
      validated = await this.validateDgiiSeed(
        companyId,
        environment,
        config.authValidateUrl,
        config.userAgent,
        config.timeoutMs,
        signedXmlValidation.signedXml,
        signedSeedFinalXml.diagnostics,
      );
    } catch (error) {
      if ((error as any)?.errorCode === 'DGII_SEED_VALIDATE_BAD_REQUEST') {
        const rawMessage = String((error as any)?.message ?? 'DGII no devolvió detalle');
        const compatibilityWarning = buildCertificateCompatibilityWarning(certificateAnalysis);
        const signerConfig = await this.prisma.electronicInboundEndpointConfig.findUnique({
          where: { companyId_branchId: { companyId, branchId: 0 } },
          select: {
            signerFullName: true,
            signerDocumentType: true,
            signerDocumentNumber: true,
            signerAuthorizedForDgii: true,
          },
        });
        const certificateIdentity = extractCertificateIdentity(loaded.subject, loaded.serialNumber);
        const signerNameMatchesCertificate = namesAreCompatible(
          signerConfig?.signerFullName,
          certificateIdentity.certificateSubjectName,
        );
        const signerDocumentMatchesCertificate =
          !!signerConfig?.signerDocumentNumber &&
          !!certificateIdentity.certificateDocumentNumber &&
          normalizeSignerDocumentNumber(signerConfig.signerDocumentNumber) ===
            normalizeSignerDocumentNumber(certificateIdentity.certificateDocumentNumber);
        const maybeInvalidSignature = rawMessage
          .toLowerCase()
          .includes('firma del certificado invalida') ||
          rawMessage.toLowerCase().includes('firma del certificado inválida');
        (error as any).message = buildUserFacingSeedValidationMessage(rawMessage);
        (error as any).details = {
          ...((error as any)?.details ?? {}),
          selfVerifyValid: selfVerify.valid,
          certificateSubject: loaded.subject,
          certificateIssuer: loaded.issuer,
          certificateSerialNumber: loaded.serialNumber,
          certSubjectShort: certificateAnalysis.certSubjectShort,
          certIssuer: loaded.issuer,
          certSerialNumber: loaded.serialNumber,
          environment,
          requestId,
          certificateCompatibilityWarning: compatibilityWarning,
          dgiiValidationDiagnosis: compatibilityWarning ?? classifyDgiiSeedValidationFailure(rawMessage, (error as any)?.details ?? {}),
          signerContext: {
            configured: !!signerConfig?.signerFullName,
            signerFullName: signerConfig?.signerFullName ?? null,
            signerDocumentType: signerConfig?.signerDocumentType ?? null,
            signerDocumentMasked: maskDocumentNumber(signerConfig?.signerDocumentNumber),
            signerAuthorizedForDgii: signerConfig?.signerAuthorizedForDgii ?? false,
            certificateName: certificateIdentity.certificateSubjectName,
            certificateDocumentMasked: maskDocumentNumber(certificateIdentity.certificateDocumentNumber),
            signerNameMatchesCertificate,
            signerDocumentMatchesCertificate,
            certificateLooksNaturalPerson: certificateAnalysis.isNaturalPerson,
            delegationLikelyRequired: certificateAnalysis.isNaturalPerson,
            recommendation:
              maybeInvalidSignature &&
              (!signerConfig?.signerAuthorizedForDgii || !signerDocumentMatchesCertificate)
                ? 'Verifique en DGII que el firmante está autorizado para este RNC y que su documento coincide con el certificado cargado.'
                : null,
          },
        };
      }
      throw error;
    }

    console.info('[electronic-invoicing.dgii.auth] seed.validate.response', {
      requestId,
      companyId,
      companyRnc: companyIdentity?.rnc ?? null,
      environment,
      validateUrl: validated.meta.validateUrl,
      requestContentType: validated.meta.requestContentType,
      payloadMode: validated.meta.payloadMode,
      fieldName: validated.meta.fieldName,
      httpStatus: validated.meta.httpStatus,
      responseContentType: validated.meta.responseContentType,
      tokenFound: !!validated.token,
      signedXmlRoot: validated.meta.signedXmlRoot,
      signedXmlHasSignature: validated.meta.signedXmlHasSignature,
      signedXmlHasIdAttributeOnRoot: validated.meta.signedXmlHasIdAttributeOnRoot,
      signatureReferenceUri: validated.meta.signatureReferenceUri,
      signedXmlRootId: validated.meta.signedXmlRootId,
      canonicalizationAlgorithm: validated.meta.canonicalizationAlgorithm,
      signatureAlgorithm: validated.meta.signatureAlgorithm,
      digestAlgorithm: validated.meta.digestAlgorithm,
      signedXmlSize: validated.meta.signedXmlSize,
      expiresAt: validated.expiresAt.toISOString(),
    });

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

    return { token: validated.token, source: 'auto', meta: validated.meta };
  }

  private async requestDgiiSeed(
    companyId: number,
    environment: DgiiEnvironment,
    url: string,
    userAgent: string,
    timeoutMs: number,
  ): Promise<{ seedXml: string; raw: unknown; meta: SeedRequestMeta }> {
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
            errorCode: 'DGII_SEED_REQUEST_FAILED',
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

        const seedXml = extractDgiiSeedXml(fallback.raw, fallback.rawText);
        if (!seedXml.trim().startsWith('<')) {
          throw {
            status: 502,
            message: 'DGII devolvió semilla sin XML válido',
            errorCode: 'DGII_SEED_INVALID_XML',
            details: {
              environment,
              methodTried: ['POST', 'GET'],
              rawTextSummary: summarizeRawText(fallback.rawText),
            },
          };
        }

        const seedPreview = xmlEdgePreview(seedXml);
        return {
          seedXml,
          raw: fallback.raw,
          meta: {
            authSeedUrl: url,
            methodUsed: 'GET',
            httpStatus: fallback.response.status,
            contentType: fallback.response.headers.get('content-type') ?? '',
            xmlSize: seedXml.length,
            rootElement: extractXmlRootName(seedXml),
            containsSemillaModel: hasXmlNode(seedXml, 'SemillaModel'),
            containsValor: hasXmlNode(seedXml, 'valor'),
            containsFecha: hasXmlNode(seedXml, 'fecha'),
            rawTextSummary: summarizeRawText(fallback.rawText),
            seedHead: seedPreview.head,
            seedTail: seedPreview.tail,
          },
        };
      }

      if (!primary.response.ok) {
        throw {
          status: 502,
          message:
            deepFindFirstString(primary.raw, ['Mensaje', 'mensaje', 'Message', 'message']) ||
            `DGII rechazó la solicitud de semilla (HTTP ${primary.response.status})`,
          errorCode: 'DGII_SEED_REQUEST_FAILED',
          details: {
            environment,
            methodTried: ['POST'],
            httpStatus: primary.response.status,
            raw: primary.raw,
            rawTextSummary: summarizeRawText(primary.rawText),
          },
        };
      }

      const seedXml = extractDgiiSeedXml(primary.raw, primary.rawText);
      if (!seedXml.trim().startsWith('<')) {
        throw {
          status: 502,
          message: 'DGII devolvió semilla sin XML válido',
          errorCode: 'DGII_SEED_INVALID_XML',
          details: {
            environment,
            methodTried: ['POST'],
            rawTextSummary: summarizeRawText(primary.rawText),
          },
        };
      }

      const seedPreview = xmlEdgePreview(seedXml);
      return {
        seedXml,
        raw: primary.raw,
        meta: {
          authSeedUrl: url,
          methodUsed: 'POST',
          httpStatus: primary.response.status,
          contentType: primary.response.headers.get('content-type') ?? '',
          xmlSize: seedXml.length,
          rootElement: extractXmlRootName(seedXml),
          containsSemillaModel: hasXmlNode(seedXml, 'SemillaModel'),
          containsValor: hasXmlNode(seedXml, 'valor'),
          containsFecha: hasXmlNode(seedXml, 'fecha'),
          rawTextSummary: summarizeRawText(primary.rawText),
          seedHead: seedPreview.head,
          seedTail: seedPreview.tail,
        },
      };
    } catch (error) {
      await this.prisma.electronicDgiiTokenCache.upsert({
        where: { companyId_environment: { companyId, environment } },
        update: {
          lastErrorCode: (error as any)?.errorCode ?? 'DGII_SEED_REQUEST_FAILED',
          lastErrorMessage: error instanceof Error ? error.message : String((error as any)?.message ?? error),
        },
        create: {
          companyId,
          environment,
          tokenEncrypted: encryptSecret('seed-error-placeholder'),
          issuedAt: new Date(),
          expiresAt: new Date(Date.now() - 1000),
          lastErrorCode: (error as any)?.errorCode ?? 'DGII_SEED_REQUEST_FAILED',
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
    sanitizerDiagnostics?: SignedSeedSanitizerDiagnostics,
  ): Promise<{ token: string; issuedAt: Date; expiresAt: Date; validatedAt: Date; meta: ValidateSeedMeta }> {
    const validatedXml = validateSignedSeedXmlForDgii(signedSeedXml);
    const signedXmlDiagnostics: SignedXmlDiagnostics = this.signatureService.inspectSignedXml(validatedXml.signedXml);

    const validateUrls = buildValidateUrlCandidates(url);
    const attempts = [
      this.buildValidateAttempt(
        validatedXml.signedXml,
        this.preferredValidatePayload.payloadMode,
        this.preferredValidatePayload.fieldName,
      ),
    ];

    let lastFailure: unknown = null;
    let lastFailureMeta: ValidateSeedMeta | null = null;

    try {
      console.info('[electronic-invoicing.dgii.auth] validate.urls', {
        companyId,
        environment,
        configuredValidateUrl: url,
        candidates: validateUrls,
      });

      for (const validateUrl of validateUrls) {
        for (const attempt of attempts) {
          const result = await this.callValidateAttempt(
            validateUrl,
            userAgent,
            timeoutMs,
            attempt,
            validatedXml,
            signedXmlDiagnostics,
            sanitizerDiagnostics,
          );

          console.info('[electronic-invoicing.dgii.auth] validate.attempt', {
            companyId,
            environment,
            validateUrl,
            requestContentType: result.meta.requestContentType,
            payloadMode: result.meta.payloadMode,
            fieldName: result.meta.fieldName,
            httpStatus: result.response.status,
            responseContentType: result.meta.responseContentType,
            tokenFound: !!result.token,
            signedXmlRoot: result.meta.signedXmlRoot,
            signedXmlHasSignature: result.meta.signedXmlHasSignature,
            signedXmlHasBom: result.meta.signedXmlHasBom,
            signedXmlHasDeclaration: result.meta.signedXmlHasDeclaration,
            signedXmlHasIdAttributeOnRoot: result.meta.signedXmlHasIdAttributeOnRoot,
            signedXmlHasRootIdAttribute: result.meta.signedXmlHasRootIdAttribute,
            signatureReferenceUri: result.meta.signatureReferenceUri,
            signatureReferenceUriBeforeSanitize: result.meta.signatureReferenceUriBeforeSanitize,
            signatureReferenceUriAfterSanitize: result.meta.signatureReferenceUriAfterSanitize,
            canonicalizationAlgorithm: result.meta.canonicalizationAlgorithm,
            signatureAlgorithm: result.meta.signatureAlgorithm,
            digestAlgorithm: result.meta.digestAlgorithm,
            signedXmlSize: result.meta.signedXmlSize,
            finalXmlSize: result.meta.finalXmlSize,
            finalXmlStartsWith: result.meta.finalXmlStartsWith,
            finalXmlRootAfterSanitize: result.meta.finalXmlRootAfterSanitize,
            rawTextSummary: result.meta.rawTextSummary,
          });

          if (result.response.ok && result.token) {
            return {
              token: result.token,
              issuedAt: new Date(),
              expiresAt: extractDgiiExpiry(result.raw, result.token),
              validatedAt: new Date(),
              meta: result.meta,
            };
          }

          lastFailureMeta = result.meta;
          const rawValueMessage =
            typeof result.raw === 'string' && result.raw.trim().length > 0 ? result.raw.trim() : undefined;
          const rawTextMessage =
            typeof result.rawText === 'string' && result.rawText.trim().length > 0 ? result.rawText.trim() : undefined;
          const responseMessage =
            deepFindFirstString(result.raw, ['Mensaje', 'mensaje', 'Message', 'message', 'descripcion', 'Descripcion']) ||
            rawValueMessage ||
            rawTextMessage ||
            'DGII no devolvió token válido';

          lastFailure = {
            status: result.response.status === 400 ? 400 : 502,
            message: responseMessage,
            errorCode: result.response.status === 400 ? 'DGII_SEED_VALIDATE_BAD_REQUEST' : 'DGII_TOKEN_MISSING',
            details: {
              environment,
              httpStatus: result.response.status,
              raw: result.raw,
              validateUrl,
              requestContentType: result.meta.requestContentType,
              payloadMode: result.meta.payloadMode,
              fieldName: result.meta.fieldName,
              rawTextSummary: result.meta.rawTextSummary,
              dgiiSafeResponse: result.meta.dgiiSafeResponse,
              originalSeedRoot: result.meta.originalSeedRoot,
              signedXmlRoot: result.meta.signedXmlRoot,
              signedXmlHasSignature: result.meta.signedXmlHasSignature,
              signedXmlHasBom: result.meta.signedXmlHasBom,
              signedXmlHasDeclaration: result.meta.signedXmlHasDeclaration,
              signedXmlHasIdAttributeOnRoot: result.meta.signedXmlHasIdAttributeOnRoot,
              signedXmlHasRootIdAttribute: result.meta.signedXmlHasRootIdAttribute,
              signatureReferenceUri: result.meta.signatureReferenceUri,
              signatureReferenceUriBeforeSanitize: result.meta.signatureReferenceUriBeforeSanitize,
              signatureReferenceUriAfterSanitize: result.meta.signatureReferenceUriAfterSanitize,
              signedXmlRootId: result.meta.signedXmlRootId,
              rootIdBeforeSanitize: result.meta.rootIdBeforeSanitize,
              rootIdAfterSanitize: result.meta.rootIdAfterSanitize,
              canonicalizationAlgorithm: result.meta.canonicalizationAlgorithm,
              signatureAlgorithm: result.meta.signatureAlgorithm,
              digestAlgorithm: result.meta.digestAlgorithm,
              signedXmlSize: result.meta.signedXmlSize,
              signedXmlSizeBeforeSanitize: result.meta.signedXmlSizeBeforeSanitize,
              finalXmlSize: result.meta.finalXmlSize,
              finalXmlStartsWith: result.meta.finalXmlStartsWith,
              finalXmlRootAfterSanitize: result.meta.finalXmlRootAfterSanitize,
              xmlDeclarationBeforeSanitize: result.meta.xmlDeclarationBeforeSanitize,
              xmlDeclarationAfterSanitize: result.meta.xmlDeclarationAfterSanitize,
              dgiiValidationDiagnosis: classifyDgiiSeedValidationFailure(responseMessage, result.meta),
            },
          };

          // Si el endpoint no es válido o método no permitido, pasa al siguiente endpoint candidato.
          if (result.response.status === 404 || result.response.status === 405) {
            break;
          }

          // 400 funcional: DGII entendió el endpoint pero rechazó el archivo. No reintentar con otros formatos.
          if (result.response.status === 400) {
            throw lastFailure;
          }

          // Otros estados: no seguir probando variantes de payload/endpoint.
          throw lastFailure;
        }
      }

      throw lastFailure ?? {
        status: 502,
        message: 'DGII no devolvió token válido',
        errorCode: 'DGII_TOKEN_MISSING',
        details: { environment },
      };
    } catch (error) {
      await this.prisma.electronicDgiiTokenCache.upsert({
        where: { companyId_environment: { companyId, environment } },
        update: {
          lastErrorCode: (error as any)?.errorCode ?? 'DGII_TOKEN_MISSING',
          lastErrorMessage: error instanceof Error ? error.message : String((error as any)?.message ?? error),
        },
        create: {
          companyId,
          environment,
          tokenEncrypted: encryptSecret('validation-error-placeholder'),
          issuedAt: new Date(),
          expiresAt: new Date(Date.now() - 1000),
          lastErrorCode: (error as any)?.errorCode ?? 'DGII_TOKEN_MISSING',
          lastErrorMessage: error instanceof Error ? error.message : String((error as any)?.message ?? error),
        },
      });

      console.error('[electronic-invoicing.dgii.auth] validate.error', {
        companyId,
        environment,
        validateUrl: url,
        requestContentType: lastFailureMeta?.requestContentType ?? null,
        payloadMode: lastFailureMeta?.payloadMode ?? null,
        fieldName: lastFailureMeta?.fieldName ?? null,
        responseStatus: (error as any)?.details?.httpStatus ?? null,
        rawResponse: (error as any)?.details?.raw ?? null,
        rawTextSummary: (error as any)?.details?.rawTextSummary ?? null,
        dgiiSafeResponse: (error as any)?.details?.dgiiSafeResponse ?? null,
        originalSeedRoot: (error as any)?.details?.originalSeedRoot ?? null,
        signedXmlRoot: (error as any)?.details?.signedXmlRoot ?? null,
        signedXmlHasSignature: (error as any)?.details?.signedXmlHasSignature ?? null,
        signedXmlHasBom: (error as any)?.details?.signedXmlHasBom ?? null,
        signedXmlHasDeclaration: (error as any)?.details?.signedXmlHasDeclaration ?? null,
        signedXmlHasIdAttributeOnRoot: (error as any)?.details?.signedXmlHasIdAttributeOnRoot ?? null,
        signedXmlHasRootIdAttribute: (error as any)?.details?.signedXmlHasRootIdAttribute ?? null,
        signatureReferenceUri: (error as any)?.details?.signatureReferenceUri ?? null,
        signatureReferenceUriBeforeSanitize: (error as any)?.details?.signatureReferenceUriBeforeSanitize ?? null,
        signatureReferenceUriAfterSanitize: (error as any)?.details?.signatureReferenceUriAfterSanitize ?? null,
        signedXmlRootId: (error as any)?.details?.signedXmlRootId ?? null,
        rootIdBeforeSanitize: (error as any)?.details?.rootIdBeforeSanitize ?? null,
        rootIdAfterSanitize: (error as any)?.details?.rootIdAfterSanitize ?? null,
        canonicalizationAlgorithm: (error as any)?.details?.canonicalizationAlgorithm ?? null,
        signatureAlgorithm: (error as any)?.details?.signatureAlgorithm ?? null,
        digestAlgorithm: (error as any)?.details?.digestAlgorithm ?? null,
        signedXmlSize: (error as any)?.details?.signedXmlSize ?? null,
        signedXmlSizeBeforeSanitize: (error as any)?.details?.signedXmlSizeBeforeSanitize ?? null,
        finalXmlSize: (error as any)?.details?.finalXmlSize ?? null,
        finalXmlStartsWith: (error as any)?.details?.finalXmlStartsWith ?? null,
        finalXmlRootAfterSanitize: (error as any)?.details?.finalXmlRootAfterSanitize ?? null,
        xmlDeclarationBeforeSanitize: (error as any)?.details?.xmlDeclarationBeforeSanitize ?? null,
        xmlDeclarationAfterSanitize: (error as any)?.details?.xmlDeclarationAfterSanitize ?? null,
        errorCode: (error as any)?.errorCode ?? 'DGII_TOKEN_MISSING',
        errorMessage: (error as any)?.message ?? 'DGII no devolvió token válido',
      });

      throw error;
    }
  }

  async debugAuthenticateByLocators(
    input: {
      companyRnc?: string;
      companyCloudId?: string;
      environment?: DgiiEnvironment;
      forceRefresh?: boolean;
      manualToken?: string;
      diagnosticMatrix?: boolean;
    },
    requestId?: string,
  ) {
    const company = await this.mapper.resolveCompanyOrThrow(input.companyRnc, input.companyCloudId, {
      preferCloudOnConflict: true,
      requestId,
      source: 'debug_dgii_auth',
    });
    const environment = input.environment ?? env.DGII_DEFAULT_ENVIRONMENT;
    const config = this.directory.getEnvironmentConfig(environment);
    const activeCertificate = await this.prisma.electronicCertificate.findFirst({
      where: { companyId: company.id, status: 'ACTIVE' },
      orderBy: { updatedAt: 'desc' },
    });
    const now = Date.now();

    const out: {
      companyResolved: boolean;
      companyId: number;
      companyRnc: string | null;
      companyCloudId: string | null;
      environment: DgiiEnvironment;
      certificateFound: boolean;
      certificateValid: boolean;
      authSeedUrl: string | null;
      authValidateUrl: string | null;
      endpointUsed: string | null;
      seedOk: boolean;
      signOk: boolean;
      validateOk: boolean;
      tokenFound: boolean;
      tokenSource?: DgiiTokenSource;
      httpStatus?: number;
      errorCode?: string;
      errorMessage?: string;
      payloadMode?: ValidateSeedMeta['payloadMode'];
      rootElement?: string | null;
      hasSignature?: boolean;
      signedXmlSize?: number;
      validateFieldName?: ValidateSeedMeta['fieldName'];
      validateContentType?: string;
      validateRawResponse?: unknown;
      dgiiSafeResponse?: string | null;
      dgiiHttpStatus?: number | null;
      dgiiValidationDiagnosis?: string | null;
      signerContext?: Record<string, unknown>;
      originalSeedRoot?: string | null;
      signedXmlRoot?: string | null;
      signedXmlHasSignature?: boolean;
      signedXmlHasBom?: boolean | null;
      signedXmlHasDeclaration?: boolean | null;
      signedXmlHasIdAttributeOnRoot?: boolean;
      signedXmlHasRootIdAttribute?: boolean | null;
      signedXmlRootId?: string | null;
      signatureReferenceUri?: string | null;
      signatureReferenceUriBeforeSanitize?: string | null;
      signatureReferenceUriAfterSanitize?: string | null;
      rootIdBeforeSanitize?: string | null;
      rootIdAfterSanitize?: string | null;
      signedXmlSizeBeforeSanitize?: number | null;
      finalXmlSize?: number | null;
      finalXmlStartsWith?: string | null;
      finalXmlRootAfterSanitize?: string | null;
      xmlDeclarationBeforeSanitize?: boolean | null;
      xmlDeclarationAfterSanitize?: boolean | null;
      canonicalizationAlgorithm?: string | null;
      signatureAlgorithm?: string | null;
      digestAlgorithm?: string | null;
      validatePayloadMode?: ValidateSeedMeta['payloadMode'];
      selfVerifyValid?: boolean | null;
      certificateSubject?: string | null;
      certificateIssuer?: string | null;
      certificateSerialNumber?: string | null;
      certificateFingerprint?: string | null;
      certificateValidTo?: string | null;
      certificateSelectedIndex?: number | null;
      certificateHasPrivateKey?: boolean | null;
      certificateDiagnostics?: {
        subject: string;
        certSubjectShort: string;
        issuer: string;
        serialNumber: string;
        fingerprint: string;
        selectedIndex: number;
        validTo: string;
        hasPrivateKey: boolean;
        keyMatchesCertificate: boolean;
        rncInCertificate: string | null;
        rncMatchesCompany: boolean;
        isNaturalPerson: boolean;
        isLegalEntity: boolean;
        chainCertCount: number;
        keyInfoCertificateCount: number;
        keyInfoContainsX509Certificate: boolean;
        localSignatureVerify: boolean | null;
        compatibilityWarning: string | null;
      };
      diagnosticMatrix?: DiagnosticMatrixEntry[];
      tokenPreview?: never;
      token?: never;
    } = {
      companyResolved: true,
      companyId: company.id,
      companyRnc: company.rnc ?? null,
      companyCloudId: company.cloudCompanyId ?? null,
      environment,
      certificateFound: !!activeCertificate,
      certificateValid: !!activeCertificate && activeCertificate.validFrom.getTime() <= now && activeCertificate.validTo.getTime() >= now,
      authSeedUrl: config.authSeedUrl ?? null,
      authValidateUrl: config.authValidateUrl ?? null,
      endpointUsed: config.authValidateUrl ?? config.authSeedUrl ?? null,
      seedOk: false,
      signOk: false,
      validateOk: false,
      tokenFound: false,
    };

    const certificateDetails = activeCertificate ? await this.loadCompanyCertificate(company.id).catch(() => null) : null;
    if (certificateDetails) {
      const analysis = analyzeCertificateForDgii(
        certificateDetails.loaded.subject,
        certificateDetails.loaded.issuer,
        company.rnc ?? null,
        certificateDetails.loaded.chainPems.length,
      );
      out.certificateDiagnostics = {
        subject: certificateDetails.loaded.subject,
        certSubjectShort: analysis.certSubjectShort,
        issuer: certificateDetails.loaded.issuer,
        serialNumber: certificateDetails.loaded.serialNumber,
        fingerprint: certificateDetails.loaded.fingerprintSha256,
        selectedIndex: certificateDetails.loaded.selectedCertificateIndex,
        validTo: certificateDetails.loaded.validTo.toISOString(),
        hasPrivateKey: !!certificateDetails.loaded.privateKeyPem,
        keyMatchesCertificate: certificateDetails.loaded.keyMatchesCertificate,
        rncInCertificate: analysis.rncInCertificate,
        rncMatchesCompany: analysis.rncMatchesCompany,
        isNaturalPerson: analysis.isNaturalPerson,
        isLegalEntity: analysis.isLegalEntity,
        chainCertCount: certificateDetails.loaded.chainPems.length,
        keyInfoCertificateCount: certificateDetails.loaded.chainPems.length + 1,
        keyInfoContainsX509Certificate: true,
        localSignatureVerify: null,
        compatibilityWarning: buildCertificateCompatibilityWarning(analysis),
      };
    }

    try {
      const tokenResult = await this.getCompanyBearerTokenWithMeta(company.id, environment, requestId, {
        forceRefresh: input.forceRefresh ?? true,
        manualToken: input.manualToken,
      });

      out.seedOk = true;
      out.signOk = true;
      out.validateOk = true;
      out.tokenFound = !!tokenResult.token;
      out.tokenSource = tokenResult.source;
      out.httpStatus = 200;
      out.dgiiHttpStatus = tokenResult.meta?.httpStatus ?? 200;
      out.dgiiSafeResponse = tokenResult.meta?.dgiiSafeResponse ?? null;
      out.originalSeedRoot = tokenResult.meta?.originalSeedRoot ?? undefined;
      out.signedXmlRoot = tokenResult.meta?.signedXmlRoot ?? undefined;
      out.signedXmlHasSignature = tokenResult.meta?.signedXmlHasSignature ?? undefined;
      out.signedXmlHasBom = tokenResult.meta?.signedXmlHasBom ?? undefined;
      out.signedXmlHasDeclaration = tokenResult.meta?.signedXmlHasDeclaration ?? undefined;
      out.signedXmlHasIdAttributeOnRoot = tokenResult.meta?.signedXmlHasIdAttributeOnRoot ?? undefined;
      out.signedXmlHasRootIdAttribute = tokenResult.meta?.signedXmlHasRootIdAttribute ?? undefined;
      out.signedXmlRootId = tokenResult.meta?.signedXmlRootId ?? undefined;
      out.signatureReferenceUri = tokenResult.meta?.signatureReferenceUri ?? undefined;
      out.signatureReferenceUriBeforeSanitize = tokenResult.meta?.signatureReferenceUriBeforeSanitize ?? undefined;
      out.signatureReferenceUriAfterSanitize = tokenResult.meta?.signatureReferenceUriAfterSanitize ?? undefined;
      out.rootIdBeforeSanitize = tokenResult.meta?.rootIdBeforeSanitize ?? undefined;
      out.rootIdAfterSanitize = tokenResult.meta?.rootIdAfterSanitize ?? undefined;
      out.signedXmlSizeBeforeSanitize = tokenResult.meta?.signedXmlSizeBeforeSanitize ?? undefined;
      out.finalXmlSize = tokenResult.meta?.finalXmlSize ?? undefined;
      out.finalXmlStartsWith = tokenResult.meta?.finalXmlStartsWith ?? undefined;
      out.finalXmlRootAfterSanitize = tokenResult.meta?.finalXmlRootAfterSanitize ?? undefined;
      out.xmlDeclarationBeforeSanitize = tokenResult.meta?.xmlDeclarationBeforeSanitize ?? undefined;
      out.xmlDeclarationAfterSanitize = tokenResult.meta?.xmlDeclarationAfterSanitize ?? undefined;
      out.canonicalizationAlgorithm = tokenResult.meta?.canonicalizationAlgorithm ?? undefined;
      out.signatureAlgorithm = tokenResult.meta?.signatureAlgorithm ?? undefined;
      out.digestAlgorithm = tokenResult.meta?.digestAlgorithm ?? undefined;
      out.validatePayloadMode = tokenResult.meta?.payloadMode ?? undefined;
      out.validateFieldName = tokenResult.meta?.fieldName ?? undefined;
      out.validateContentType = tokenResult.meta?.requestContentType ?? undefined;
      out.selfVerifyValid = true;
      out.certificateSubject = out.certificateDiagnostics?.subject ?? undefined;
      out.certificateIssuer = out.certificateDiagnostics?.issuer ?? undefined;
      out.certificateSerialNumber = out.certificateDiagnostics?.serialNumber ?? undefined;
      out.certificateFingerprint = out.certificateDiagnostics?.fingerprint ?? undefined;
      out.certificateValidTo = out.certificateDiagnostics?.validTo ?? undefined;
      out.certificateSelectedIndex = out.certificateDiagnostics?.selectedIndex ?? undefined;
      out.certificateHasPrivateKey = out.certificateDiagnostics?.hasPrivateKey ?? undefined;
      if (input.diagnosticMatrix) {
        out.diagnosticMatrix = await this.runSeedDiagnosticMatrix(company.id, company.rnc ?? null, environment, requestId);
      }
      return out;
    } catch (error) {
      const details = ((error as any)?.details ?? null) as Record<string, unknown> | null;
      out.errorCode = (error as any)?.errorCode ?? 'DGII_AUTH_DEBUG_FAILED';
      out.errorMessage = (error as any)?.message ?? 'Error desconocido en autenticación DGII';
      out.httpStatus = (error as any)?.status ?? (typeof details?.httpStatus === 'number' ? (details.httpStatus as number) : undefined);
      out.dgiiHttpStatus = (typeof details?.httpStatus === 'number' ? (details.httpStatus as number) : null);
      out.dgiiSafeResponse = (details?.dgiiSafeResponse as string | null | undefined) ?? null;
      out.payloadMode = (details?.payloadMode as ValidateSeedMeta['payloadMode'] | undefined) ?? undefined;
      out.rootElement = (details?.signedXmlRoot as string | null | undefined) ?? undefined;
      out.hasSignature = (details?.signedXmlHasSignature as boolean | undefined) ?? undefined;
      out.signedXmlSize = (details?.signedXmlSize as number | undefined) ?? undefined;
      out.validateFieldName = (details?.fieldName as ValidateSeedMeta['fieldName'] | undefined) ?? undefined;
      out.validateContentType = (details?.requestContentType as string | undefined) ?? undefined;
      out.originalSeedRoot = (details?.originalSeedRoot as string | null | undefined) ?? undefined;
      out.signedXmlRoot = (details?.signedXmlRoot as string | null | undefined) ?? undefined;
      out.signedXmlHasSignature = (details?.signedXmlHasSignature as boolean | undefined) ?? undefined;
      out.signedXmlHasBom = (details?.signedXmlHasBom as boolean | undefined) ?? undefined;
      out.signedXmlHasDeclaration = (details?.signedXmlHasDeclaration as boolean | undefined) ?? undefined;
      out.signedXmlHasIdAttributeOnRoot = (details?.signedXmlHasIdAttributeOnRoot as boolean | undefined) ?? undefined;
      out.signedXmlHasRootIdAttribute = (details?.signedXmlHasRootIdAttribute as boolean | undefined) ?? undefined;
      out.signedXmlRootId = (details?.signedXmlRootId as string | null | undefined) ?? undefined;
      out.signatureReferenceUri = (details?.signatureReferenceUri as string | null | undefined) ?? undefined;
      out.signatureReferenceUriBeforeSanitize = (details?.signatureReferenceUriBeforeSanitize as string | null | undefined) ?? undefined;
      out.signatureReferenceUriAfterSanitize = (details?.signatureReferenceUriAfterSanitize as string | null | undefined) ?? undefined;
      out.rootIdBeforeSanitize = (details?.rootIdBeforeSanitize as string | null | undefined) ?? undefined;
      out.rootIdAfterSanitize = (details?.rootIdAfterSanitize as string | null | undefined) ?? undefined;
      out.signedXmlSizeBeforeSanitize = (details?.signedXmlSizeBeforeSanitize as number | undefined) ?? undefined;
      out.finalXmlSize = (details?.finalXmlSize as number | undefined) ?? undefined;
      out.finalXmlStartsWith = (details?.finalXmlStartsWith as string | undefined) ?? undefined;
      out.finalXmlRootAfterSanitize = (details?.finalXmlRootAfterSanitize as string | null | undefined) ?? undefined;
      out.xmlDeclarationBeforeSanitize = (details?.xmlDeclarationBeforeSanitize as boolean | undefined) ?? undefined;
      out.xmlDeclarationAfterSanitize = (details?.xmlDeclarationAfterSanitize as boolean | undefined) ?? undefined;
      out.canonicalizationAlgorithm = (details?.canonicalizationAlgorithm as string | null | undefined) ?? undefined;
      out.signatureAlgorithm = (details?.signatureAlgorithm as string | null | undefined) ?? undefined;
      out.digestAlgorithm = (details?.digestAlgorithm as string | null | undefined) ?? undefined;
      out.validatePayloadMode = (details?.payloadMode as ValidateSeedMeta['payloadMode'] | undefined) ?? undefined;
      out.selfVerifyValid = (details?.selfVerifyValid as boolean | undefined) ?? out.certificateDiagnostics?.localSignatureVerify ?? undefined;
      out.certificateSubject = (details?.certificateSubject as string | undefined) ?? out.certificateDiagnostics?.subject ?? undefined;
      out.certificateIssuer = (details?.certificateIssuer as string | undefined) ?? (details?.certIssuer as string | undefined) ?? out.certificateDiagnostics?.issuer ?? undefined;
      out.certificateSerialNumber = (details?.certificateSerialNumber as string | undefined) ?? (details?.certSerialNumber as string | undefined) ?? out.certificateDiagnostics?.serialNumber ?? undefined;
      out.certificateFingerprint = out.certificateDiagnostics?.fingerprint ?? undefined;
      out.certificateValidTo = out.certificateDiagnostics?.validTo ?? undefined;
      out.certificateSelectedIndex = out.certificateDiagnostics?.selectedIndex ?? undefined;
      out.certificateHasPrivateKey = out.certificateDiagnostics?.hasPrivateKey ?? undefined;
      out.validateRawResponse = details?.raw ?? details?.rawTextSummary ?? null;
      out.dgiiValidationDiagnosis = (details?.dgiiValidationDiagnosis as string | null | undefined) ?? undefined;
      out.signerContext = (details?.signerContext as Record<string, unknown> | undefined) ?? undefined;
      if (input.diagnosticMatrix) {
        out.diagnosticMatrix = await this.runSeedDiagnosticMatrix(company.id, company.rnc ?? null, environment, requestId).catch(() => []);
      }

      const errorCode = out.errorCode ?? '';
      out.seedOk = !errorCode.includes('SEED_REQUEST');
      out.signOk = !(errorCode.includes('SEED_SIGN') || errorCode.includes('SIGNED_XML_INVALID'));
      out.validateOk = !(errorCode.includes('SEED_VALIDATE') || errorCode.includes('TOKEN_MISSING'));
      out.tokenFound = false;
      return out;
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

function buildValidateUrlCandidates(url: string) {
  const out = new Set<string>();
  const trimmed = url.trim();
  if (trimmed) out.add(trimmed);

  if (trimmed.includes('/autenticacion/api/autenticacion/validarsemilla')) {
    out.add(trimmed.replace('/autenticacion/api/autenticacion/validarsemilla', '/autenticacion/api/semilla/validacioncertificado'));
    out.add(
      trimmed.replace(
        '/autenticacion/api/autenticacion/validarsemilla',
        '/emisorreceptor/fe/autenticacion/api/validacioncertificado',
      ),
    );
  }

  if (trimmed.includes('/autenticacion/api/semilla/validacioncertificado')) {
    out.add(trimmed.replace('/autenticacion/api/semilla/validacioncertificado', '/autenticacion/api/autenticacion/validarsemilla'));
  }

  return [...out];
}

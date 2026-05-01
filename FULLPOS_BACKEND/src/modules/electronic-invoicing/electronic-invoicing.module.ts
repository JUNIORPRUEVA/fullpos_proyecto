import express, { Router } from 'express';
import { z } from 'zod';
import env, { normalizeDgiiEnvironmentAlias } from '../../config/env';
import { prisma } from '../../config/prisma';
import { authGuard } from '../../middlewares/authGuard';
import { overrideKeyGuard } from '../../middlewares/overrideKeyGuard';
import { asyncHandler } from '../../middlewares/asyncHandler';
import { requireRoles } from '../../middlewares/requireRoles';
import { validate } from '../../middlewares/validate';
import { DgiiDirectoryService } from './services/dgii-directory.service';
import { ElectronicInvoicingAuditService } from './services/electronic-invoicing-audit.service';
import { SequenceService } from './services/sequence.service';
import { DgiiXmlBuilderService } from './services/dgii-xml-builder.service';
import { DgiiSignatureService } from './services/dgii-signature.service';
import { DgiiSubmissionService } from './services/dgii-submission.service';
import { DgiiResultService } from './services/dgii-result.service';
import { ElectronicInvoicingMapperService } from './services/electronic-invoicing-mapper.service';
import { DgiiAuthService } from './services/dgii-auth.service';
import { InboundReceptionService } from './services/inbound-reception.service';
import { InboundApprovalService } from './services/inbound-approval.service';
import { ElectronicInvoicingService } from './services/electronic-invoicing.service';
import { DgiiCertificationService } from './services/dgii-certification.service';
import { DgiiCertificationXmlBuilderService } from './services/dgii-certification-xml-builder.service';
import { DgiiCertificationXmlValidationService } from './services/dgii-certification-xml-validation.service';
import { DgiiCertificationRfceXmlBuilderService } from './services/dgii-certification-rfce-xml-builder.service';
import {
  auditTimelineParamsSchema,
  configQuerySchema,
  createElectronicInvoicingAdminController,
  electronicCertificateAccessGuard,
  invoiceIdParamsSchema,
  invoiceIdVariantParamsSchema,
  listQuerySchema,
  uploadElectronicCertificate,
  validateCreateCertificateRequest,
} from './controllers/electronic-invoicing-admin.controller';
import { createElectronicInvoicingDgiiController } from './controllers/electronic-invoicing-dgii.controller';
import {
  certificationBatchParamsSchema,
  certificationCaseParamsSchema,
  certificationCasesQuerySchema,
  certificationAiAuditSchema,
  certificationLocatorSchema,
  certificationResetSchema,
  createElectronicInvoicingCertificationController,
  uploadDgiiCertificationExcel,
  uploadDgiiCertificationSignedCaseXml,
  uploadDgiiSignedSeedXml,
  validateDgiiCertificationSignedCaseXmlUpload,
  validateDgiiCertificationExcelUpload,
  validateDgiiSignedSeedXmlUpload,
} from './controllers/electronic-invoicing-certification.controller';
import {
  createElectronicInvoicingPublicController,
  validateCommercialApprovalRequest,
  validateReceiveEcfRequest,
} from './controllers/electronic-invoicing-public.controller';
import { upsertElectronicConfigDtoSchema } from './dto/config.dto';
import { createCreditNoteDtoSchema } from './dto/credit-note.dto';
import { createEcfDtoSchema } from './dto/create-ecf.dto';
import { queryTrackDtoSchema } from './dto/query-track.dto';
import { createSequenceDtoSchema } from './dto/sequence.dto';
import { sendEcfDtoSchema } from './dto/send-ecf.dto';
import { signerByRncQuerySchema, signerDocumentTypeSchema, upsertSignerByRncSchema } from './dto/signer.dto';
import { requestSeedDtoSchema, validateSeedDtoSchema } from './dto/validate-seed.dto';

const directory = new DgiiDirectoryService();
const audit = new ElectronicInvoicingAuditService(prisma);
const mapper = new ElectronicInvoicingMapperService(prisma);
const signature = new DgiiSignatureService();
const authService = new DgiiAuthService(prisma, mapper, signature, audit, directory);
const sequenceService = new SequenceService(prisma, audit);
const xmlBuilder = new DgiiXmlBuilderService();
const submissionService = new DgiiSubmissionService(directory, authService);
const resultService = new DgiiResultService(directory, authService);
const receptionService = new InboundReceptionService(prisma, authService, mapper, audit);
const approvalService = new InboundApprovalService(prisma, authService, mapper, audit);
const certificationXmlBuilder = new DgiiCertificationXmlBuilderService();
const certificationXmlValidation = new DgiiCertificationXmlValidationService();
const certificationRfceXmlBuilder = new DgiiCertificationRfceXmlBuilderService();
const certificationService = new DgiiCertificationService(
  prisma,
  mapper,
  certificationXmlBuilder,
  signature,
  submissionService,
  resultService,
  directory,
  certificationXmlValidation,
  certificationRfceXmlBuilder,
);
const electronicInvoicingService = new ElectronicInvoicingService(
  prisma,
  mapper,
  sequenceService,
  xmlBuilder,
  signature,
  submissionService,
  resultService,
  audit,
);

const adminController = createElectronicInvoicingAdminController(electronicInvoicingService);
const dgiiController = createElectronicInvoicingDgiiController(electronicInvoicingService);
const certificationController = createElectronicInvoicingCertificationController(certificationService, authService);
const publicController = createElectronicInvoicingPublicController(
  authService,
  receptionService,
  approvalService,
);

const posLocatorsBaseSchema = z.object({
  companyRnc: z.string().trim().min(3).optional(),
  companyCloudId: z.string().trim().min(6).optional(),
});

const sequenceDocumentTypeCodeSchema = z.preprocess(
  (value) => String(value ?? '').trim(),
  z.enum(['31', '32', '34']),
);

const sequenceStatusSchema = z.preprocess(
  (value) => String(value ?? 'ACTIVE').trim().toUpperCase(),
  z.enum(['ACTIVE', 'PAUSED', 'EXHAUSTED', 'INACTIVE']),
);

const optionalSequenceLimitSchema = z.preprocess(
  (value) => value == null || String(value).trim() === '' ? undefined : value,
  z.coerce.number().int().positive().optional(),
);

const requirePosLocators = (data: {
  companyRnc?: string | undefined;
  companyCloudId?: string | undefined;
}) => !!data.companyRnc || !!data.companyCloudId;

const posGenerateByRncSchema = posLocatorsBaseSchema
  .extend({
    saleId: z.coerce.number().int().positive(),
    saleLocalCode: z.string().trim().min(1).optional(),
    documentTypeCode: z.string().trim().min(2),
    branchId: z.coerce.number().int().min(0).optional().default(0),
  })
  .strict()
  .refine(requirePosLocators, {
    message: 'RNC o ID interno requerido',
    path: ['companyRnc'],
  });

const posQueryByRncSchema = posLocatorsBaseSchema
  .extend({
    branchId: z.coerce.number().int().min(0).optional().default(0),
  })
  .strict()
  .refine(requirePosLocators, {
    message: 'RNC o ID interno requerido',
    path: ['companyRnc'],
  });

const posConfigByRncSchema = posLocatorsBaseSchema
  .extend({
    branchId: z.coerce.number().int().min(0).optional().default(0),
  })
  .strict()
  .refine(requirePosLocators, {
    message: 'RNC o ID interno requerido',
    path: ['companyRnc'],
  });

const posSignerByRncQuerySchema = signerByRncQuerySchema;

const posSignerByRncSaveSchema = upsertSignerByRncSchema.extend({
  signerDocumentNumber: z.preprocess(
    (value) => String(value ?? '').trim().replace(/[\s-]+/g, ''),
    z.string().trim().min(1),
  ),
  signerDocumentType: signerDocumentTypeSchema,
});

const posUpsertConfigByRncSchema = upsertElectronicConfigDtoSchema
  .extend({
    companyRnc: z.string().trim().min(3).optional(),
    companyCloudId: z.string().trim().min(6).optional(),
    companyId: z.coerce.number().int().positive().optional(),
    manualToken: z.string().trim().optional(),
    dgiiManualToken: z.string().trim().optional(),
  })
  .strict()
  .refine(requirePosLocators, {
    message: 'RNC o ID interno requerido',
    path: ['companyRnc'],
  });

const posSequenceByRncSchema = z.object({
    companyRnc: z.string().trim().min(3).optional(),
    companyCloudId: z.string().trim().min(6).optional(),
    companyId: z.coerce.number().int().positive().optional(),
    branchId: z.coerce.number().int().min(0).optional().default(0),
  documentTypeCode: sequenceDocumentTypeCodeSchema,
    prefix: z.string().trim().optional(),
    startNumber: z.coerce.number().int().min(1).optional().default(1),
    currentNumber: z.coerce.number().int().min(0).optional().default(0),
    maxNumber: optionalSequenceLimitSchema,
    endNumber: optionalSequenceLimitSchema,
  status: sequenceStatusSchema.optional().default('ACTIVE'),
  })
  .strict()
  .refine(requirePosLocators, {
    message: 'RNC o ID interno requerido',
    path: ['companyRnc'],
  });

const posOutboundListByRncSchema = posLocatorsBaseSchema
  .extend({
    branchId: z.coerce.number().int().min(0).optional(),
    limit: z.coerce.number().int().min(1).max(100).optional().default(18),
  })
  .strict()
  .refine(requirePosLocators, {
    message: 'RNC o ID interno requerido',
    path: ['companyRnc'],
  });

function documentLabel(documentTypeCode: string) {
  switch ((documentTypeCode || '').trim()) {
    case '31':
      return 'Factura crédito fiscal';
    case '32':
      return 'Factura de consumo';
    case '34':
      return 'Nota de crédito';
    default:
      return 'Documento electrónico';
  }
}

function invoiceClientStatus(item: { internalStatus: string; dgiiStatus: string }) {
  if (item.internalStatus === 'ACCEPTED' || item.internalStatus === 'ACCEPTED_CONDITIONAL') return 'ACCEPTED';
  if (item.internalStatus === 'REJECTED' || item.dgiiStatus === 'REJECTED') return 'REJECTED';
  if (item.internalStatus === 'ERROR' || item.dgiiStatus === 'ERROR') return 'SEND_ERROR';
  if (item.internalStatus === 'SUBMITTED' || item.internalStatus === 'SUBMISSION_PENDING' || item.dgiiStatus === 'IN_PROCESS' || item.dgiiStatus === 'RECEIVED') {
    return 'PENDING_DGII';
  }
  return item.internalStatus;
}

function invoiceClientStatusLabel(item: { internalStatus: string; dgiiStatus: string }) {
  const status = invoiceClientStatus(item);
  switch (status) {
    case 'ACCEPTED':
      return 'Aceptada';
    case 'REJECTED':
      return 'Rechazada por DGII';
    case 'SEND_ERROR':
      return 'Error envío';
    case 'PENDING_DGII':
      return 'Pendiente DGII';
    default:
      return status;
  }
}

function publicBaseUrlFromRequest(req: express.Request) {
  return env.PUBLIC_BASE_URL?.trim() || `${req.protocol}://${req.get('host')}`;
}

function sequenceNumberToClient(value: number | bigint) {
  return typeof value === 'bigint' ? Number(value) : value;
}

function sequenceToClient(item: { id: number; companyId: number; branchId: number; documentTypeCode: string; prefix: string; currentNumber: number | bigint; maxNumber?: number | bigint; endNumber?: number | bigint; status: string; updatedAt: Date; createdAt?: Date }) {
  const currentNumber = sequenceNumberToClient(item.currentNumber);
  const maxNumber = sequenceNumberToClient((item.maxNumber ?? item.endNumber) as number | bigint);
  return {
    id: item.id,
    companyId: item.companyId,
    branchId: item.branchId,
    documentTypeCode: item.documentTypeCode,
    prefix: item.prefix,
    startNumber: 1,
    currentNumber,
    endNumber: maxNumber,
    maxNumber,
    status: item.status,
    remaining: Math.max(0, maxNumber - currentNumber),
    updatedAt: item.updatedAt,
  };
}

function sequenceIsReady(sequence: { prefix: string; documentTypeCode: string; currentNumber: number | bigint; maxNumber?: number | bigint; endNumber?: number | bigint; status: string } | undefined) {
  if (!sequence) return false;
  const currentNumber = sequenceNumberToClient(sequence.currentNumber);
  const maxNumber = sequenceNumberToClient((sequence.maxNumber ?? sequence.endNumber) as number | bigint);
  return sequence.status === 'ACTIVE' &&
    sequence.prefix === `E${sequence.documentTypeCode}` &&
    currentNumber >= 0 &&
    maxNumber > currentNumber;
}

async function buildResolvedConfigPayload(company: Awaited<ReturnType<ElectronicInvoicingMapperService['resolveCompanyOrThrow']>>, branchId: number) {
  const companyConfig = (company as any).config as { address?: string | null; phone?: string | null; email?: string | null } | null | undefined;
  const [config, certificate, sequences, signer] = await Promise.all([
    electronicInvoicingService.getConfig(company.id, branchId),
    prisma.electronicCertificate.findFirst({
      where: { companyId: company.id },
      orderBy: { updatedAt: 'desc' },
    }),
    prisma.electronicSequence.findMany({
      where: { companyId: company.id, branchId },
      orderBy: [{ documentTypeCode: 'asc' }],
    }),
    electronicInvoicingService.getSignerConfig(company.id, branchId),
  ]);
  const certificateComparison = await electronicInvoicingService.buildSignerCertificateComparison(company.id, signer);

  if (!config) {
    throw {
      status: 404,
      message: 'La compañía no tiene configuración de facturación electrónica',
      errorCode: 'ELECTRONIC_CONFIG_MISSING',
    };
  }

  const now = Date.now();
  const certificateFound = !!certificate;
  const certificateExpired = !!certificate && certificate.validTo.getTime() < now;
  const certificateReady =
    !!certificate &&
    certificate.status === 'ACTIVE' &&
    certificate.validFrom.getTime() <= now &&
    certificate.validTo.getTime() >= now;
  const sequenceMap = new Map(sequences.map((item) => [item.documentTypeCode, item]));
  const sequence31Ready = sequenceIsReady(sequenceMap.get('31'));
  const sequence32Ready = sequenceIsReady(sequenceMap.get('32'));
  const sequence34Ready = sequenceIsReady(sequenceMap.get('34'));

  const productionDisabled = config.environment === 'production' && !env.DGII_ALLOW_PRODUCTION;
  const dgiiSubmitConfigured = config.environment === 'production'
    ? !!env.DGII_PRODUCTION_SUBMIT_URL?.trim() && !productionDisabled
    : !!env.DGII_PRECERT_SUBMIT_URL?.trim();
  const dgiiTokenConfigured = config.environment === 'production'
    ? !!(env.DGII_PRODUCTION_AUTH_SEED_URL?.trim() && env.DGII_PRODUCTION_AUTH_VALIDATE_URL?.trim()) && !productionDisabled
    : !!(env.DGII_PRECERT_AUTH_SEED_URL?.trim() && env.DGII_PRECERT_AUTH_VALIDATE_URL?.trim());

  const checklist: Record<string, boolean> = {
    companyExists: true,
    companyRnc: !!company.rnc?.trim(),
    companyName: !!company.name?.trim(),
    configActive: config.active,
    outboundEnabled: config.outboundEnabled,
    certificateReady,
    environmentConfigured: !!config.environment,
    dgiiSubmitConfigured,
    dgiiTokenConfigured,
    encryptionKeyConfigured: !!env.FE_MASTER_ENCRYPTION_KEY?.trim(),
    sequence_31: sequence31Ready,
    sequence_32: sequence32Ready,
    sequence_34: sequence34Ready,
    signerConfigured: !!signer.signerFullName.trim(),
    signerDocumentConfigured: !!signer.signerDocumentNumber.trim(),
    signerMatchesCertificateDocument: certificateComparison.signerDocumentMatchesCertificate,
    signerAuthorizedForDgii: signer.signerAuthorizedForDgii,
  };

  const missing: string[] = [];
  if (!checklist.companyRnc) missing.push('COMPANY_RNC_MISSING');
  if (!checklist.companyName) missing.push('COMPANY_NAME_MISSING');
  if (!config.active) missing.push('ELECTRONIC_INVOICING_DISABLED');
  if (!config.outboundEnabled) missing.push('AUTO_SUBMIT_DISABLED');
  if (!certificateFound) missing.push('CERTIFICATE_REQUIRED');
  if (certificateExpired) missing.push('CERTIFICATE_EXPIRED');
  if (certificateFound && !certificateReady && !certificateExpired) missing.push('CERTIFICATE_INVALID');
  if (!sequence31Ready) missing.push('SEQUENCE_31_MISSING');
  if (!sequence32Ready) missing.push('SEQUENCE_32_MISSING');
  if (!sequence34Ready) missing.push('SEQUENCE_34_MISSING');
  if (!dgiiSubmitConfigured) missing.push(productionDisabled ? 'PRODUCTION_DISABLED' : 'DGII_SUBMIT_ENDPOINT_MISSING');
  if (!dgiiTokenConfigured) missing.push(productionDisabled ? 'PRODUCTION_DISABLED' : 'AUTH_ENDPOINTS_MISSING');
  if (!checklist.encryptionKeyConfigured) missing.push('FE_MASTER_ENCRYPTION_KEY_MISSING');
  if (!checklist.signerConfigured) missing.push('SIGNER_REQUIRED');
  if (!checklist.signerDocumentConfigured) missing.push('SIGNER_DOCUMENT_REQUIRED');
  if (checklist.signerDocumentConfigured && !checklist.signerMatchesCertificateDocument) {
    missing.push('SIGNER_CERTIFICATE_DOCUMENT_MISMATCH');
  }
  if (checklist.signerConfigured && checklist.signerDocumentConfigured && checklist.signerMatchesCertificateDocument && !checklist.signerAuthorizedForDgii) {
    missing.push('SIGNER_DGII_AUTHORIZATION_NOT_CONFIRMED');
  }

  const forceNotReadyCodes = new Set([
    'SIGNER_REQUIRED',
    'SIGNER_DOCUMENT_REQUIRED',
    'SIGNER_CERTIFICATE_DOCUMENT_MISMATCH',
  ]);
  const hasForceNotReady = missing.some((code) => forceNotReadyCodes.has(code));
  const baseStatus = missing.length === 0 ? 'READY' : (config.active || certificateFound || sequences.length > 0 ? 'PARTIAL' : 'NOT_READY');
  const readinessStatus = hasForceNotReady
    ? 'NOT_READY'
    : (baseStatus === 'READY' && missing.includes('SIGNER_DGII_AUTHORIZATION_NOT_CONFIRMED') ? 'PARTIAL' : baseStatus);

  return {
    company: {
      companyId: company.id,
      companyCloudId: company.cloudCompanyId,
      companyName: company.name,
      rnc: company.rnc,
      address: companyConfig?.address ?? null,
      city: null,
      phone: companyConfig?.phone ?? null,
      email: companyConfig?.email ?? null,
    },
    config: {
      ...config,
      electronicInvoicingEnabled: config.active,
      autoSubmitToDgii: config.outboundEnabled,
      uiEnvironment: config.environment === 'production' ? 'produccion' : 'pruebas',
    },
    certificate: certificate
      ? {
          alias: certificate.alias,
          status: certificate.status,
          validFrom: certificate.validFrom,
          validTo: certificate.validTo,
          subject: certificate.subject,
          issuer: certificate.issuer,
          serialNumber: certificate.serialNumber,
        }
      : null,
    sequences: sequences.map(sequenceToClient),
    dgii: {
      submitConfigured: dgiiSubmitConfigured,
      tokenConfigured: dgiiTokenConfigured,
      productionAllowed: env.DGII_ALLOW_PRODUCTION,
      environment: config.environment,
    },
    signer,
    certificateComparison,
    readiness: {
      status: readinessStatus,
      missing: [...new Set(missing)],
      messages: missing.length === 0 ? [] : missing.map((code) => `Pendiente: ${code}`),
      checklist,
    },
  };
}

const posSendByRncSchema = posLocatorsBaseSchema
  .extend({
    invoiceId: z.coerce.number().int().positive(),
    force: z.coerce.boolean().optional().default(false),
    dgiiManualToken: z.string().trim().min(1).optional(),
  })
  .strict()
  .refine(requirePosLocators, {
    message: 'RNC o ID interno requerido',
    path: ['companyRnc'],
  });

const posDebugDgiiAuthByRncSchema = posLocatorsBaseSchema
  .extend({
    companyId: z.coerce.number().int().positive().optional(),
    environment: z.preprocess(normalizeDgiiEnvironmentAlias, z.enum(['precertification', 'production'])).optional(),
    forceRefresh: z.coerce.boolean().optional().default(true),
    diagnosticMatrix: z.coerce.boolean().optional(),
  })
  .strict()
  .refine(requirePosLocators, {
    message: 'RNC o ID interno requerido',
    path: ['companyRnc'],
  });

export const posElectronicInvoicingRouter = Router();

setTimeout(() => {
  certificationService.buildDiagnostics()
    .then((diagnostics) => {
      if (diagnostics.pendingMigrationWarning) {
        console.warn(`[electronic-invoicing.certification] ${diagnostics.pendingMigrationWarning}`, {
          databaseHasNewFields: diagnostics.databaseHasNewFields,
          databaseCheckError: diagnostics.databaseCheckError,
        });
      }
    })
    .catch((error) => {
      console.warn('[electronic-invoicing.certification] No se pudo verificar la migracion DGII de certificacion', {
        message: error instanceof Error ? error.message : String(error),
      });
    });
}, 0);

posElectronicInvoicingRouter.post(
  '/certification/import-excel',
  overrideKeyGuard,
  uploadDgiiCertificationExcel,
  validateDgiiCertificationExcelUpload,
  asyncHandler(certificationController.importExcel),
);

posElectronicInvoicingRouter.get(
  '/certification/diagnostics',
  overrideKeyGuard,
  asyncHandler(certificationController.diagnostics),
);

posElectronicInvoicingRouter.get(
  '/certification/dgii-auth/seed',
  overrideKeyGuard,
  validate(certificationLocatorSchema, 'query'),
  asyncHandler(certificationController.downloadManualSeed),
);

posElectronicInvoicingRouter.post(
  '/certification/dgii-auth/signed-seed',
  overrideKeyGuard,
  uploadDgiiSignedSeedXml,
  validateDgiiSignedSeedXmlUpload,
  asyncHandler(certificationController.uploadManualSignedSeed),
);

posElectronicInvoicingRouter.get(
  '/certification/batches',
  overrideKeyGuard,
  validate(certificationLocatorSchema, 'query'),
  asyncHandler(certificationController.listBatches),
);

posElectronicInvoicingRouter.get(
  '/certification/batches/:id',
  overrideKeyGuard,
  validate(certificationBatchParamsSchema, 'params'),
  validate(certificationLocatorSchema, 'query'),
  asyncHandler(certificationController.getBatch),
);

posElectronicInvoicingRouter.get(
  '/certification/batches/:id/summary',
  overrideKeyGuard,
  validate(certificationBatchParamsSchema, 'params'),
  validate(certificationLocatorSchema, 'query'),
  asyncHandler(certificationController.getBatchSummary),
);

posElectronicInvoicingRouter.get(
  '/certification/batches/:id/cases',
  overrideKeyGuard,
  validate(certificationBatchParamsSchema, 'params'),
  validate(certificationCasesQuerySchema, 'query'),
  asyncHandler(certificationController.listCases),
);

posElectronicInvoicingRouter.get(
  '/certification/cases/:id',
  overrideKeyGuard,
  validate(certificationCaseParamsSchema, 'params'),
  validate(certificationLocatorSchema, 'query'),
  asyncHandler(certificationController.getCase),
);

posElectronicInvoicingRouter.post(
  '/certification/cases/:id/generate-xml',
  overrideKeyGuard,
  validate(certificationCaseParamsSchema, 'params'),
  validate(certificationLocatorSchema),
  asyncHandler(certificationController.generateCaseXml),
);

posElectronicInvoicingRouter.get(
  '/certification/cases/:id/xml',
  overrideKeyGuard,
  validate(certificationCaseParamsSchema, 'params'),
  validate(certificationLocatorSchema, 'query'),
  asyncHandler(certificationController.getCaseXml),
);

posElectronicInvoicingRouter.get(
  '/certification/cases/:id/signed-xml',
  overrideKeyGuard,
  validate(certificationCaseParamsSchema, 'params'),
  validate(certificationLocatorSchema, 'query'),
  asyncHandler(certificationController.getCaseSignedXml),
);

posElectronicInvoicingRouter.post(
  '/certification/cases/:id/signed-xml/import',
  overrideKeyGuard,
  validate(certificationCaseParamsSchema, 'params'),
  uploadDgiiCertificationSignedCaseXml,
  validateDgiiCertificationSignedCaseXmlUpload,
  asyncHandler(certificationController.uploadManualSignedCaseXml),
);

posElectronicInvoicingRouter.post(
  '/certification/cases/:id/validate-xml',
  overrideKeyGuard,
  validate(certificationCaseParamsSchema, 'params'),
  validate(certificationLocatorSchema),
  asyncHandler(certificationController.validateCaseXml),
);

posElectronicInvoicingRouter.post(
  '/certification/cases/:id/validate-xsd',
  overrideKeyGuard,
  validate(certificationCaseParamsSchema, 'params'),
  validate(certificationLocatorSchema),
  asyncHandler(certificationController.validateCaseXsd),
);

posElectronicInvoicingRouter.post(
  '/certification/cases/:id/audit',
  overrideKeyGuard,
  validate(certificationCaseParamsSchema, 'params'),
  validate(certificationLocatorSchema),
  asyncHandler(certificationController.auditCase),
);

posElectronicInvoicingRouter.post(
  '/certification/cases/:id/ai-audit',
  overrideKeyGuard,
  validate(certificationCaseParamsSchema, 'params'),
  validate(certificationAiAuditSchema),
  asyncHandler(certificationController.aiAuditCase),
);

posElectronicInvoicingRouter.post(
  '/certification/cases/:id/ai-fix-suggestion',
  overrideKeyGuard,
  validate(certificationCaseParamsSchema, 'params'),
  validate(certificationAiAuditSchema),
  asyncHandler(certificationController.aiFixSuggestionCase),
);

posElectronicInvoicingRouter.post(
  '/certification/cases/:id/apply-certified-fix',
  overrideKeyGuard,
  validate(certificationCaseParamsSchema, 'params'),
  validate(certificationLocatorSchema),
  asyncHandler(certificationController.applyCertifiedFix),
);

posElectronicInvoicingRouter.post(
  '/certification/cases/:id/preflight',
  overrideKeyGuard,
  validate(certificationCaseParamsSchema, 'params'),
  validate(certificationLocatorSchema),
  asyncHandler(certificationController.preflightCase),
);

posElectronicInvoicingRouter.post(
  '/certification/batches/:id/generate-xml',
  overrideKeyGuard,
  validate(certificationBatchParamsSchema, 'params'),
  validate(certificationLocatorSchema),
  asyncHandler(certificationController.generateBatchXml),
);

posElectronicInvoicingRouter.post(
  '/certification/batches/:id/audit',
  overrideKeyGuard,
  validate(certificationBatchParamsSchema, 'params'),
  validate(certificationLocatorSchema),
  asyncHandler(certificationController.auditBatch),
);

posElectronicInvoicingRouter.post(
  '/certification/batches/:id/ai-audit',
  overrideKeyGuard,
  validate(certificationBatchParamsSchema, 'params'),
  validate(certificationAiAuditSchema),
  asyncHandler(certificationController.aiAuditBatch),
);

posElectronicInvoicingRouter.post(
  '/certification/batches/:id/ai-fix-suggestion',
  overrideKeyGuard,
  validate(certificationBatchParamsSchema, 'params'),
  validate(certificationAiAuditSchema),
  asyncHandler(certificationController.aiFixSuggestionBatch),
);

posElectronicInvoicingRouter.post(
  '/certification/batches/:id/preflight',
  overrideKeyGuard,
  validate(certificationBatchParamsSchema, 'params'),
  validate(certificationLocatorSchema),
  asyncHandler(certificationController.preflightBatch),
);

posElectronicInvoicingRouter.post(
  '/certification/cases/:id/sign',
  overrideKeyGuard,
  validate(certificationCaseParamsSchema, 'params'),
  validate(certificationLocatorSchema),
  asyncHandler(certificationController.signCase),
);

posElectronicInvoicingRouter.post(
  '/certification/batches/:id/sign',
  overrideKeyGuard,
  validate(certificationBatchParamsSchema, 'params'),
  validate(certificationLocatorSchema),
  asyncHandler(certificationController.signBatch),
);

posElectronicInvoicingRouter.post(
  '/certification/cases/:id/send',
  overrideKeyGuard,
  validate(certificationCaseParamsSchema, 'params'),
  validate(certificationLocatorSchema),
  asyncHandler(certificationController.sendCase),
);

posElectronicInvoicingRouter.post(
  '/certification/batches/:id/send',
  overrideKeyGuard,
  validate(certificationBatchParamsSchema, 'params'),
  validate(certificationLocatorSchema),
  asyncHandler(certificationController.sendBatch),
);

posElectronicInvoicingRouter.post(
  '/certification/batches/:id/reprocess-and-send',
  overrideKeyGuard,
  validate(certificationBatchParamsSchema, 'params'),
  validate(certificationLocatorSchema),
  asyncHandler(certificationController.reprocessAndSendBatch),
);

posElectronicInvoicingRouter.get(
  '/certification/cases/:id/result',
  overrideKeyGuard,
  validate(certificationCaseParamsSchema, 'params'),
  validate(certificationLocatorSchema, 'query'),
  asyncHandler(certificationController.queryCaseResult),
);

posElectronicInvoicingRouter.post(
  '/certification/batches/:id/query-results',
  overrideKeyGuard,
  validate(certificationBatchParamsSchema, 'params'),
  validate(certificationLocatorSchema),
  asyncHandler(certificationController.queryBatchResults),
);

posElectronicInvoicingRouter.post(
  '/certification/cases/:id/reset',
  overrideKeyGuard,
  validate(certificationCaseParamsSchema, 'params'),
  validate(certificationResetSchema),
  asyncHandler(certificationController.resetCase),
);

posElectronicInvoicingRouter.post(
  '/certification/batches/:id/reset',
  overrideKeyGuard,
  validate(certificationBatchParamsSchema, 'params'),
  validate(certificationResetSchema),
  asyncHandler(certificationController.resetBatch),
);

posElectronicInvoicingRouter.delete(
  '/certification/batches/:id',
  overrideKeyGuard,
  validate(certificationBatchParamsSchema, 'params'),
  validate(certificationLocatorSchema, 'query'),
  asyncHandler(certificationController.deleteBatch),
);

type OutboundStage = 'generate' | 'resolve_company' | 'sale_lookup' | 'map_sale' | 'sequence' | 'xml' | 'sign' | 'token' | 'submit' | 'result' | 'save';

function outboundStageFromError(error: any, fallback: OutboundStage): OutboundStage {
  const code = String(error?.errorCode ?? error?.code ?? '').toUpperCase();
  const message = String(error?.message ?? '').toLowerCase();
  if (code.includes('COMPANY')) return 'resolve_company';
  if (code === 'SALE_NOT_FOUND' || code === 'SALE_NOT_SYNCED_TO_BACKEND' || code.includes('SALE_SYNC')) return 'sale_lookup';
  if (code.includes('SALE_') || code.includes('BUYER') || code.includes('CUSTOMER') || code.includes('DOCUMENT_TYPE')) return 'map_sale';
  if (code.includes('SEQUENCE')) return 'sequence';
  if (code.includes('XML') || message.includes('xml')) return fallback === 'sign' ? 'sign' : 'xml';
  if (code.includes('CERTIFICATE') || code.includes('SIGN')) return 'sign';
  if (code.includes('TOKEN') || code.includes('AUTH') || code.includes('SEED')) return 'token';
  if (code.includes('SUBMIT') || code.includes('SEND') || code.includes('DGII')) return 'submit';
  return fallback;
}

function outboundErrorCode(error: any, stage: OutboundStage) {
  const existing = String(error?.errorCode ?? error?.code ?? '').trim();
  if (existing) return existing;
  switch (stage) {
    case 'resolve_company': return 'COMPANY_NOT_FOUND';
    case 'sale_lookup': return 'SALE_NOT_SYNCED_TO_BACKEND';
    case 'sequence': return 'SEQUENCE_NOT_CONFIGURED';
    case 'xml': return 'XML_GENERATION_FAILED';
    case 'sign': return 'XML_SIGN_FAILED';
    case 'token': return 'DGII_AUTH_NOT_READY';
    case 'submit': return 'DGII_SUBMIT_FAILED';
    default: return 'ELECTRONIC_OUTBOUND_RUNTIME_ERROR';
  }
}

function outboundErrorMessage(error: any, code: string, stage: OutboundStage) {
  const message = String(error?.message ?? '').trim();
  if (message && message !== 'Unexpected error') return message;
  switch (code) {
    case 'SALE_NOT_FOUND':
    case 'SALE_NOT_SYNCED_TO_BACKEND':
      return 'La venta todavía no se ha sincronizado con la nube antes de generar el e-CF.';
    case 'SEQUENCE_NOT_FOUND':
    case 'SEQUENCE_NOT_CONFIGURED':
      return 'La secuencia electrónica no está configurada para este tipo de comprobante.';
    case 'SEQUENCE_EXHAUSTED':
      return 'La secuencia electrónica está agotada.';
    case 'CERTIFICATE_NOT_FOUND':
      return 'Falta certificado digital válido.';
    case 'CERTIFICATE_EXPIRED':
      return 'El certificado digital está vencido.';
    case 'DGII_AUTH_NOT_READY':
    case 'DGII_TOKEN_GENERATION_FAILED':
      return 'DGII no pudo generar el token.';
    case 'XML_GENERATION_FAILED':
      return 'El XML no pudo generarse por datos incompletos.';
    case 'XML_SIGN_FAILED':
      return 'El XML no pudo firmarse con el certificado activo.';
    case 'DGII_SUBMIT_FAILED':
      return 'DGII no pudo recibir el e-CF.';
    default:
      return `No se pudo completar la etapa ${stage} del e-CF.`;
  }
}

function safeOutboundErrorDetails(input: {
  requestId?: string;
  companyId?: number | null;
  companyRnc?: string | null;
  companyCloudId?: string | null;
  saleId?: number | null;
  saleLocalCode?: string | null;
  invoiceId?: number | null;
  documentTypeCode?: string | null;
  branchId?: number | null;
  extra?: Record<string, unknown> | null;
}) {
  return {
    requestId: input.requestId ?? null,
    companyId: input.companyId ?? null,
    companyRnc: input.companyRnc ?? null,
    companyCloudId: input.companyCloudId ?? null,
    saleId: input.saleId ?? null,
    saleLocalCode: input.saleLocalCode ?? null,
    invoiceId: input.invoiceId ?? null,
    documentTypeCode: input.documentTypeCode ?? null,
    branchId: input.branchId ?? null,
    ...(input.extra ?? {}),
  };
}

function sendOutboundError(res: express.Response, error: any, fallbackStage: OutboundStage, details: ReturnType<typeof safeOutboundErrorDetails>) {
  const stage = outboundStageFromError(error, fallbackStage);
  const errorCode = outboundErrorCode(error, stage);
  const status = typeof error?.status === 'number' ? error.status : 500;
  const message = outboundErrorMessage(error, errorCode, stage);
  console.error('[electronic-invoicing.pos] outbound.structured_error', {
    ...details,
    stage,
    status,
    errorCode,
    message,
    originalMessage: error?.message ?? null,
    prismaCode: error?.code ?? null,
    stack: error?.stack ? String(error.stack).split('\n').slice(0, 5).join('\n') : null,
  });
  return res.status(status).json({
    ok: false,
    errorCode,
    message,
    stage,
    details: {
      ...details,
      originalErrorCode: error?.errorCode ?? error?.code ?? null,
    },
  });
}

type SafeDiagnosticError = { code: string; message: string; action: string };

function electronicEnvDiagnostics(environment: 'precertification' | 'production') {
  const variableNames = environment === 'production'
    ? [
        'DGII_ALLOW_PRODUCTION',
        'DGII_PRODUCTION_AUTH_SEED_URL',
        'DGII_PRODUCTION_AUTH_VALIDATE_URL',
        'DGII_PRODUCTION_SUBMIT_URL',
        'DGII_PRODUCTION_RESULT_URL_TEMPLATE',
      ]
    : [
        'FE_MASTER_ENCRYPTION_KEY',
        'DGII_PRECERT_AUTH_SEED_URL',
        'DGII_PRECERT_AUTH_VALIDATE_URL',
        'DGII_PRECERT_SUBMIT_URL',
        'DGII_PRECERT_RESULT_URL_TEMPLATE',
      ];

  const configured: Record<string, boolean> = {
    FE_MASTER_ENCRYPTION_KEY: !!env.FE_MASTER_ENCRYPTION_KEY?.trim(),
    DGII_ALLOW_PRODUCTION: env.DGII_ALLOW_PRODUCTION === true,
    DGII_PRECERT_AUTH_SEED_URL: !!env.DGII_PRECERT_AUTH_SEED_URL?.trim(),
    DGII_PRECERT_AUTH_VALIDATE_URL: !!env.DGII_PRECERT_AUTH_VALIDATE_URL?.trim(),
    DGII_PRECERT_SUBMIT_URL: !!env.DGII_PRECERT_SUBMIT_URL?.trim(),
    DGII_PRECERT_RESULT_URL_TEMPLATE: !!env.DGII_PRECERT_RESULT_URL_TEMPLATE?.trim(),
    DGII_PRODUCTION_AUTH_SEED_URL: !!env.DGII_PRODUCTION_AUTH_SEED_URL?.trim(),
    DGII_PRODUCTION_AUTH_VALIDATE_URL: !!env.DGII_PRODUCTION_AUTH_VALIDATE_URL?.trim(),
    DGII_PRODUCTION_SUBMIT_URL: !!env.DGII_PRODUCTION_SUBMIT_URL?.trim(),
    DGII_PRODUCTION_RESULT_URL_TEMPLATE: !!env.DGII_PRODUCTION_RESULT_URL_TEMPLATE?.trim(),
  };

  const missing = variableNames.filter((name) => !configured[name]);
  return {
    environment,
    configured: Object.fromEntries(variableNames.map((name) => [name, configured[name] === true])),
    missing,
    seedUrlConfigured: environment === 'production' ? configured.DGII_PRODUCTION_AUTH_SEED_URL : configured.DGII_PRECERT_AUTH_SEED_URL,
    validateUrlConfigured: environment === 'production' ? configured.DGII_PRODUCTION_AUTH_VALIDATE_URL : configured.DGII_PRECERT_AUTH_VALIDATE_URL,
    submitUrlConfigured: environment === 'production' ? configured.DGII_PRODUCTION_SUBMIT_URL : configured.DGII_PRECERT_SUBMIT_URL,
    resultUrlConfigured: environment === 'production' ? configured.DGII_PRODUCTION_RESULT_URL_TEMPLATE : configured.DGII_PRECERT_RESULT_URL_TEMPLATE,
    encryptionKeyConfigured: configured.FE_MASTER_ENCRYPTION_KEY,
    productionBlocked: environment === 'production' && !env.DGII_ALLOW_PRODUCTION,
  };
}

function diagnosticAction(code: string) {
  if (code.includes('OVERRIDE_KEY')) return 'Revise la llave cloud/API key configurada en Ajustes y el OVERRIDE_API_KEY del backend.';
  if (code.includes('COMPANY')) return 'Revise RNC, cloudCompanyId y la empresa activa sincronizada.';
  if (code.includes('CERTIFICATE')) return 'Suba un certificado .p12/.pfx válido y confirme FE_MASTER_ENCRYPTION_KEY estable.';
  if (code.includes('AUTH') || code.includes('SEED') || code.includes('TOKEN')) return 'Revise URLs DGII de autenticación, certificado y respuesta DGII segura.';
  if (code.includes('PRODUCTION')) return 'Use certificación/precertificación o habilite producción solo cuando esté certificado.';
  if (code.includes('SUBMIT') || code.includes('RESULT')) return 'Configure URLs DGII de recepción y consulta de estado.';
  return 'Revise el detalle técnico y vuelva a probar.';
}

function resolvePosCompany(
  companyRnc?: string | null,
  companyCloudId?: string | null,
  requestId?: string,
  source?: string,
) {
  return mapper.resolveCompanyOrThrow(companyRnc ?? null, companyCloudId ?? null, {
    preferCloudOnConflict: true,
    requestId,
    source,
  });
}

async function buildSafeDgiiAuthDiagnostic(input: {
  companyRnc?: string;
  companyCloudId?: string;
  requestedCompanyId?: number;
  environment?: 'precertification' | 'production';
  forceRefresh?: boolean;
  diagnosticMatrix?: boolean;
  requestId?: string;
}) {
  const errors: SafeDiagnosticError[] = [];
  let stage: 'resolve_company' | 'config' | 'certificate' | 'seed' | 'sign' | 'validate' | 'token' = 'resolve_company';
  let company: Awaited<ReturnType<ElectronicInvoicingMapperService['resolveCompanyOrThrow']>> | null = null;

  try {
    company = await resolvePosCompany(input.companyRnc ?? null, input.companyCloudId ?? null, input.requestId, 'debug_dgii_auth');
  } catch (error) {
    const code = (error as any)?.errorCode ?? 'COMPANY_RESOLVE_FAILED';
    errors.push({ code, message: (error as any)?.message ?? 'No se pudo resolver la empresa', action: diagnosticAction(code) });
    return {
      ok: false,
      buildMarker: 'dgii-auth-debug-v2',
      stage,
      requestId: input.requestId,
      companyRequested: {
        companyId: input.requestedCompanyId ?? null,
        rnc: input.companyRnc ?? null,
        cloudCompanyId: input.companyCloudId ?? null,
      },
      companyResolved: null,
      config: null,
      certificate: { found: false, status: null, alias: null, validFrom: null, validTo: null, expired: false, ready: false },
      dgiiAuth: { seedUrlConfigured: false, validateUrlConfigured: false, submitUrlConfigured: false, resultUrlConfigured: false, seedOk: false, signOk: false, validateOk: false, tokenFound: false },
      env: null,
      errors,
    };
  }

  stage = 'config';
  const config = await electronicInvoicingService.getConfig(company.id, 0);
  const signer = await electronicInvoicingService.getSignerConfig(company.id, 0);
  const certificateComparison = await electronicInvoicingService.buildSignerCertificateComparison(company.id, signer);
  const environment = (input.environment ??
    normalizeDgiiEnvironmentAlias(config?.environment ?? env.DGII_DEFAULT_ENVIRONMENT)) as 'precertification' | 'production';
  const envCheck = electronicEnvDiagnostics(environment);
  if (envCheck.missing.length > 0) {
    errors.push({
      code: envCheck.productionBlocked ? 'DGII_PRODUCTION_DISABLED' : 'DGII_ENV_MISSING',
      message: `Variables faltantes: ${envCheck.missing.join(', ')}`,
      action: envCheck.productionBlocked ? diagnosticAction('PRODUCTION_DISABLED') : 'Configure las variables DGII/FE indicadas en el backend y reinicie el servicio.',
    });
  }

  stage = 'certificate';
  const certificate = await prisma.electronicCertificate.findFirst({
    where: { companyId: company.id },
    orderBy: { updatedAt: 'desc' },
  });
  const now = Date.now();
  const certificateExpired = !!certificate && certificate.validTo.getTime() < now;
  const certificateReady = !!certificate && certificate.status === 'ACTIVE' && certificate.validFrom.getTime() <= now && certificate.validTo.getTime() >= now;
  if (!certificate) {
    errors.push({ code: 'CERTIFICATE_NOT_FOUND', message: 'No hay certificado digital activo para esta empresa.', action: diagnosticAction('CERTIFICATE_NOT_FOUND') });
  } else if (!certificateReady) {
    errors.push({ code: certificateExpired ? 'CERTIFICATE_EXPIRED' : 'CERTIFICATE_NOT_READY', message: certificateExpired ? 'El certificado digital está vencido.' : 'El certificado digital no está activo o válido por fecha.', action: diagnosticAction('CERTIFICATE_NOT_READY') });
  }

  let authDebug: any = null;
  if (envCheck.seedUrlConfigured && envCheck.validateUrlConfigured && envCheck.encryptionKeyConfigured && !envCheck.productionBlocked && certificateReady) {
    stage = 'seed';
    authDebug = await authService.debugAuthenticateByLocators(
      {
        companyRnc: input.companyRnc,
        companyCloudId: input.companyCloudId,
        environment,
        forceRefresh: input.forceRefresh ?? true,
        diagnosticMatrix: input.diagnosticMatrix,
      },
      input.requestId,
    );
    if (authDebug?.signOk) stage = 'validate';
    if (authDebug?.validateOk) stage = 'token';
    if (authDebug?.errorCode) {
      errors.push({ code: authDebug.errorCode, message: authDebug.errorMessage ?? 'DGII no pudo generar o validar el token.', action: diagnosticAction(authDebug.errorCode) });
    }
  } else if (!certificateReady) {
    stage = 'certificate';
  }

  const seedOk = authDebug?.seedOk === true;
  const signOk = authDebug?.signOk === true;
  const validateOk = authDebug?.validateOk === true;
  const tokenFound = authDebug?.tokenFound === true;
  const ok = errors.length === 0 && seedOk && signOk && validateOk && tokenFound;

  return {
    ok,
    buildMarker: 'dgii-auth-debug-v7-dedicated-seed-signer-text-xml',
    stage,
    requestId: input.requestId,
    originalSeedRoot: authDebug?.originalSeedRoot ?? null,
    signedXmlRoot: authDebug?.signedXmlRoot ?? authDebug?.rootElement ?? null,
    signedXmlHasSignature: authDebug?.signedXmlHasSignature ?? authDebug?.hasSignature ?? null,
    signedXmlHasBom: authDebug?.signedXmlHasBom ?? null,
    signedXmlHasDeclaration: authDebug?.signedXmlHasDeclaration ?? null,
    signedXmlHasIdAttributeOnRoot: authDebug?.signedXmlHasIdAttributeOnRoot ?? null,
    signedXmlHasRootIdAttribute: authDebug?.signedXmlHasRootIdAttribute ?? authDebug?.signedXmlHasIdAttributeOnRoot ?? null,
    signedXmlRootId: authDebug?.signedXmlRootId ?? null,
    signatureReferenceUri: authDebug?.signatureReferenceUri ?? null,
    signatureReferenceUriBeforeSanitize: authDebug?.signatureReferenceUriBeforeSanitize ?? null,
    signatureReferenceUriAfterSanitize: authDebug?.signatureReferenceUriAfterSanitize ?? null,
    rootIdBeforeSanitize: authDebug?.rootIdBeforeSanitize ?? null,
    rootIdAfterSanitize: authDebug?.rootIdAfterSanitize ?? null,
    finalXmlSize: authDebug?.finalXmlSize ?? authDebug?.signedXmlSize ?? null,
    finalXmlStartsWith: authDebug?.finalXmlStartsWith ?? null,
    finalXmlRootAfterSanitize: authDebug?.finalXmlRootAfterSanitize ?? null,
    xmlDeclarationBeforeSanitize: authDebug?.xmlDeclarationBeforeSanitize ?? null,
    xmlDeclarationAfterSanitize: authDebug?.xmlDeclarationAfterSanitize ?? null,
    canonicalizationAlgorithm: authDebug?.canonicalizationAlgorithm ?? null,
    signatureAlgorithm: authDebug?.signatureAlgorithm ?? null,
    digestAlgorithm: authDebug?.digestAlgorithm ?? null,
    validatePayloadMode: authDebug?.validatePayloadMode ?? authDebug?.payloadMode ?? null,
    validateFieldName: authDebug?.validateFieldName ?? null,
    validateContentType: authDebug?.validateContentType ?? null,
    selfVerifyValid: authDebug?.selfVerifyValid ?? authDebug?.certificateDiagnostics?.localSignatureVerify ?? null,
    certificateSubject: authDebug?.certificateSubject ?? authDebug?.certificateDiagnostics?.subject ?? null,
    certificateIssuer: authDebug?.certificateIssuer ?? authDebug?.certificateDiagnostics?.issuer ?? null,
    certificateSerialNumber: authDebug?.certificateSerialNumber ?? authDebug?.certificateDiagnostics?.serialNumber ?? null,
    certificateFingerprint: authDebug?.certificateFingerprint ?? authDebug?.certificateDiagnostics?.fingerprint ?? null,
    certificateValidTo: authDebug?.certificateValidTo ?? authDebug?.certificateDiagnostics?.validTo ?? null,
    certificateSelectedIndex: authDebug?.certificateSelectedIndex ?? authDebug?.certificateDiagnostics?.selectedIndex ?? null,
    certificateHasPrivateKey: authDebug?.certificateHasPrivateKey ?? authDebug?.certificateDiagnostics?.hasPrivateKey ?? null,
    companyRequested: {
      companyId: input.requestedCompanyId ?? null,
      rnc: input.companyRnc ?? null,
      cloudCompanyId: input.companyCloudId ?? null,
    },
    companyResolved: {
      id: company.id,
      name: company.name,
      rnc: company.rnc,
      cloudCompanyId: company.cloudCompanyId,
    },
    config: {
      active: config?.active ?? false,
      outboundEnabled: config?.outboundEnabled ?? false,
      environment,
      productionBlocked: envCheck.productionBlocked,
    },
    signer,
    certificateComparison,
    certificate: {
      found: !!certificate,
      status: certificate?.status ?? null,
      alias: certificate?.alias ?? null,
      validFrom: certificate?.validFrom ?? null,
      validTo: certificate?.validTo ?? null,
      expired: certificateExpired,
      ready: certificateReady,
    },
    dgiiAuth: {
      seedUrlConfigured: envCheck.seedUrlConfigured,
      validateUrlConfigured: envCheck.validateUrlConfigured,
      submitUrlConfigured: envCheck.submitUrlConfigured,
      resultUrlConfigured: envCheck.resultUrlConfigured,
      seedOk,
      signOk,
      validateOk,
      tokenFound,
      httpStatus: authDebug?.httpStatus ?? null,
      dgiiHttpStatus: authDebug?.dgiiHttpStatus ?? authDebug?.httpStatus ?? null,
      dgiiSafeResponse: authDebug?.dgiiSafeResponse ?? null,
      payloadMode: authDebug?.payloadMode ?? authDebug?.validatePayloadMode ?? null,
      rootElement: authDebug?.rootElement ?? authDebug?.signedXmlRoot ?? null,
      hasSignature: authDebug?.hasSignature ?? authDebug?.signedXmlHasSignature ?? null,
      originalSeedRoot: authDebug?.originalSeedRoot ?? null,
      signedXmlRoot: authDebug?.signedXmlRoot ?? authDebug?.rootElement ?? null,
      signedXmlHasSignature: authDebug?.signedXmlHasSignature ?? authDebug?.hasSignature ?? null,
      signedXmlHasBom: authDebug?.signedXmlHasBom ?? null,
      signedXmlHasDeclaration: authDebug?.signedXmlHasDeclaration ?? null,
      signedXmlHasIdAttributeOnRoot: authDebug?.signedXmlHasIdAttributeOnRoot ?? null,
      signedXmlHasRootIdAttribute: authDebug?.signedXmlHasRootIdAttribute ?? authDebug?.signedXmlHasIdAttributeOnRoot ?? null,
      signedXmlRootId: authDebug?.signedXmlRootId ?? null,
      signatureReferenceUri: authDebug?.signatureReferenceUri ?? null,
      signatureReferenceUriBeforeSanitize: authDebug?.signatureReferenceUriBeforeSanitize ?? null,
      signatureReferenceUriAfterSanitize: authDebug?.signatureReferenceUriAfterSanitize ?? null,
      rootIdBeforeSanitize: authDebug?.rootIdBeforeSanitize ?? null,
      rootIdAfterSanitize: authDebug?.rootIdAfterSanitize ?? null,
      signedXmlSizeBeforeSanitize: authDebug?.signedXmlSizeBeforeSanitize ?? null,
      finalXmlSize: authDebug?.finalXmlSize ?? authDebug?.signedXmlSize ?? null,
      finalXmlStartsWith: authDebug?.finalXmlStartsWith ?? null,
      finalXmlRootAfterSanitize: authDebug?.finalXmlRootAfterSanitize ?? null,
      xmlDeclarationBeforeSanitize: authDebug?.xmlDeclarationBeforeSanitize ?? null,
      xmlDeclarationAfterSanitize: authDebug?.xmlDeclarationAfterSanitize ?? null,
      canonicalizationAlgorithm: authDebug?.canonicalizationAlgorithm ?? null,
      signatureAlgorithm: authDebug?.signatureAlgorithm ?? null,
      digestAlgorithm: authDebug?.digestAlgorithm ?? null,
      validatePayloadMode: authDebug?.validatePayloadMode ?? authDebug?.payloadMode ?? null,
      validateFieldName: authDebug?.validateFieldName ?? null,
      validateContentType: authDebug?.validateContentType ?? null,
      selfVerifyValid: authDebug?.selfVerifyValid ?? authDebug?.certificateDiagnostics?.localSignatureVerify ?? null,
      certificateSubject: authDebug?.certificateSubject ?? authDebug?.certificateDiagnostics?.subject ?? null,
      certificateIssuer: authDebug?.certificateIssuer ?? authDebug?.certificateDiagnostics?.issuer ?? null,
      certificateSerialNumber: authDebug?.certificateSerialNumber ?? authDebug?.certificateDiagnostics?.serialNumber ?? null,
      certificateFingerprint: authDebug?.certificateFingerprint ?? authDebug?.certificateDiagnostics?.fingerprint ?? null,
      certificateValidTo: authDebug?.certificateValidTo ?? authDebug?.certificateDiagnostics?.validTo ?? null,
      certificateSelectedIndex: authDebug?.certificateSelectedIndex ?? authDebug?.certificateDiagnostics?.selectedIndex ?? null,
      certificateHasPrivateKey: authDebug?.certificateHasPrivateKey ?? authDebug?.certificateDiagnostics?.hasPrivateKey ?? null,
      safeErrorCode: authDebug?.errorCode ?? null,
      safeErrorMessage: authDebug?.errorMessage ?? null,
      signerContext: authDebug?.signerContext ?? null,
      certificateDiagnostics: authDebug?.certificateDiagnostics ?? null,
      diagnosticMatrix: authDebug?.diagnosticMatrix ?? null,
    },
    env: {
      configured: envCheck.configured,
      missing: envCheck.missing,
    },
    errors,
  };
}

// Rutas para FULLPOS (POS) — no tiene JWT. Se protege con overrideKeyGuard.
posElectronicInvoicingRouter.get(
  '/config/by-rnc',
  overrideKeyGuard,
  validate(posConfigByRncSchema, 'query'),
  asyncHandler(async (req, res) => {
    const query = req.query as unknown as typeof posConfigByRncSchema._output;
    const company = await resolvePosCompany(query.companyRnc ?? null, query.companyCloudId ?? null, req.requestId, 'config_get_by_rnc');
    const branchId = query.branchId;
    console.info('[electronic-invoicing.pos] config.by-rnc.resolve', {
      requestId: req.requestId,
      requestedCompanyId: null,
      companyRnc: query.companyRnc ?? null,
      companyCloudId: query.companyCloudId ?? null,
      resolvedCompanyId: company.id,
      branchId,
    });

    if (!(await electronicInvoicingService.getConfig(company.id, branchId))) {
      await electronicInvoicingService.upsertConfig(company.id, {
        branchId,
        authEnabled: true,
        authPath: '/fe/autenticacion/api/semilla',
        receptionPath: '/fe/recepcion/api/ecf',
        approvalPath: '/fe/aprobacioncomercial/api/ecf',
        publicBaseUrl: publicBaseUrlFromRequest(req),
        active: false,
        outboundEnabled: false,
        environment: env.DGII_DEFAULT_ENVIRONMENT,
        tokenTtlSeconds: 300,
      }, 'fullpos_pos', req.requestId);
    }

    res.json(await buildResolvedConfigPayload(company, branchId));
  }),
);

posElectronicInvoicingRouter.put(
  '/config/by-rnc',
  overrideKeyGuard,
  validate(posUpsertConfigByRncSchema),
  asyncHandler(async (req, res) => {
    const dto = req.body as typeof posUpsertConfigByRncSchema._output;
    if (dto.environment === 'production' && !env.DGII_ALLOW_PRODUCTION) {
      return res.status(409).json({
        message: 'Producción DGII está deshabilitada en este backend',
        errorCode: 'PRODUCTION_DISABLED',
      });
    }

    const company = await resolvePosCompany(dto.companyRnc ?? null, dto.companyCloudId ?? null, req.requestId, 'config_put_by_rnc');
    console.info('[electronic-invoicing.pos] config.by-rnc.save.resolve', {
      requestId: req.requestId,
      requestedCompanyId: dto.companyId ?? null,
      companyRnc: dto.companyRnc ?? null,
      companyCloudId: dto.companyCloudId ?? null,
      resolvedCompanyId: company.id,
      branchId: dto.branchId,
      active: dto.active,
      outboundEnabled: dto.outboundEnabled,
      environment: dto.environment,
    });

    await electronicInvoicingService.upsertConfig(company.id, {
      branchId: dto.branchId,
      authEnabled: dto.authEnabled,
      authPath: dto.authPath,
      receptionPath: dto.receptionPath,
      approvalPath: dto.approvalPath,
      publicBaseUrl: dto.publicBaseUrl || publicBaseUrlFromRequest(req),
      active: dto.active,
      outboundEnabled: dto.outboundEnabled,
      environment: dto.environment,
      tokenTtlSeconds: dto.tokenTtlSeconds,
    }, 'fullpos_pos', req.requestId);

    res.json(await buildResolvedConfigPayload(company, dto.branchId));
  }),
);

posElectronicInvoicingRouter.get(
  '/signer/by-rnc',
  overrideKeyGuard,
  validate(posSignerByRncQuerySchema, 'query'),
  asyncHandler(async (req, res) => {
    const query = req.query as unknown as typeof posSignerByRncQuerySchema._output;
    const company = await resolvePosCompany(query.companyRnc ?? null, query.companyCloudId ?? null, req.requestId, 'signer_get_by_rnc');
    const signer = await electronicInvoicingService.getSignerConfig(company.id, 0);
    const certificateComparison = await electronicInvoicingService.buildSignerCertificateComparison(company.id, signer);

    res.json({
      ok: true,
      company: {
        id: company.id,
        name: company.name,
        rnc: company.rnc,
        cloudCompanyId: company.cloudCompanyId,
      },
      signer,
      certificateComparison,
    });
  }),
);

posElectronicInvoicingRouter.put(
  '/signer/by-rnc',
  overrideKeyGuard,
  validate(posSignerByRncSaveSchema),
  asyncHandler(async (req, res) => {
    const body = req.body as typeof posSignerByRncSaveSchema._output;
    const company = await resolvePosCompany(body.companyRnc ?? null, body.companyCloudId ?? null, req.requestId, 'signer_put_by_rnc');
    const signer = await electronicInvoicingService.upsertSignerConfig(company.id, body, 'fullpos_pos', req.requestId);
    const certificateComparison = await electronicInvoicingService.buildSignerCertificateComparison(company.id, signer);

    res.json({
      ok: true,
      company: {
        id: company.id,
        name: company.name,
        rnc: company.rnc,
        cloudCompanyId: company.cloudCompanyId,
      },
      signer,
      certificateComparison,
    });
  }),
);

posElectronicInvoicingRouter.post(
  '/sequences',
  overrideKeyGuard,
  validate(posSequenceByRncSchema),
  asyncHandler(async (req, res) => {
    const dto = req.body as typeof posSequenceByRncSchema._output;
    try {
      const company = await resolvePosCompany(dto.companyRnc ?? null, dto.companyCloudId ?? null, req.requestId, 'sequence_save_by_rnc');
      console.info('[electronic-invoicing.pos] sequence.save.resolve', {
        requestId: req.requestId,
        requestedCompanyId: dto.companyId ?? null,
        companyRnc: dto.companyRnc ?? null,
        companyCloudId: dto.companyCloudId ?? null,
        resolvedCompanyId: company.id,
        branchId: dto.branchId,
        documentTypeCode: dto.documentTypeCode,
        prefix: dto.prefix ?? null,
        startNumber: dto.startNumber,
        currentNumber: dto.currentNumber,
        endNumber: dto.endNumber ?? null,
        maxNumber: dto.maxNumber ?? null,
        resolvedEndNumber: dto.endNumber ?? dto.maxNumber ?? null,
        status: dto.status,
      });
      const sequence = await electronicInvoicingService.upsertSequence(company.id, dto, 'fullpos_pos', req.requestId);
      res.status(201).json({ ok: true, sequence });
    } catch (error) {
      const status = typeof (error as any)?.status === 'number' ? (error as any).status : 500;
      res.status(status).json({
        ok: false,
        errorCode: (error as any)?.errorCode ?? 'SEQUENCE_SAVE_FAILED',
        message: (error as any)?.message ?? 'No se pudo guardar la secuencia electrónica',
        details: (error as any)?.details ?? {},
      });
    }
  }),
);

posElectronicInvoicingRouter.post(
  '/sequences/auto-configure/by-rnc',
  overrideKeyGuard,
  validate(posConfigByRncSchema),
  asyncHandler(async (req, res) => {
    const dto = req.body as unknown as typeof posConfigByRncSchema._output;
    const company = await resolvePosCompany(dto.companyRnc ?? null, dto.companyCloudId ?? null, req.requestId, 'sequence_auto_configure_by_rnc');
    const branchId = dto.branchId;
    const created = [];
    for (const documentTypeCode of ['31', '32', '34'] as const) {
      const existing = await prisma.electronicSequence.findUnique({
        where: { companyId_branchId_documentTypeCode: { companyId: company.id, branchId, documentTypeCode } },
      });
      if (!existing) {
        created.push(await electronicInvoicingService.upsertSequence(company.id, {
          branchId,
          documentTypeCode,
          prefix: `E${documentTypeCode}`,
          startNumber: 1,
          currentNumber: 0,
          endNumber: 1,
          status: 'INACTIVE',
        }, 'fullpos_pos', req.requestId));
      }
    }
    res.status(201).json({ success: true, created });
  }),
);

posElectronicInvoicingRouter.post(
  '/outbound/generate/by-rnc',
  overrideKeyGuard,
  validate(posGenerateByRncSchema),
  asyncHandler(async (req, res) => {
    const dto = req.body as typeof posGenerateByRncSchema._output;
    const body = req.body as typeof posGenerateByRncSchema._output & {
      localCode?: string;
      sale?: { localCode?: string };
    };
    const saleLocalCode = body.saleLocalCode ?? body.localCode ?? body.sale?.localCode ?? null;
    let companyId: number | null = null;
    try {
      console.info('[electronic-invoicing.pos] outbound.generate.by-rnc.start', {
        requestId: req.requestId,
        companyRnc: dto.companyRnc ?? null,
        companyCloudId: dto.companyCloudId ?? null,
        saleId: dto.saleId,
        saleLocalCode,
        documentTypeCode: dto.documentTypeCode,
        branchId: dto.branchId,
        autoSubmitToDgii: null,
      });
      const company = await resolvePosCompany(dto.companyRnc ?? null, dto.companyCloudId ?? null, req.requestId, 'outbound_generate_by_rnc');
      companyId = company.id;
      console.info('[electronic-invoicing.pos] outbound.generate.by-rnc.company_resolved', {
        requestId: req.requestId,
        resolvedCompanyId: company.id,
        resolvedRnc: company.rnc ?? null,
        resolvedCloudCompanyId: company.cloudCompanyId ?? null,
      });

      const invoice = await electronicInvoicingService.generateOutbound(
        company.id,
        {
          saleId: dto.saleId,
          saleLocalCode,
          companyCloudId: dto.companyCloudId ?? null,
          companyRnc: dto.companyRnc ?? null,
          documentTypeCode: dto.documentTypeCode as any,
          branchId: dto.branchId,
        },
        'fullpos_pos',
        req.requestId,
      );

      res.status(201).json(invoice);
    } catch (error) {
      return sendOutboundError(res, error, 'generate', safeOutboundErrorDetails({
        requestId: req.requestId,
        companyId,
        companyRnc: dto.companyRnc ?? null,
        companyCloudId: dto.companyCloudId ?? null,
        saleId: dto.saleId,
        saleLocalCode,
        documentTypeCode: dto.documentTypeCode,
        branchId: dto.branchId,
      }));
    }
  }),
);

posElectronicInvoicingRouter.post(
  '/debug/dgii-auth/by-rnc',
  overrideKeyGuard,
  validate(posDebugDgiiAuthByRncSchema),
  asyncHandler(async (req, res) => {
    const body = req.body as unknown as typeof posDebugDgiiAuthByRncSchema._output;
    console.info('[electronic-invoicing.pos] debug.dgii-auth.by-rnc', {
      requestId: req.requestId,
      requestedCompanyId: body.companyId ?? null,
      companyRnc: body.companyRnc ?? null,
      companyCloudId: body.companyCloudId ?? null,
      environment: body.environment ?? null,
    });
    const result = await buildSafeDgiiAuthDiagnostic({
      companyRnc: body.companyRnc,
      companyCloudId: body.companyCloudId,
      requestedCompanyId: body.companyId,
      environment: body.environment,
      forceRefresh: body.forceRefresh,
      diagnosticMatrix: body.diagnosticMatrix,
      requestId: req.requestId,
    });
    res.status(200).json(result);
  }),
);

posElectronicInvoicingRouter.post(
  '/debug/auth/by-rnc',
  overrideKeyGuard,
  validate(posDebugDgiiAuthByRncSchema),
  asyncHandler(async (req, res) => {
    const body = req.body as unknown as typeof posDebugDgiiAuthByRncSchema._output;
    console.info('[electronic-invoicing.pos] debug.auth.by-rnc', {
      requestId: req.requestId,
      requestedCompanyId: body.companyId ?? null,
      companyRnc: body.companyRnc ?? null,
      companyCloudId: body.companyCloudId ?? null,
      environment: body.environment ?? null,
    });
    const result = await buildSafeDgiiAuthDiagnostic({
      companyRnc: body.companyRnc,
      companyCloudId: body.companyCloudId,
      requestedCompanyId: body.companyId,
      environment: body.environment,
      forceRefresh: body.forceRefresh,
      diagnosticMatrix: body.diagnosticMatrix,
      requestId: req.requestId,
    });
    res.status(200).json(result);
  }),
);

posElectronicInvoicingRouter.post(
  '/outbound/sign/by-rnc',
  overrideKeyGuard,
  validate(posSendByRncSchema),
  asyncHandler(async (req, res) => {
    const dto = req.body as typeof posSendByRncSchema._output;
    let companyId: number | null = null;
    try {
      const company = await resolvePosCompany(dto.companyRnc ?? null, dto.companyCloudId ?? null, req.requestId, 'outbound_sign_by_rnc');
      companyId = company.id;

      console.info('[electronic-invoicing.pos] outbound.sign.by-rnc', {
        requestId: req.requestId,
        companyId: company.id,
        companyRnc: dto.companyRnc ?? null,
        companyCloudId: dto.companyCloudId ?? null,
        invoiceId: dto.invoiceId,
        force: dto.force,
      });

      const invoice = await electronicInvoicingService.signOutbound(
        company.id,
        {
          invoiceId: dto.invoiceId,
          force: dto.force,
        },
        'fullpos_pos',
        req.requestId,
      );

      res.json(invoice);
    } catch (error) {
      return sendOutboundError(res, error, 'sign', safeOutboundErrorDetails({
        requestId: req.requestId,
        companyId,
        companyRnc: dto.companyRnc ?? null,
        companyCloudId: dto.companyCloudId ?? null,
        invoiceId: dto.invoiceId,
        branchId: 0,
      }));
    }
  }),
);

posElectronicInvoicingRouter.post(
  '/outbound/submit/by-rnc',
  overrideKeyGuard,
  validate(posSendByRncSchema),
  asyncHandler(async (req, res) => {
    const dto = req.body as typeof posSendByRncSchema._output;
    let companyId: number | null = null;
    try {
      const company = await resolvePosCompany(dto.companyRnc ?? null, dto.companyCloudId ?? null, req.requestId, 'outbound_submit_by_rnc');
      companyId = company.id;

      console.info('[electronic-invoicing.pos] outbound.submit.by-rnc', {
        requestId: req.requestId,
        companyId: company.id,
        companyRnc: dto.companyRnc ?? null,
        companyCloudId: dto.companyCloudId ?? null,
        invoiceId: dto.invoiceId,
        force: dto.force,
        hasManualToken: !!dto.dgiiManualToken,
      });

      const invoice = await electronicInvoicingService.submitOutbound(
        company.id,
        {
          invoiceId: dto.invoiceId,
          force: dto.force,
          dgiiManualToken: dto.dgiiManualToken,
        },
        'fullpos_pos',
        req.requestId,
      );

      res.json(invoice);
    } catch (error) {
      return sendOutboundError(res, error, 'submit', safeOutboundErrorDetails({
        requestId: req.requestId,
        companyId,
        companyRnc: dto.companyRnc ?? null,
        companyCloudId: dto.companyCloudId ?? null,
        invoiceId: dto.invoiceId,
        branchId: 0,
        extra: { submitAttempted: true, hasManualToken: !!dto.dgiiManualToken },
      }));
    }
  }),
);

posElectronicInvoicingRouter.get(
  '/outbound/by-rnc',
  overrideKeyGuard,
  validate(posOutboundListByRncSchema, 'query'),
  asyncHandler(async (req, res) => {
    const query = req.query as unknown as typeof posOutboundListByRncSchema._output;
    const company = await resolvePosCompany(query.companyRnc ?? null, query.companyCloudId ?? null, req.requestId, 'outbound_list_by_rnc');

    const invoices = await prisma.electronicInvoice.findMany({
      where: {
        companyId: company.id,
        direction: 'outbound',
        ...(query.branchId != null ? { branchId: query.branchId } : {}),
      },
      include: {
        sale: {
          select: {
            localCode: true,
          },
        },
      },
      orderBy: { createdAt: 'desc' },
      take: query.limit,
    });

    res.json(
      invoices.map((item) => ({
        id: item.id,
        saleId: item.saleId,
        saleLocalCode: item.sale?.localCode ?? null,
        documentNumber: item.ecf,
        documentTypeCode: item.documentTypeCode,
        documentLabel: documentLabel(item.documentTypeCode),
        dgiiTrackId: item.dgiiTrackId,
        trackId: item.dgiiTrackId,
        internalStatus: item.internalStatus,
        dgiiStatus: item.dgiiStatus,
        status: invoiceClientStatus(item),
        statusLabel: invoiceClientStatusLabel(item),
        rejectionCode: item.rejectionCode,
        rejectionMessage: item.rejectionMessage,
        lastError: item.internalStatus === 'ERROR' || item.dgiiStatus === 'ERROR' ? item.rejectionMessage : null,
        submittedAt: item.submittedAt,
        totalAmount: item.totalAmount,
        customerName: item.buyerName,
        customerRnc: item.buyerRnc,
        referenceDocument: item.originalInvoiceId,
        createdAt: item.createdAt,
      })),
    );
  }),
);

posElectronicInvoicingRouter.get(
  '/outbound/result/by-rnc/:trackId',
  overrideKeyGuard,
  validate(queryTrackDtoSchema, 'params'),
  validate(posQueryByRncSchema, 'query'),
  asyncHandler(async (req, res) => {
    const params = req.params as unknown as typeof queryTrackDtoSchema._output;
    const query = req.query as unknown as typeof posQueryByRncSchema._output;
    let companyId: number | null = null;
    try {
      const company = await resolvePosCompany(query.companyRnc ?? null, query.companyCloudId ?? null, req.requestId, 'outbound_result_by_rnc');
      companyId = company.id;

      console.info('[electronic-invoicing.pos] outbound.result.by-rnc', {
        requestId: req.requestId,
        companyId: company.id,
        companyRnc: query.companyRnc ?? null,
        companyCloudId: query.companyCloudId ?? null,
        trackId: params.trackId,
        branchId: query.branchId,
      });

      const result = await electronicInvoicingService.queryOutboundResult(
        company.id,
        params.trackId,
        'fullpos_pos',
        req.requestId,
      );
      res.json(result);
    } catch (error) {
      return sendOutboundError(res, error, 'result', safeOutboundErrorDetails({
        requestId: req.requestId,
        companyId,
        companyRnc: query.companyRnc ?? null,
        companyCloudId: query.companyCloudId ?? null,
        branchId: query.branchId,
        extra: { trackId: params.trackId },
      }));
    }
  }),
);

export const adminElectronicInvoicingRouter = Router();

adminElectronicInvoicingRouter.post('/certificates', electronicCertificateAccessGuard, uploadElectronicCertificate, validateCreateCertificateRequest, asyncHandler(adminController.createCertificate));

adminElectronicInvoicingRouter.use(authGuard);

adminElectronicInvoicingRouter.get('/config', requireRoles('admin', 'owner'), validate(configQuerySchema, 'query'), asyncHandler(adminController.getConfig));
adminElectronicInvoicingRouter.put('/config', requireRoles('admin', 'owner'), validate(upsertElectronicConfigDtoSchema), asyncHandler(adminController.upsertConfig));
adminElectronicInvoicingRouter.post('/sequences', requireRoles('admin', 'owner'), validate(createSequenceDtoSchema), asyncHandler(adminController.createSequence));
adminElectronicInvoicingRouter.post('/outbound/generate', requireRoles('admin', 'owner'), validate(createEcfDtoSchema), asyncHandler(adminController.generateOutbound));
adminElectronicInvoicingRouter.post('/outbound/sign', requireRoles('admin', 'owner'), validate(sendEcfDtoSchema), asyncHandler(adminController.signOutbound));
adminElectronicInvoicingRouter.post('/outbound/submit', requireRoles('admin', 'owner'), validate(sendEcfDtoSchema), asyncHandler(dgiiController.submitOutbound));
adminElectronicInvoicingRouter.get('/outbound/result/:trackId', requireRoles('admin', 'owner'), validate(queryTrackDtoSchema, 'params'), asyncHandler(dgiiController.queryTrackResult));
adminElectronicInvoicingRouter.get('/outbound/:id/xml/:variant', requireRoles('admin', 'owner'), validate(invoiceIdVariantParamsSchema, 'params'), asyncHandler(adminController.getXmlVariant));
adminElectronicInvoicingRouter.get('/outbound/:id', requireRoles('admin', 'owner'), validate(invoiceIdParamsSchema, 'params'), asyncHandler(adminController.getOutbound));
adminElectronicInvoicingRouter.get('/outbound', requireRoles('admin', 'owner'), validate(listQuerySchema, 'query'), asyncHandler(adminController.listOutbound));
adminElectronicInvoicingRouter.get('/audit/:invoiceId', requireRoles('admin', 'owner'), validate(auditTimelineParamsSchema, 'params'), asyncHandler(adminController.getAuditTimeline));
adminElectronicInvoicingRouter.post('/corrections/credit-note', requireRoles('admin', 'owner'), validate(createCreditNoteDtoSchema), asyncHandler(adminController.createCreditNote));

export const publicElectronicInvoicingRouter = Router();
publicElectronicInvoicingRouter.post('/autenticacion/api/semilla', validate(requestSeedDtoSchema), asyncHandler(publicController.createSeed));
publicElectronicInvoicingRouter.post('/autenticacion/api/semilla/validacioncertificado', validate(validateSeedDtoSchema), asyncHandler(publicController.validateSeed));
publicElectronicInvoicingRouter.post(
  '/recepcion/api/ecf',
  express.text({ type: ['application/xml', 'text/xml'] }),
  validateReceiveEcfRequest,
  asyncHandler(publicController.receiveEcf),
);
publicElectronicInvoicingRouter.post(
  '/aprobacioncomercial/api/ecf',
  express.text({ type: ['application/xml', 'text/xml'] }),
  validateCommercialApprovalRequest,
  asyncHandler(publicController.receiveCommercialApproval),
);

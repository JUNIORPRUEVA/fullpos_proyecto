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
const publicController = createElectronicInvoicingPublicController(
  authService,
  receptionService,
  approvalService,
);

const posLocatorsBaseSchema = z.object({
  companyRnc: z.string().trim().min(3).optional(),
  companyCloudId: z.string().trim().min(6).optional(),
});

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
    documentTypeCode: z.enum(['31', '32', '34']),
    prefix: z.string().trim().optional(),
    startNumber: z.coerce.number().int().min(1).optional().default(1),
    currentNumber: z.coerce.number().int().min(0).optional().default(0),
    maxNumber: z.coerce.number().int().positive().optional(),
    endNumber: z.coerce.number().int().positive().optional(),
    status: z.enum(['ACTIVE', 'PAUSED', 'EXHAUSTED', 'INACTIVE']).optional().default('ACTIVE'),
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

function sequenceToClient(item: { id: number; companyId: number; branchId: number; documentTypeCode: string; prefix: string; currentNumber: number | bigint; maxNumber: number | bigint; status: string; updatedAt: Date; createdAt?: Date }) {
  const currentNumber = sequenceNumberToClient(item.currentNumber);
  const maxNumber = sequenceNumberToClient(item.maxNumber);
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
    updatedAt: item.updatedAt,
  };
}

function sequenceIsReady(sequence: { prefix: string; documentTypeCode: string; currentNumber: number | bigint; maxNumber: number | bigint; status: string } | undefined) {
  if (!sequence) return false;
  const currentNumber = sequenceNumberToClient(sequence.currentNumber);
  const maxNumber = sequenceNumberToClient(sequence.maxNumber);
  return sequence.status === 'ACTIVE' &&
    sequence.prefix === `E${sequence.documentTypeCode}` &&
    currentNumber >= 0 &&
    maxNumber > currentNumber;
}

async function buildResolvedConfigPayload(company: Awaited<ReturnType<ElectronicInvoicingMapperService['resolveCompanyOrThrow']>>, branchId: number) {
  const companyConfig = (company as any).config as { address?: string | null; phone?: string | null; email?: string | null } | null | undefined;
  const [config, certificate, sequences] = await Promise.all([
    electronicInvoicingService.getConfig(company.id, branchId),
    prisma.electronicCertificate.findFirst({
      where: { companyId: company.id },
      orderBy: { updatedAt: 'desc' },
    }),
    prisma.electronicSequence.findMany({
      where: { companyId: company.id, branchId },
      orderBy: [{ documentTypeCode: 'asc' }],
    }),
  ]);

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

  const readinessStatus = missing.length === 0 ? 'READY' : (config.active || certificateFound || sequences.length > 0 ? 'PARTIAL' : 'NOT_READY');

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
    environment: z.preprocess(normalizeDgiiEnvironmentAlias, z.enum(['precertification', 'production'])).optional(),
    forceRefresh: z.coerce.boolean().optional().default(true),
  })
  .strict()
  .refine(requirePosLocators, {
    message: 'RNC o ID interno requerido',
    path: ['companyRnc'],
  });

export const posElectronicInvoicingRouter = Router();

// Rutas para FULLPOS (POS) — no tiene JWT. Se protege con overrideKeyGuard.
posElectronicInvoicingRouter.get(
  '/config/by-rnc',
  overrideKeyGuard,
  validate(posConfigByRncSchema, 'query'),
  asyncHandler(async (req, res) => {
    const query = req.query as unknown as typeof posConfigByRncSchema._output;
    const company = await mapper.resolveCompanyOrThrow(query.companyRnc ?? null, query.companyCloudId ?? null);
    const branchId = query.branchId;
    console.info('[electronic-invoicing.pos] config.by-rnc.resolve', {
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

    const company = await mapper.resolveCompanyOrThrow(dto.companyRnc ?? null, dto.companyCloudId ?? null);
    console.info('[electronic-invoicing.pos] config.by-rnc.save.resolve', {
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

posElectronicInvoicingRouter.post(
  '/sequences',
  overrideKeyGuard,
  validate(posSequenceByRncSchema),
  asyncHandler(async (req, res) => {
    const dto = req.body as typeof posSequenceByRncSchema._output;
    const company = await mapper.resolveCompanyOrThrow(dto.companyRnc ?? null, dto.companyCloudId ?? null);
    console.info('[electronic-invoicing.pos] sequence.save.resolve', {
      requestedCompanyId: dto.companyId ?? null,
      companyRnc: dto.companyRnc ?? null,
      companyCloudId: dto.companyCloudId ?? null,
      resolvedCompanyId: company.id,
      branchId: dto.branchId,
      documentTypeCode: dto.documentTypeCode,
    });
    const sequence = await electronicInvoicingService.upsertSequence(company.id, dto, 'fullpos_pos', req.requestId);
    res.status(201).json(sequence);
  }),
);

posElectronicInvoicingRouter.post(
  '/sequences/auto-configure/by-rnc',
  overrideKeyGuard,
  validate(posConfigByRncSchema),
  asyncHandler(async (req, res) => {
    const dto = req.body as unknown as typeof posConfigByRncSchema._output;
    const company = await mapper.resolveCompanyOrThrow(dto.companyRnc ?? null, dto.companyCloudId ?? null);
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
    const company = await mapper.resolveCompanyOrThrow(dto.companyRnc ?? null, dto.companyCloudId ?? null);
    console.info('[electronic-invoicing.pos] outbound.generate.by-rnc', {
      companyId: company.id,
      companyRnc: dto.companyRnc ?? null,
      companyCloudId: dto.companyCloudId ?? null,
      saleId: dto.saleId,
      saleLocalCode,
      documentTypeCode: dto.documentTypeCode,
      branchId: dto.branchId,
    });

    console.info('[electronic-invoicing.pos] generate.by-rnc.service_payload', {
      companyId: company.id,
      companyRnc: dto.companyRnc ?? null,
      companyCloudId: dto.companyCloudId ?? null,
      saleId: dto.saleId,
      saleLocalCode,
      documentTypeCode: dto.documentTypeCode,
      branchId: dto.branchId,
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
  }),
);

posElectronicInvoicingRouter.post(
  '/debug/dgii-auth/by-rnc',
  overrideKeyGuard,
  validate(posDebugDgiiAuthByRncSchema),
  asyncHandler(async (req, res) => {
    const body = req.body as unknown as typeof posDebugDgiiAuthByRncSchema._output;
    const result = await authService.debugAuthenticateByLocators(
      {
        companyRnc: body.companyRnc,
        companyCloudId: body.companyCloudId,
        environment: body.environment,
        forceRefresh: body.forceRefresh,
      },
      req.requestId,
    );
    res.status(200).json(result);
  }),
);

posElectronicInvoicingRouter.post(
  '/debug/auth/by-rnc',
  overrideKeyGuard,
  validate(posDebugDgiiAuthByRncSchema),
  asyncHandler(async (req, res) => {
    const body = req.body as unknown as typeof posDebugDgiiAuthByRncSchema._output;
    const result = await authService.debugAuthenticateByLocators(
      {
        companyRnc: body.companyRnc,
        companyCloudId: body.companyCloudId,
        environment: body.environment,
        forceRefresh: body.forceRefresh,
      },
      req.requestId,
    );
    res.status(200).json(result);
  }),
);

posElectronicInvoicingRouter.post(
  '/outbound/sign/by-rnc',
  overrideKeyGuard,
  validate(posSendByRncSchema),
  asyncHandler(async (req, res) => {
    const dto = req.body as typeof posSendByRncSchema._output;
    const company = await mapper.resolveCompanyOrThrow(dto.companyRnc ?? null, dto.companyCloudId ?? null);

    console.info('[electronic-invoicing.pos] outbound.sign.by-rnc', {
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
  }),
);

posElectronicInvoicingRouter.post(
  '/outbound/submit/by-rnc',
  overrideKeyGuard,
  validate(posSendByRncSchema),
  asyncHandler(async (req, res) => {
    const dto = req.body as typeof posSendByRncSchema._output;
    const company = await mapper.resolveCompanyOrThrow(dto.companyRnc ?? null, dto.companyCloudId ?? null);

    console.info('[electronic-invoicing.pos] outbound.submit.by-rnc', {
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
  }),
);

posElectronicInvoicingRouter.get(
  '/outbound/by-rnc',
  overrideKeyGuard,
  validate(posOutboundListByRncSchema, 'query'),
  asyncHandler(async (req, res) => {
    const query = req.query as unknown as typeof posOutboundListByRncSchema._output;
    const company = await mapper.resolveCompanyOrThrow(query.companyRnc ?? null, query.companyCloudId ?? null);

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
    const company = await mapper.resolveCompanyOrThrow(query.companyRnc ?? null, query.companyCloudId ?? null);

    console.info('[electronic-invoicing.pos] outbound.result.by-rnc', {
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
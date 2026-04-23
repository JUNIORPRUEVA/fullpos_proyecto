import express, { Router } from 'express';
import { z } from 'zod';
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
const authService = new DgiiAuthService(prisma, mapper, signature, audit);
const sequenceService = new SequenceService(prisma, audit);
const xmlBuilder = new DgiiXmlBuilderService();
const submissionService = new DgiiSubmissionService(directory);
const resultService = new DgiiResultService(directory);
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

const posLocatorsSchema = z
  .object({
    companyRnc: z.string().trim().min(3).optional(),
    companyCloudId: z.string().trim().min(6).optional(),
  })
  .refine((data) => !!data.companyRnc || !!data.companyCloudId, {
    message: 'RNC o ID interno requerido',
    path: ['companyRnc'],
  });

const posGenerateByRncSchema = posLocatorsSchema
  .extend({
    saleId: z.coerce.number().int().positive(),
    saleLocalCode: z.string().trim().min(1).optional(),
    documentTypeCode: z.string().trim().min(2),
    branchId: z.coerce.number().int().min(0).optional().default(0),
  })
  .strict();

const posQueryByRncSchema = posLocatorsSchema
  .extend({
    branchId: z.coerce.number().int().min(0).optional().default(0),
  })
  .strict();

export const posElectronicInvoicingRouter = Router();

// Rutas para FULLPOS (POS) — no tiene JWT. Se protege con overrideKeyGuard.
posElectronicInvoicingRouter.post(
  '/outbound/generate/by-rnc',
  overrideKeyGuard,
  validate(posGenerateByRncSchema),
  asyncHandler(async (req, res) => {
    const dto = req.body as typeof posGenerateByRncSchema._output;
    const company = await mapper.resolveCompanyOrThrow(dto.companyRnc ?? null, dto.companyCloudId ?? null);
    console.info('[electronic-invoicing.pos] outbound.generate.by-rnc', {
      companyId: company.id,
      companyRnc: dto.companyRnc ?? null,
      companyCloudId: dto.companyCloudId ?? null,
      saleId: dto.saleId,
      saleLocalCode: dto.saleLocalCode ?? null,
      documentTypeCode: dto.documentTypeCode,
      branchId: dto.branchId,
    });

    const invoice = await electronicInvoicingService.generateOutbound(
      company.id,
      {
        saleId: dto.saleId,
        documentTypeCode: dto.documentTypeCode as any,
        branchId: dto.branchId,
      },
      'fullpos_pos',
      req.requestId,
    );

    res.status(201).json(invoice);
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
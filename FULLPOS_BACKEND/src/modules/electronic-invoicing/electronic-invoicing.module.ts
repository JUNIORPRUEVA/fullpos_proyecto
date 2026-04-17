import express, { Router } from 'express';
import { prisma } from '../../config/prisma';
import { authGuard } from '../../middlewares/authGuard';
import { requireRoles } from '../../middlewares/requireRoles';
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
import { createElectronicInvoicingAdminController } from './controllers/electronic-invoicing-admin.controller';
import { createElectronicInvoicingDgiiController } from './controllers/electronic-invoicing-dgii.controller';
import { createElectronicInvoicingPublicController } from './controllers/electronic-invoicing-public.controller';

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

export const adminElectronicInvoicingRouter = Router();
adminElectronicInvoicingRouter.use(authGuard);

adminElectronicInvoicingRouter.get('/config', requireRoles('admin', 'owner'), adminController.getConfig);
adminElectronicInvoicingRouter.put('/config', requireRoles('admin', 'owner'), adminController.upsertConfig);
adminElectronicInvoicingRouter.post('/sequences', requireRoles('admin', 'owner'), adminController.createSequence);
adminElectronicInvoicingRouter.post('/certificates', requireRoles('admin', 'owner'), adminController.createCertificate);
adminElectronicInvoicingRouter.post('/outbound/generate', requireRoles('admin', 'owner'), adminController.generateOutbound);
adminElectronicInvoicingRouter.post('/outbound/sign', requireRoles('admin', 'owner'), adminController.signOutbound);
adminElectronicInvoicingRouter.post('/outbound/submit', requireRoles('admin', 'owner'), dgiiController.submitOutbound);
adminElectronicInvoicingRouter.get('/outbound/result/:trackId', requireRoles('admin', 'owner'), dgiiController.queryTrackResult);
adminElectronicInvoicingRouter.get('/outbound/:id/xml/:variant', requireRoles('admin', 'owner'), adminController.getXmlVariant);
adminElectronicInvoicingRouter.get('/outbound/:id', requireRoles('admin', 'owner'), adminController.getOutbound);
adminElectronicInvoicingRouter.get('/outbound', requireRoles('admin', 'owner'), adminController.listOutbound);
adminElectronicInvoicingRouter.get('/audit/:invoiceId', requireRoles('admin', 'owner'), adminController.getAuditTimeline);
adminElectronicInvoicingRouter.post('/corrections/credit-note', requireRoles('admin', 'owner'), adminController.createCreditNote);

export const publicElectronicInvoicingRouter = Router();
publicElectronicInvoicingRouter.post('/autenticacion/api/semilla', publicController.createSeed);
publicElectronicInvoicingRouter.post('/autenticacion/api/semilla/validacioncertificado', publicController.validateSeed);
publicElectronicInvoicingRouter.post(
  '/recepcion/api/ecf',
  express.text({ type: ['application/xml', 'text/xml'] }),
  publicController.receiveEcf,
);
publicElectronicInvoicingRouter.post(
  '/aprobacioncomercial/api/ecf',
  express.text({ type: ['application/xml', 'text/xml'] }),
  publicController.receiveCommercialApproval,
);
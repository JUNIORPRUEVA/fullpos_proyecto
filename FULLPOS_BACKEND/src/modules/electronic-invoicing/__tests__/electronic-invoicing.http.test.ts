import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import request from 'supertest';
import { authGuard } from '../../../middlewares/authGuard';
import { asyncHandler } from '../../../middlewares/asyncHandler';
import { errorHandler, notFound } from '../../../middlewares/errorHandler';
import { requireRoles } from '../../../middlewares/requireRoles';
import { validate } from '../../../middlewares/validate';
import {
  auditTimelineParamsSchema,
  configQuerySchema,
  createElectronicInvoicingAdminController,
  invoiceIdParamsSchema,
  invoiceIdVariantParamsSchema,
  listQuerySchema,
} from '../controllers/electronic-invoicing-admin.controller';
import { createElectronicInvoicingDgiiController } from '../controllers/electronic-invoicing-dgii.controller';
import {
  createElectronicInvoicingPublicController,
  validateCommercialApprovalRequest,
  validateReceiveEcfRequest,
} from '../controllers/electronic-invoicing-public.controller';
import { createCertificateDtoSchema } from '../dto/certificate.dto';
import { upsertElectronicConfigDtoSchema } from '../dto/config.dto';
import { createCreditNoteDtoSchema } from '../dto/credit-note.dto';
import { createEcfDtoSchema } from '../dto/create-ecf.dto';
import { queryTrackDtoSchema } from '../dto/query-track.dto';
import { createSequenceDtoSchema } from '../dto/sequence.dto';
import { sendEcfDtoSchema } from '../dto/send-ecf.dto';
import { requestSeedDtoSchema, validateSeedDtoSchema } from '../dto/validate-seed.dto';
import { ensureFeTestEnv } from './test-helpers';

ensureFeTestEnv();

function buildAdminToken() {
  return jwt.sign(
    {
      id: 1,
      companyId: 1,
      username: 'owner',
      role: 'owner',
      email: 'owner@example.com',
    },
    process.env.JWT_ACCESS_SECRET!,
    { expiresIn: '15m' },
  );
}

function createPublicTestApp(overrides?: {
  authService?: Record<string, any>;
  receptionService?: Record<string, any>;
  approvalService?: Record<string, any>;
}) {
  const app = express();
  app.use(express.json());

  const controller = createElectronicInvoicingPublicController(
    {
      createSeed: async () => ({ seedId: 'seed-1', xml: '<Semilla />', expiresAt: new Date('2026-01-01T00:00:00.000Z') }),
      validateSignedSeed: async () => ({ accessToken: 'fe-token', expiresIn: 300, tokenType: 'Bearer' }),
      ...(overrides?.authService ?? {}),
    } as any,
    {
      receive: async () => ({ ok: true, acknowledged: true, invoiceId: 9, ecf: 'E310000000009', receivedAt: '2026-01-01T00:00:00.000Z' }),
      ...(overrides?.receptionService ?? {}),
    } as any,
    {
      receiveApproval: async () => ({ ok: true, invoiceId: 9, ecf: 'E310000000009', commercialStatus: 'APPROVED', internalStatus: 'COMMERCIAL_APPROVED' }),
      ...(overrides?.approvalService ?? {}),
    } as any,
  );

  const router = express.Router();
  router.post('/autenticacion/api/semilla', validate(requestSeedDtoSchema), asyncHandler(controller.createSeed));
  router.post('/autenticacion/api/semilla/validacioncertificado', validate(validateSeedDtoSchema), asyncHandler(controller.validateSeed));
  router.post('/recepcion/api/ecf', express.text({ type: ['application/xml', 'text/xml'] }), validateReceiveEcfRequest, asyncHandler(controller.receiveEcf));
  router.post('/aprobacioncomercial/api/ecf', express.text({ type: ['application/xml', 'text/xml'] }), validateCommercialApprovalRequest, asyncHandler(controller.receiveCommercialApproval));

  app.use('/fe', router);
  app.use(notFound);
  app.use(errorHandler);
  return app;
}

function createAdminTestApp(serviceOverrides?: Record<string, any>) {
  const app = express();
  app.use(express.json());

  const adminController = createElectronicInvoicingAdminController({
    getConfig: async () => ({ id: 1, companyId: 1, branchId: 0, active: true, outboundEnabled: true }),
    upsertConfig: async (_companyId: number, dto: any) => ({ id: 1, companyId: 1, ...dto }),
    upsertSequence: async (_companyId: number, dto: any) => ({ id: 2, companyId: 1, prefix: `E${dto.documentTypeCode}`, ...dto }),
    registerCertificate: async () => ({ id: 3, alias: 'main-cert', serialNumber: '1001', subject: 'CN=Test', issuer: 'CN=Test', validFrom: new Date('2025-01-01T00:00:00.000Z'), validTo: new Date('2027-01-01T00:00:00.000Z'), status: 'ACTIVE' }),
    generateOutbound: async () => ({ id: 4, ecf: 'E310000000001', internalStatus: 'GENERATED' }),
    signOutbound: async () => ({ id: 4, ecf: 'E310000000001', internalStatus: 'SIGNED', xmlSigned: '<eCF><Signature /></eCF>' }),
    listOutboundInvoices: async () => ([]),
    getOutboundInvoice: async () => ({ id: 4, ecf: 'E310000000001', statusHistory: [] }),
    getXmlVariant: async () => ({ filename: 'E310000000001-signed.xml', xml: '<eCF />' }),
    getAuditTimeline: async () => ({ statusHistory: [], auditLogs: [] }),
    createCreditNote: async () => ({ id: 5, ecf: 'E340000000001', internalStatus: 'GENERATED' }),
    submitOutbound: async () => ({ id: 4, ecf: 'E310000000001', internalStatus: 'SUBMITTED' }),
    queryOutboundResult: async () => ({ invoice: { id: 4 }, result: { trackId: 'TRK-1', normalizedStatus: 'pending' } }),
    ...(serviceOverrides ?? {}),
  } as any);

  const dgiiController = createElectronicInvoicingDgiiController({
    submitOutbound: async (_companyId: number, dto: any) => ({ id: dto.invoiceId, internalStatus: 'SUBMITTED' }),
    queryOutboundResult: async () => ({ invoice: { id: 4 }, result: { trackId: 'TRK-1', normalizedStatus: 'pending' } }),
    ...(serviceOverrides ?? {}),
  } as any);

  const router = express.Router();
  router.use(authGuard);
  router.get('/config', requireRoles('admin', 'owner'), validate(configQuerySchema, 'query'), asyncHandler(adminController.getConfig));
  router.put('/config', requireRoles('admin', 'owner'), validate(upsertElectronicConfigDtoSchema), asyncHandler(adminController.upsertConfig));
  router.post('/sequences', requireRoles('admin', 'owner'), validate(createSequenceDtoSchema), asyncHandler(adminController.createSequence));
  router.post('/certificates', requireRoles('admin', 'owner'), validate(createCertificateDtoSchema), asyncHandler(adminController.createCertificate));
  router.post('/outbound/generate', requireRoles('admin', 'owner'), validate(createEcfDtoSchema), asyncHandler(adminController.generateOutbound));
  router.post('/outbound/sign', requireRoles('admin', 'owner'), validate(sendEcfDtoSchema), asyncHandler(adminController.signOutbound));
  router.post('/outbound/submit', requireRoles('admin', 'owner'), validate(sendEcfDtoSchema), asyncHandler(dgiiController.submitOutbound));
  router.get('/outbound/result/:trackId', requireRoles('admin', 'owner'), validate(queryTrackDtoSchema, 'params'), asyncHandler(dgiiController.queryTrackResult));
  router.get('/outbound/:id/xml/:variant', requireRoles('admin', 'owner'), validate(invoiceIdVariantParamsSchema, 'params'), asyncHandler(adminController.getXmlVariant));
  router.get('/outbound/:id', requireRoles('admin', 'owner'), validate(invoiceIdParamsSchema, 'params'), asyncHandler(adminController.getOutbound));
  router.get('/outbound', requireRoles('admin', 'owner'), validate(listQuerySchema, 'query'), asyncHandler(adminController.listOutbound));
  router.get('/audit/:invoiceId', requireRoles('admin', 'owner'), validate(auditTimelineParamsSchema, 'params'), asyncHandler(adminController.getAuditTimeline));
  router.post('/corrections/credit-note', requireRoles('admin', 'owner'), validate(createCreditNoteDtoSchema), asyncHandler(adminController.createCreditNote));

  app.use('/api/electronic-invoicing', router);
  app.use(notFound);
  app.use(errorHandler);
  return app;
}

test('invalid public FE payload returns 400 JSON and does not crash', async () => {
  const app = createPublicTestApp();

  const response = await request(app)
    .post('/fe/autenticacion/api/semilla')
    .send({});

  assert.equal(response.status, 400);
  assert.equal(response.body.message, 'Validation error');
  assert.equal(response.body.errorCode, 'VALIDATION_ERROR');
  assert.ok(Array.isArray(response.body.issues));
  assert.equal(response.body.issues[0]?.path?.[0], 'companyRnc');
});

test('invalid admin FE payload returns 400 JSON and does not crash', async () => {
  const app = createAdminTestApp();
  const token = buildAdminToken();

  const response = await request(app)
    .put('/api/electronic-invoicing/config')
    .set('Authorization', `Bearer ${token}`)
    .send({ publicBaseUrl: 'notaurl' });

  assert.equal(response.status, 400);
  assert.equal(response.body.message, 'Validation error');
  assert.equal(response.body.errorCode, 'VALIDATION_ERROR');
  assert.ok(Array.isArray(response.body.issues));
});

test('unauthenticated admin FE route returns 401 cleanly', async () => {
  const app = createAdminTestApp();

  const response = await request(app)
    .get('/api/electronic-invoicing/config');

  assert.equal(response.status, 401);
  assert.deepEqual(response.body, { message: 'Token requerido' });
});

test('valid FE request still works with safe handler pipeline', async () => {
  const app = createPublicTestApp();

  const response = await request(app)
    .post('/fe/autenticacion/api/semilla')
    .send({ companyRnc: '101010101', branchId: 0 });

  assert.equal(response.status, 201);
  assert.equal(response.body.seedId, 'seed-1');
  assert.match(response.body.xml, /Semilla/);
});

test('service error reaches errorHandler through async wrapper', async () => {
  const app = createAdminTestApp({
    getConfig: async () => {
      throw {
        status: 409,
        message: 'fallo-controlado',
        errorCode: 'CONTROLLED_FAILURE',
      };
    },
  });
  const token = buildAdminToken();

  const response = await request(app)
    .get('/api/electronic-invoicing/config?branchId=0')
    .set('Authorization', `Bearer ${token}`);

  assert.equal(response.status, 409);
  assert.equal(response.body.message, 'fallo-controlado');
  assert.equal(response.body.errorCode, 'CONTROLLED_FAILURE');
});

test('invalid inbound FE payload returns 400 JSON instead of uncaught crash', async () => {
  const app = createPublicTestApp();

  const response = await request(app)
    .post('/fe/recepcion/api/ecf')
    .send({});

  assert.equal(response.status, 400);
  assert.equal(response.body.message, 'Validation error');
  assert.equal(response.body.errorCode, 'VALIDATION_ERROR');
  assert.ok(Array.isArray(response.body.issues));
  assert.equal(response.body.issues[0]?.path?.[0], 'xml');
});
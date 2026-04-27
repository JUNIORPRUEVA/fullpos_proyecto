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
  uploadElectronicCertificate,
  validateCreateCertificateRequest,
} from '../controllers/electronic-invoicing-admin.controller';
import { createElectronicInvoicingDgiiController } from '../controllers/electronic-invoicing-dgii.controller';
import {
  createElectronicInvoicingPublicController,
  validateCommercialApprovalRequest,
  validateReceiveEcfRequest,
} from '../controllers/electronic-invoicing-public.controller';
import { upsertElectronicConfigDtoSchema } from '../dto/config.dto';
import { createCreditNoteDtoSchema } from '../dto/credit-note.dto';
import { createEcfDtoSchema } from '../dto/create-ecf.dto';
import { queryTrackDtoSchema } from '../dto/query-track.dto';
import { createSequenceDtoSchema } from '../dto/sequence.dto';
import { sendEcfDtoSchema } from '../dto/send-ecf.dto';
import { requestSeedDtoSchema, validateSeedDtoSchema } from '../dto/validate-seed.dto';
import { createTempPkcs12, ensureFeTestEnv } from './test-helpers';
const { ElectronicInvoicingService } = require('../services/electronic-invoicing.service');
const { DgiiXmlBuilderService } = require('../services/dgii-xml-builder.service');
const { DgiiSignatureService } = require('../services/dgii-signature.service');

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
  router.post('/certificates', requireRoles('admin', 'owner'), uploadElectronicCertificate, validateCreateCertificateRequest, asyncHandler(adminController.createCertificate));
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

function createCertificatePrisma() {
  let certificateId = 1;
  const state = {
    certificates: [] as Array<any>,
    auditLogs: [] as Array<any>,
  };

  return {
    state,
    prisma: {
      electronicCertificate: {
        async upsert(input: { where: { companyId_alias: { companyId: number; alias: string } }; create: any; update: any }) {
          const existingIndex = state.certificates.findIndex(
            (item) =>
              item.companyId === input.where.companyId_alias.companyId &&
              item.alias === input.where.companyId_alias.alias,
          );
          if (existingIndex >= 0) {
            state.certificates[existingIndex] = {
              ...state.certificates[existingIndex],
              ...input.update,
              updatedAt: new Date(),
            };
            return state.certificates[existingIndex];
          }

          const record = {
            id: certificateId++,
            createdAt: new Date(),
            updatedAt: new Date(),
            ...input.create,
          };
          state.certificates.push(record);
          return record;
        },
      },
      electronicAuditLog: {
        async create(input: { data: any }) {
          state.auditLogs.push(input.data);
          return input.data;
        },
      },
    },
  };
}

function createAdminCertificateUploadApp() {
  const { prisma, state } = createCertificatePrisma();
  const app = express();
  const token = buildAdminToken();
  const service = new ElectronicInvoicingService(
    prisma as any,
    {} as any,
    {} as any,
    new DgiiXmlBuilderService(),
    new DgiiSignatureService(),
    {} as any,
    {} as any,
    { log: async (input: any) => state.auditLogs.push(input) } as any,
  );
  const adminController = createElectronicInvoicingAdminController(service as any);

  app.use(express.json());

  const router = express.Router();
  router.use(authGuard);
  router.post(
    '/certificates',
    requireRoles('admin', 'owner'),
    uploadElectronicCertificate,
    validateCreateCertificateRequest,
    asyncHandler(adminController.createCertificate),
  );

  app.use('/api/electronic-invoicing', router);
  app.use(notFound);
  app.use(errorHandler);

  return { app, token, state };
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

test('multipart electronic certificate upload succeeds and stores encrypted inline payload', async () => {
  const cert = createTempPkcs12({ password: 'secret123' });
  const { app, token, state } = createAdminCertificateUploadApp();

  try {
    const response = await request(app)
      .post('/api/electronic-invoicing/certificates')
      .set('Authorization', `Bearer ${token}`)
      .field('alias', 'main-cert')
      .field('password', 'secret123')
      .attach('file', cert.filePath);

    assert.equal(response.status, 201);
    assert.equal(response.body.success, true);
    assert.equal(response.body.alias, 'main-cert');
    assert.equal(response.body.serial, '1001');
    assert.match(state.certificates[0]?.secretReference ?? '', /^inline-p12:/);
    assert.equal(state.certificates[0]?.filePath, null);
  } finally {
    cert.cleanup();
  }
});

test('multipart electronic certificate upload returns 400 for wrong password', async () => {
  const cert = createTempPkcs12({ password: 'correct-password' });
  const { app, token } = createAdminCertificateUploadApp();

  try {
    const response = await request(app)
      .post('/api/electronic-invoicing/certificates')
      .set('Authorization', `Bearer ${token}`)
      .field('alias', 'bad-pass')
      .field('password', 'wrong-password')
      .attach('file', cert.filePath);

    assert.equal(response.status, 400);
    assert.equal(response.body.errorCode, 'CERTIFICATE_INVALID_PASSWORD');
  } finally {
    cert.cleanup();
  }
});

test('multipart electronic certificate upload allows expired certificate with warning', async () => {
  const cert = createTempPkcs12({
    password: 'secret123',
    validFrom: new Date('2020-01-01T00:00:00.000Z'),
    validTo: new Date('2021-01-01T00:00:00.000Z'),
  });
  const { app, token, state } = createAdminCertificateUploadApp();

  try {
    const response = await request(app)
      .post('/api/electronic-invoicing/certificates')
      .set('Authorization', `Bearer ${token}`)
      .field('alias', 'expired-cert')
      .field('password', 'secret123')
      .attach('file', cert.filePath);

    assert.equal(response.status, 201);
    assert.equal(response.body.success, true);
    assert.match(response.body.warning ?? '', /expirado/i);
    assert.equal(state.certificates[0]?.status, 'EXPIRED');
  } finally {
    cert.cleanup();
  }
});

test('multipart electronic certificate upload rejects invalid file extension', async () => {
  const { app, token } = createAdminCertificateUploadApp();
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const invalidPath = path.join(os.tmpdir(), `fullpos-invalid-${Date.now()}.txt`);
  fs.writeFileSync(invalidPath, 'not-a-certificate', 'utf8');

  try {
    const response = await request(app)
      .post('/api/electronic-invoicing/certificates')
      .set('Authorization', `Bearer ${token}`)
      .field('alias', 'invalid-file')
      .field('password', 'secret123')
      .attach('file', invalidPath);

    assert.equal(response.status, 400);
    assert.equal(response.body.errorCode, 'ELECTRONIC_CERTIFICATE_INVALID_FILE');
  } finally {
    fs.rmSync(invalidPath, { force: true });
  }
});
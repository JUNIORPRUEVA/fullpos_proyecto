import test from 'node:test';
import assert from 'node:assert/strict';
import { createTempPkcs12, ensureFeTestEnv } from './test-helpers';

ensureFeTestEnv();

const { ElectronicInvoicingService } = require('../services/electronic-invoicing.service');
const { DgiiXmlBuilderService } = require('../services/dgii-xml-builder.service');
const { DgiiSignatureService } = require('../services/dgii-signature.service');

function createInMemoryPrisma() {
  let invoiceId = 1;
  let certificateId = 1;
  const state = {
    config: {
      id: 1,
      companyId: 1,
      branchId: 0,
      authEnabled: true,
      authPath: '/fe/autenticacion/api/semilla',
      receptionPath: '/fe/recepcion/api/ecf',
      approvalPath: '/fe/aprobacioncomercial/api/ecf',
      publicBaseUrl: 'https://example.test',
      active: true,
      outboundEnabled: true,
      environment: 'precertification',
      tokenTtlSeconds: 300,
    },
    invoices: [] as Array<any>,
    statusHistory: [] as Array<any>,
    certificates: [] as Array<any>,
  };

  const prisma = {
    electronicInboundEndpointConfig: {
      async findUnique() {
        return state.config;
      },
      async upsert(input: { create: any; update: any }) {
        state.config = { ...state.config, ...input.create, ...input.update };
        return state.config;
      },
    },
    electronicCertificate: {
      async upsert(input: { where: { companyId_alias: { alias: string } }; create: any; update: any }) {
        const existingIndex = state.certificates.findIndex(
          (item) => item.companyId === 1 && item.alias === input.where.companyId_alias.alias,
        );
        if (existingIndex >= 0) {
          state.certificates[existingIndex] = { ...state.certificates[existingIndex], ...input.update };
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
      async findFirst() {
        return state.certificates[state.certificates.length - 1] ?? null;
      },
    },
    electronicInvoice: {
      async findFirst(input: { where: any }) {
        return (
          state.invoices.find((invoice) => {
            if (input.where.id != null && invoice.id !== input.where.id) return false;
            if (input.where.companyId != null && invoice.companyId !== input.where.companyId) return false;
            if (input.where.saleId != null && invoice.saleId !== input.where.saleId) return false;
            if (input.where.direction != null && invoice.direction !== input.where.direction) return false;
            if (input.where.documentTypeCode != null && invoice.documentTypeCode !== input.where.documentTypeCode) return false;
            if (input.where.dgiiTrackId != null && invoice.dgiiTrackId !== input.where.dgiiTrackId) return false;
            if (input.where.internalStatus?.notIn?.includes(invoice.internalStatus)) return false;
            return true;
          }) ?? null
        );
      },
      async findUnique(input: { where: { id: number } }) {
        return state.invoices.find((invoice) => invoice.id === input.where.id) ?? null;
      },
      async create(input: { data: any }) {
        const record = {
          id: invoiceId++,
          createdAt: new Date(),
          updatedAt: new Date(),
          ...input.data,
        };
        state.invoices.push(record);
        return record;
      },
      async update(input: { where: { id: number }; data: any }) {
        const current = state.invoices.find((invoice) => invoice.id === input.where.id);
        if (!current) throw new Error('invoice not found');
        Object.assign(current, input.data, { updatedAt: new Date() });
        return current;
      },
      async findMany() {
        return [...state.invoices];
      },
    },
    electronicInvoiceStatusHistory: {
      async create(input: { data: any }) {
        state.statusHistory.push({ id: state.statusHistory.length + 1, ...input.data });
        return state.statusHistory[state.statusHistory.length - 1];
      },
      async findMany() {
        return [...state.statusHistory];
      },
    },
  };

  return { prisma, state };
}

test('ElectronicInvoicingService registers certificate on happy path and rejects invalid password', async () => {
  const validCert = createTempPkcs12({ password: 'secret123' });
  const invalidCert = createTempPkcs12({ password: 'correct-password' });
  const { prisma } = createInMemoryPrisma();
  const auditEvents: Array<any> = [];
  const service = new ElectronicInvoicingService(
    prisma as any,
    {} as any,
    {} as any,
    new DgiiXmlBuilderService(),
    new DgiiSignatureService(),
    {} as any,
    {} as any,
    { log: async (input: any) => auditEvents.push(input) } as any,
  );

  try {
    const registered = await service.registerCertificate(
      1,
      { alias: 'precert-main', filePath: validCert.filePath, password: 'secret123' },
      'owner',
      'req-cert',
    );

    assert.equal(registered.alias, 'precert-main');
    assert.equal(auditEvents[0]?.eventType, 'certificate.registered');

    await assert.rejects(
      service.registerCertificate(
        1,
        { alias: 'bad-pass', filePath: invalidCert.filePath, password: 'wrong-password' },
        'owner',
        'req-cert-bad',
      ),
    );
  } finally {
    validCert.cleanup();
    invalidCert.cleanup();
  }
});

test('ElectronicInvoicingService completes outbound generate -> sign flow with real XML signature', async () => {
  const cert = createTempPkcs12({ password: 'secret123' });
  const { prisma, state } = createInMemoryPrisma();
  const auditEvents: Array<any> = [];
  const mapper = {
    async mapSaleToOutbound() {
      return {
        ecf: '',
        documentTypeCode: '31',
        issueDate: new Date('2025-01-03T10:00:00.000Z'),
        currencyCode: 'DOP',
        issuer: { rnc: '101010101', name: 'Empresa Demo', address: 'Calle 1' },
        buyer: { rnc: '131313131', name: 'Cliente Fiscal' },
        lines: [
          {
            lineNumber: 1,
            description: 'Producto A',
            quantity: 1,
            unitPrice: 100,
            lineExtensionAmount: 100,
            taxAmount: 18,
          },
        ],
        subtotalAmount: 100,
        taxAmount: 18,
        totalAmount: 118,
      };
    },
  };
  const sequenceService = {
    async allocate() {
      return { ecf: 'E310000000001', prefix: 'E31', sequenceNumber: 1 };
    },
  };
  const service = new ElectronicInvoicingService(
    prisma as any,
    mapper as any,
    sequenceService as any,
    new DgiiXmlBuilderService(),
    new DgiiSignatureService(),
    {} as any,
    {} as any,
    { log: async (input: any) => auditEvents.push(input) } as any,
  );

  try {
    await service.registerCertificate(
      1,
      { alias: 'main-cert', filePath: cert.filePath, password: 'secret123' },
      'owner',
      'req-cert',
    );

    const generated = await service.generateOutbound(
      1,
      { saleId: 100, documentTypeCode: '31', branchId: 0 },
      'owner',
      'req-generate',
    );
    const generatedSnapshot = { ...generated };
    const signed = await service.signOutbound(
      1,
      { invoiceId: generated.id, force: false },
      'owner',
      'req-sign',
    );

    assert.equal(generatedSnapshot.internalStatus, 'GENERATED');
    assert.match(generatedSnapshot.xmlUnsigned ?? '', /<eNCF>E310000000001<\/eNCF>/);
    assert.equal(signed.internalStatus, 'SIGNED');
    assert.ok(signed.certificateId);
    assert.match(signed.xmlSigned ?? '', /<Signature/);
    assert.match(signed.xmlSigned ?? '', /<X509Certificate>/);
    assert.ok(state.statusHistory.some((entry) => entry.toStatus === 'GENERATED'));
    assert.ok(state.statusHistory.some((entry) => entry.toStatus === 'SIGNED'));
    assert.ok(auditEvents.some((entry) => entry.eventType === 'outbound.generated'));
    assert.ok(auditEvents.some((entry) => entry.eventType === 'outbound.signed'));
  } finally {
    cert.cleanup();
  }
});

test('ElectronicInvoicingService creates credit note referencing original invoice', async () => {
  const { prisma, state } = createInMemoryPrisma();
  state.invoices.push({
    id: 40,
    companyId: 1,
    branchId: 0,
    direction: 'outbound',
    documentTypeCode: '31',
    ecf: 'E310000000777',
    issueDate: new Date('2025-01-02T00:00:00.000Z'),
    issuerRnc: '101010101',
    issuerName: 'Empresa Demo',
    buyerRnc: '131313131',
    buyerName: 'Cliente Fiscal',
    currencyCode: 'DOP',
    internalStatus: 'ACCEPTED',
  });
  const mapper = {
    async mapCreditNoteToOutbound() {
      return {
        ecf: '',
        documentTypeCode: '34',
        issueDate: new Date('2025-01-04T10:00:00.000Z'),
        currencyCode: 'DOP',
        issuer: { rnc: '101010101', name: 'Empresa Demo', address: 'Calle 1' },
        buyer: { rnc: '131313131', name: 'Cliente Fiscal' },
        lines: [
          {
            lineNumber: 1,
            description: 'Devolución Producto A',
            quantity: 1,
            unitPrice: 100,
            lineExtensionAmount: 100,
            taxAmount: 18,
          },
        ],
        subtotalAmount: 100,
        taxAmount: 18,
        totalAmount: 118,
        reference: {
          modifiedEcf: 'E310000000777',
          modifiedDocumentTypeCode: '31',
          modifiedIssueDate: new Date('2025-01-02T00:00:00.000Z'),
          reason: 'Devolución total',
        },
      };
    },
  };
  const sequenceService = {
    async allocate() {
      return { ecf: 'E340000000001', prefix: 'E34', sequenceNumber: 1 };
    },
  };
  const service = new ElectronicInvoicingService(
    prisma as any,
    mapper as any,
    sequenceService as any,
    new DgiiXmlBuilderService(),
    new DgiiSignatureService(),
    {} as any,
    {} as any,
    { log: async () => undefined } as any,
  );

  const creditNote = await service.createCreditNote(
    1,
    { originalInvoiceId: 40, saleId: 200, branchId: 0, reason: 'Devolución total' },
    'owner',
    'req-credit',
  );

  assert.equal(creditNote.documentTypeCode, '34');
  assert.equal(creditNote.originalInvoiceId, 40);
  assert.match(creditNote.xmlUnsigned ?? '', /<NCFModificado>E310000000777<\/NCFModificado>/);
  assert.match(creditNote.xmlUnsigned ?? '', /<RazonModificacion>Devolución total<\/RazonModificacion>/);
});

test('ElectronicInvoicingService writes audit log when DGII submission fails', async () => {
  const { prisma, state } = createInMemoryPrisma();
  state.invoices.push({
    id: 80,
    companyId: 1,
    branchId: 0,
    direction: 'outbound',
    documentTypeCode: '31',
    ecf: 'E310000000080',
    sequenceNumber: 80,
    issuerRnc: '101010101',
    issuerName: 'Empresa Demo',
    issueDate: new Date('2025-01-01T00:00:00.000Z'),
    totalAmount: 118,
    taxAmount: 18,
    currencyCode: 'DOP',
    xmlUnsigned: '<eCF></eCF>',
    xmlSigned: '<eCF><Signature/></eCF>',
    dgiiStatus: 'NOT_SENT',
    commercialStatus: 'NONE',
    internalStatus: 'SIGNED',
  });
  const auditEvents: Array<any> = [];
  const submissionService = {
    async submit() {
      return {
        httpStatus: 503,
        ok: false,
        normalizedStatus: 'error',
        code: 'DGII_DOWN',
        message: 'DGII temporalmente no disponible',
        raw: { message: 'DGII temporalmente no disponible' },
      };
    },
  };
  const service = new ElectronicInvoicingService(
    prisma as any,
    {} as any,
    {} as any,
    new DgiiXmlBuilderService(),
    new DgiiSignatureService(),
    submissionService as any,
    {} as any,
    { log: async (input: any) => auditEvents.push(input) } as any,
  );

  const invoice = await service.submitOutbound(1, { invoiceId: 80, force: false }, 'owner', 'req-submit');

  assert.equal(invoice.internalStatus, 'ERROR');
  assert.equal(invoice.dgiiStatus, 'ERROR');
  assert.ok(auditEvents.some((entry) => entry.eventType === 'outbound.submitted'));
});

test('ElectronicInvoicingService rejects malformed or unknown TrackId before remote polling', async () => {
  const { prisma } = createInMemoryPrisma();
  const service = new ElectronicInvoicingService(
    prisma as any,
    {} as any,
    {} as any,
    new DgiiXmlBuilderService(),
    new DgiiSignatureService(),
    {} as any,
    {} as any,
    { log: async () => undefined } as any,
  );

  await assert.rejects(
    service.queryOutboundResult(1, '../bad-track-id', 'owner', 'req-track'),
    (error: any) => error?.errorCode === 'TRACK_NOT_FOUND',
  );
});
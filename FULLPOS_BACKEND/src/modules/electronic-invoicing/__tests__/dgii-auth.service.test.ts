import test from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';
import { ensureFeTestEnv } from './test-helpers';

ensureFeTestEnv();

const { DgiiAuthService } = require('../services/dgii-auth.service');
const { sha256Hex } = require('../utils/hash.utils');

test('DgiiAuthService creates a seed with nonce, expiration, and audit log', async () => {
  const createdSeeds: Array<Record<string, unknown>> = [];
  const auditEvents: Array<{ eventType: string }> = [];
  const mapper = {
    async resolveCompanyOrThrow() {
      return { id: 1, rnc: '101010101', name: 'Empresa Demo' };
    },
  };
  const prisma = {
    electronicAuthSeed: {
      async create(input: { data: Record<string, unknown> }) {
        createdSeeds.push(input.data);
        return { id: 'seed-1', ...input.data };
      },
    },
  };
  const audit = {
    async log(input: { eventType: string }) {
      auditEvents.push(input);
    },
  };

  const service = new DgiiAuthService(prisma as any, mapper as any, {} as any, audit as any, {} as any);
  const result = await service.createSeed('101010101', undefined, 0, 'req-seed');

  assert.equal(result.seedId, 'seed-1');
  assert.match(result.xml, /<Nonce>/);
  assert.ok(result.expiresAt instanceof Date);
  assert.equal(createdSeeds.length, 1);
  assert.equal(auditEvents[0]?.eventType, 'auth.seed.created');
});

test('DgiiAuthService rejects expired signed seeds', async () => {
  const mapper = {
    async resolveCompanyOrThrow() {
      return { id: 1, rnc: '101010101', name: 'Empresa Demo' };
    },
  };
  const prisma = {
    electronicAuthSeed: {
      async findFirst() {
        return {
          id: 'seed-expired',
          companyId: 1,
          expiresAt: new Date(Date.now() - 60_000),
          challengeHash: 'unused-hash',
        };
      },
    },
  };
  const signatureService = {
    verifySignedXml() {
      return { valid: true, certificatePem: '-----BEGIN CERTIFICATE-----ABC-----END CERTIFICATE-----', errors: [] };
    },
  };

  const service = new DgiiAuthService(prisma as any, mapper as any, signatureService as any, { log: async () => undefined } as any, {} as any);

  await assert.rejects(
    service.validateSignedSeed(
      '101010101',
      undefined,
      0,
      '<Semilla><Id>seed-expired</Id><Nonce>nonce-1</Nonce></Semilla>',
      'req-expired',
    ),
    (error: any) => error?.errorCode === 'SEED_EXPIRED',
  );
});

test('DgiiAuthService enforces Bearer token for inbound routes when auth is enabled', async () => {
  const secret = sha256Hex(process.env.FE_MASTER_ENCRYPTION_KEY!);
  const validToken = jwt.sign({ companyId: 1, branchId: 0 }, secret, { expiresIn: 300 });
  const prisma = {
    electronicInboundEndpointConfig: {
      async findUnique() {
        return { companyId: 1, branchId: 0, authEnabled: true };
      },
    },
  };

  const service = new DgiiAuthService(prisma as any, {} as any, {} as any, {} as any, {} as any);

  await assert.rejects(
    service.assertInboundToken(1, 0, undefined),
    (error: any) => error?.errorCode === 'FE_TOKEN_REQUIRED',
  );

  await assert.doesNotReject(service.assertInboundToken(1, 0, `Bearer ${validToken}`));
});

test('DgiiAuthService falls back to legacy env token when automatic auth endpoints are missing', async () => {
  process.env.DGII_PRECERT_BEARER_TOKEN = 'legacy-precert-token';

  const service = new DgiiAuthService(
    {
      electronicDgiiTokenCache: {
        async findUnique() {
          return null;
        },
      },
    } as any,
    {} as any,
    {} as any,
    {} as any,
    {
      getEnvironmentConfig() {
        return {
          environment: 'precertification',
          submitUrl: 'https://precert.example.com/submit',
          resultUrlTemplate: 'https://precert.example.com/result/{trackId}',
          timeoutMs: 1000,
          maxRetries: 0,
          userAgent: 'FULLPOS-Test',
        };
      },
    } as any,
  );

  const token = await service.getCompanyBearerToken(1, 'precertification');

  assert.equal(token, 'legacy-precert-token');

});

test('DgiiAuthService debug auth maps DGII seed validation diagnostics without exposing token', async () => {
  const service = new DgiiAuthService(
    {
      electronicCertificate: {
        async findFirst() {
          return {
            status: 'ACTIVE',
            validFrom: new Date(Date.now() - 60_000),
            validTo: new Date(Date.now() + 60_000),
          };
        },
      },
    } as any,
    {
      async resolveCompanyOrThrow() {
        return { id: 4, rnc: '133080206', cloudCompanyId: 'fp-mnuoujbs-rmt12y', name: 'Fulltech, srl' };
      },
    } as any,
    {} as any,
    {} as any,
    {
      getEnvironmentConfig() {
        return {
          environment: 'precertification',
          authSeedUrl: 'https://dgii.example/semilla',
          authValidateUrl: 'https://dgii.example/validarsemilla',
          submitUrl: 'https://dgii.example/recepcion',
          resultUrlTemplate: 'https://dgii.example/result/{trackId}',
          timeoutMs: 1000,
          maxRetries: 0,
          userAgent: 'FULLPOS-Test',
        };
      },
    } as any,
  );

  service.getCompanyBearerTokenWithMeta = async () => {
    throw {
      status: 400,
      message: 'La estructura del archivo XML no es válido',
      errorCode: 'DGII_SEED_VALIDATE_BAD_REQUEST',
      details: {
        httpStatus: 400,
        payloadMode: 'multipart',
        fieldName: 'xml',
        requestContentType: 'multipart/form-data',
        raw: { errores: ["The 'Id' attribute is not declared."] },
        signedXmlRoot: 'SemillaModel',
        signedXmlHasSignature: true,
        signedXmlHasIdAttributeOnRoot: false,
        signatureReferenceUri: '',
        canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
        signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
        signedXmlSize: 3900,
      },
    };
  };

  const result = await service.debugAuthenticateByLocators({
    companyRnc: '133080206',
    companyCloudId: 'fp-mnuoujbs-rmt12y',
    environment: 'precertification',
    forceRefresh: true,
  });

  assert.equal(result.seedOk, true);
  assert.equal(result.signOk, true);
  assert.equal(result.validateOk, false);
  assert.equal(result.tokenFound, false);
  assert.equal(result.errorCode, 'DGII_SEED_VALIDATE_BAD_REQUEST');
  assert.equal(result.signedXmlRoot, 'SemillaModel');
  assert.equal(result.signedXmlHasSignature, true);
  assert.equal(result.signedXmlHasIdAttributeOnRoot, false);
  assert.equal(result.signatureReferenceUri, '');
  assert.equal(result.validatePayloadMode, 'multipart');
  assert.equal(result.validateFieldName, 'xml');
  assert.equal(result.validateContentType, 'multipart/form-data');
  assert.equal(Object.prototype.hasOwnProperty.call(result, 'token'), false);
  assert.equal(JSON.stringify(result).includes('full-token'), false);
});

test('DgiiAuthService debug auth success reports tokenFound without returning token value', async () => {
  const service = new DgiiAuthService(
    {
      electronicCertificate: {
        async findFirst() {
          return {
            status: 'ACTIVE',
            validFrom: new Date(Date.now() - 60_000),
            validTo: new Date(Date.now() + 60_000),
          };
        },
      },
    } as any,
    {
      async resolveCompanyOrThrow() {
        return { id: 4, rnc: '133080206', cloudCompanyId: 'fp-mnuoujbs-rmt12y', name: 'Fulltech, srl' };
      },
    } as any,
    {} as any,
    {} as any,
    {
      getEnvironmentConfig() {
        return {
          environment: 'precertification',
          authSeedUrl: 'https://dgii.example/semilla',
          authValidateUrl: 'https://dgii.example/validarsemilla',
          submitUrl: 'https://dgii.example/recepcion',
          resultUrlTemplate: 'https://dgii.example/result/{trackId}',
          timeoutMs: 1000,
          maxRetries: 0,
          userAgent: 'FULLPOS-Test',
        };
      },
    } as any,
  );

  service.getCompanyBearerTokenWithMeta = async () => ({
    token: 'full-token-value-that-must-not-leak',
    source: 'auto',
    meta: {
      signedXmlRoot: 'SemillaModel',
      signedXmlHasSignature: true,
      signedXmlHasIdAttributeOnRoot: false,
      signatureReferenceUri: '',
      canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
      signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
      digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
      payloadMode: 'multipart',
      fieldName: 'xml',
      requestContentType: 'multipart/form-data',
    },
  });

  const result = await service.debugAuthenticateByLocators({ companyRnc: '133080206' });

  assert.equal(result.validateOk, true);
  assert.equal(result.tokenFound, true);
  assert.equal(result.tokenSource, 'auto');
  assert.equal(result.signedXmlRoot, 'SemillaModel');
  assert.equal(result.signedXmlHasIdAttributeOnRoot, false);
  assert.equal(result.signatureReferenceUri, '');
  assert.equal(result.validatePayloadMode, 'multipart');
  assert.equal(Object.prototype.hasOwnProperty.call(result, 'token'), false);
  assert.equal(JSON.stringify(result).includes('full-token-value-that-must-not-leak'), false);
});
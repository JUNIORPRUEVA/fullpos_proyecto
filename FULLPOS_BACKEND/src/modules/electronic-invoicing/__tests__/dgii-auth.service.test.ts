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

  const service = new DgiiAuthService(prisma as any, mapper as any, {} as any, audit as any);
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

  const service = new DgiiAuthService(prisma as any, mapper as any, signatureService as any, { log: async () => undefined } as any);

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

  const service = new DgiiAuthService(prisma as any, {} as any, {} as any, {} as any);

  await assert.rejects(
    service.assertInboundToken(1, 0, undefined),
    (error: any) => error?.errorCode === 'FE_TOKEN_REQUIRED',
  );

  await assert.doesNotReject(service.assertInboundToken(1, 0, `Bearer ${validToken}`));
});
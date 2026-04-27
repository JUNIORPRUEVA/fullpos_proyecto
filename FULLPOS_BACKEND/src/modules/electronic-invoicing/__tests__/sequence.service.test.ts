import test from 'node:test';
import assert from 'node:assert/strict';
import { ensureFeTestEnv } from './test-helpers';

ensureFeTestEnv();

const { SequenceService } = require('../services/sequence.service');
const { createSequenceDtoSchema } = require('../dto/sequence.dto');

test('SequenceService allocates unique e-CF values on consecutive calls', async () => {
  const sequenceState = {
    id: 10,
    companyId: 1,
    branchId: 0,
    documentTypeCode: '31',
    prefix: 'E31',
    currentNumber: 0n,
    maxNumber: 9999999999n,
    status: 'ACTIVE',
  };
  const auditEvents: Array<{ eventType: string; payload?: unknown }> = [];

  const prisma = {
    electronicSequence: {
      async findUnique() {
        return { ...sequenceState };
      },
      async updateMany(input: { where: { currentNumber: bigint }; data: { currentNumber: bigint; maxNumber?: bigint; status: string } }) {
        if (input.where.currentNumber !== sequenceState.currentNumber || sequenceState.status !== 'ACTIVE') {
          return { count: 0 };
        }
        sequenceState.currentNumber = input.data.currentNumber;
        if (input.data.maxNumber != null) {
          sequenceState.maxNumber = input.data.maxNumber;
        }
        sequenceState.status = input.data.status;
        return { count: 1 };
      },
      async update(input: { data: { status: string } }) {
        sequenceState.status = input.data.status;
        return { ...sequenceState };
      },
    },
  };
  const audit = {
    async log(input: { eventType: string; payload?: unknown }) {
      auditEvents.push(input);
    },
  };

  const service = new SequenceService(prisma as any, audit as any);

  const first = await service.allocate(1, 0, '31', 'req-1');
  const second = await service.allocate(1, 0, '31', 'req-2');

  assert.equal(first.ecf, 'E310000000001');
  assert.equal(second.ecf, 'E310000000002');
  assert.notEqual(first.ecf, second.ecf);
  assert.equal(sequenceState.maxNumber, 9999999999n);
  assert.equal(auditEvents.length, 2);
});

test('SequenceService keeps range limit in allocation update to satisfy legacy currentNumber constraints', async () => {
  const sequenceState = {
    id: 2,
    companyId: 4,
    branchId: 0,
    documentTypeCode: '32',
    prefix: 'E32',
    currentNumber: 30n,
    maxNumber: 60n,
    status: 'ACTIVE',
  };
  let updateManyInput: any;
  const prisma = {
    electronicSequence: {
      async findUnique() {
        return { ...sequenceState };
      },
      async updateMany(input: any) {
        updateManyInput = input;
        sequenceState.currentNumber = input.data.currentNumber;
        sequenceState.maxNumber = input.data.maxNumber;
        sequenceState.status = input.data.status;
        return { count: 1 };
      },
      async update(input: { data: { status: string } }) {
        sequenceState.status = input.data.status;
        return { ...sequenceState };
      },
    },
  };
  const service = new SequenceService(prisma as any, { log: async () => undefined } as any);

  const allocated = await service.allocate(4, 0, '32', 'req-e32-allocate');

  assert.equal(allocated.ecf, 'E320000000031');
  assert.equal(updateManyInput.data.currentNumber, 31n);
  assert.equal(updateManyInput.data.maxNumber, 60n);
  assert.equal(updateManyInput.data.status, 'ACTIVE');
});

test('SequenceService maps currentNumber check constraint failures to constraint mismatch', async () => {
  const prisma = {
    electronicSequence: {
      async findUnique() {
        return {
          id: 2,
          companyId: 4,
          branchId: 0,
          documentTypeCode: '32',
          prefix: 'E32',
          currentNumber: 30n,
          maxNumber: 60n,
          status: 'ACTIVE',
        };
      },
      async updateMany() {
        throw new Error('new row for relation "ElectronicSequence" violates check constraint "ElectronicSequence_currentNumber_check"');
      },
      async update(input: { data: { status: string } }) {
        return input.data;
      },
    },
  };
  const service = new SequenceService(prisma as any, { log: async () => undefined } as any);

  await assert.rejects(
    service.allocate(4, 0, '32', 'req-e32-constraint'),
    (error: any) => error?.errorCode === 'ELECTRONIC_SEQUENCE_CONSTRAINT_MISMATCH' && error?.status === 503,
  );
});

test('SequenceService upserts sequence using endNumber as maxNumber and preserves existing currentNumber', async () => {
  const auditEvents: Array<{ eventType: string; payload?: any }> = [];
  const existing = {
    id: 2,
    companyId: 4,
    branchId: 0,
    documentTypeCode: '32',
    prefix: 'E32',
    currentNumber: 30n,
    maxNumber: 30n,
    status: 'EXHAUSTED',
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    updatedAt: new Date('2026-01-01T00:00:00.000Z'),
  };
  let upsertInput: any;
  const prisma = {
    electronicSequence: {
      async findUnique() {
        return { ...existing };
      },
      async upsert(input: any) {
        upsertInput = input;
        return {
          ...existing,
          prefix: input.update.prefix,
          currentNumber: input.update.currentNumber,
          maxNumber: input.update.maxNumber,
          status: input.update.status,
          updatedAt: new Date('2026-04-26T00:00:00.000Z'),
        };
      },
    },
  };
  const audit = {
    async log(input: { eventType: string; payload?: any }) {
      auditEvents.push(input);
    },
  };
  const dto = createSequenceDtoSchema.parse({
    branchId: 0,
    documentTypeCode: 32,
    prefix: 'E32',
    startNumber: 1,
    currentNumber: 0,
    endNumber: 100,
    status: 'active',
  });

  const service = new SequenceService(prisma as any, audit as any);
  const saved = await service.upsertSequence(4, dto, 'fullpos_pos', 'req-seq');

  assert.equal(upsertInput.update.maxNumber, 100n);
  assert.equal(upsertInput.update.currentNumber, 30n);
  assert.equal(upsertInput.update.status, 'ACTIVE');
  assert.equal(saved.companyId, 4);
  assert.equal(saved.documentTypeCode, '32');
  assert.equal(saved.prefix, 'E32');
  assert.equal(saved.currentNumber, 30);
  assert.equal(saved.endNumber, 100);
  assert.equal(saved.maxNumber, 100);
  assert.equal(saved.remaining, 70);
  assert.equal(auditEvents[0]?.payload.currentNumber, 30);
});

test('SequenceService rejects missing endNumber before Prisma upsert', async () => {
  let upsertCalled = false;
  const prisma = {
    electronicSequence: {
      async upsert() {
        upsertCalled = true;
        return {};
      },
    },
  };
  const service = new SequenceService(prisma as any, { log: async () => undefined } as any);
  const dto = createSequenceDtoSchema.parse({
    documentTypeCode: '32',
    prefix: 'E32',
    startNumber: 31,
    currentNumber: 30,
    status: 'ACTIVE',
  });

  await assert.rejects(
    service.upsertSequence(4, dto, 'fullpos_pos', 'req-missing-end'),
    (error: any) => error?.errorCode === 'SEQUENCE_END_NUMBER_REQUIRED' && error?.status === 400,
  );
  assert.equal(upsertCalled, false);
});

test('SequenceService accepts maxNumber fallback when endNumber is absent', async () => {
  let upsertInput: any;
  const prisma = {
    electronicSequence: {
      async findUnique() {
        return null;
      },
      async upsert(input: any) {
        upsertInput = input;
        return {
          id: 3,
          companyId: 4,
          branchId: 0,
          documentTypeCode: '34',
          prefix: 'E34',
          currentNumber: input.create.currentNumber,
          maxNumber: input.create.maxNumber,
          status: input.create.status,
          createdAt: new Date('2026-04-26T00:00:00.000Z'),
          updatedAt: new Date('2026-04-26T00:00:00.000Z'),
        };
      },
    },
  };
  const service = new SequenceService(prisma as any, { log: async () => undefined } as any);
  const dto = createSequenceDtoSchema.parse({
    documentTypeCode: '34',
    prefix: 'E34',
    startNumber: 1,
    currentNumber: 0,
    maxNumber: 60,
    status: 'ACTIVE',
  });

  const saved = await service.upsertSequence(4, dto, 'fullpos_pos', 'req-max-fallback');

  assert.equal(upsertInput.create.maxNumber, 60n);
  assert.equal(saved.endNumber, 60);
  assert.equal(saved.remaining, 60);
});

test('SequenceService maps schema mismatch errors to migration-required sequence error', async () => {
  const prisma = {
    electronicSequence: {
      async findUnique() {
        throw new Error('column "maxNumber" does not exist');
      },
    },
  };
  const service = new SequenceService(prisma as any, { log: async () => undefined } as any);
  const dto = createSequenceDtoSchema.parse({
    documentTypeCode: '31',
    prefix: 'E31',
    currentNumber: 0,
    endNumber: 100,
    status: 'ACTIVE',
  });

  await assert.rejects(
    service.upsertSequence(4, dto, 'fullpos_pos', 'req-mismatch'),
    (error: any) => error?.errorCode === 'ELECTRONIC_SEQUENCE_SCHEMA_MISMATCH' && error?.status === 503,
  );
});

test('SequenceService maps legacy endNumber null constraint to migration-required sequence error', async () => {
  const prisma = {
    electronicSequence: {
      async findUnique() {
        return null;
      },
      async upsert() {
        throw new Error('Null constraint violation on the fields: (`endNumber`)');
      },
    },
  };
  const service = new SequenceService(prisma as any, { log: async () => undefined } as any);
  const dto = createSequenceDtoSchema.parse({
    documentTypeCode: '32',
    prefix: 'E32',
    startNumber: 31,
    currentNumber: 30,
    endNumber: 60,
    status: 'ACTIVE',
  });

  await assert.rejects(
    service.upsertSequence(4, dto, 'fullpos_pos', 'req-legacy-endnumber'),
    (error: any) => error?.errorCode === 'ELECTRONIC_SEQUENCE_SCHEMA_MISMATCH' && error?.status === 503,
  );
});
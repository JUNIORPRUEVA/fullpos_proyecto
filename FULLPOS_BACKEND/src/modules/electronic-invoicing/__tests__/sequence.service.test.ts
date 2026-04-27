import test from 'node:test';
import assert from 'node:assert/strict';
import { ensureFeTestEnv } from './test-helpers';

ensureFeTestEnv();

const { SequenceService } = require('../services/sequence.service');

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
      async updateMany(input: { where: { currentNumber: bigint }; data: { currentNumber: bigint; status: string } }) {
        if (input.where.currentNumber !== sequenceState.currentNumber || sequenceState.status !== 'ACTIVE') {
          return { count: 0 };
        }
        sequenceState.currentNumber = input.data.currentNumber;
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
  assert.equal(auditEvents.length, 2);
});
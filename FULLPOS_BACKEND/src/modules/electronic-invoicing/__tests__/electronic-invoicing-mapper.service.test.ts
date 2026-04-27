import test from 'node:test';
import assert from 'node:assert/strict';
import { ElectronicInvoicingMapperService } from '../services/electronic-invoicing-mapper.service';
import { ensureFeTestEnv } from './test-helpers';

ensureFeTestEnv();

function createMapperWithConflictingCompanies() {
  const byCloud = {
    id: 4,
    name: 'FULLTECH cloud canonical',
    rnc: '133080206',
    cloudCompanyId: 'fp-mnuoujbs-rmt12y',
    isActive: true,
    config: null,
  };
  const byRnc = {
    id: 1,
    name: 'FULLTECH legacy duplicate',
    rnc: '133080206',
    cloudCompanyId: null,
    isActive: true,
    config: null,
  };

  const prisma = {
    company: {
      async findFirst(input: any) {
        if (input.where?.cloudCompanyId === 'fp-mnuoujbs-rmt12y') return byCloud;
        if (input.where?.rnc === '133080206') return byRnc;
        return null;
      },
    },
  };

  return new ElectronicInvoicingMapperService(prisma as any);
}

test('ElectronicInvoicingMapperService keeps strict locator conflict by default', async () => {
  const mapper = createMapperWithConflictingCompanies();

  await assert.rejects(
    mapper.resolveCompanyOrThrow('133080206', 'fp-mnuoujbs-rmt12y'),
    (error: any) => {
      assert.equal(error?.errorCode, 'COMPANY_LOCATOR_CONFLICT');
      assert.equal(error?.details?.cloudCompanyId, 4);
      assert.equal(error?.details?.rncCompanyId, 1);
      return true;
    },
  );
});

test('ElectronicInvoicingMapperService can prefer cloud company for POS by-rnc duplicate RNC conflicts', async () => {
  const mapper = createMapperWithConflictingCompanies();

  const company = await mapper.resolveCompanyOrThrow('133080206', 'fp-mnuoujbs-rmt12y', {
    preferCloudOnConflict: true,
    requestId: 'req-conflict',
    source: 'outbound_generate_by_rnc',
  });

  assert.equal(company.id, 4);
  assert.equal(company.cloudCompanyId, 'fp-mnuoujbs-rmt12y');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { prisma } from '../../../config/prisma';
import { resolveCompanyIdentity } from '../companyIdentity.service';

type CompanyStub = {
  id: number;
  name: string;
  rnc: string | null;
  cloudCompanyId: string | null;
  tenantKey: string | null;
  normalizedRnc: string | null;
  sourceBusinessId: string | null;
  primaryDeviceId: string | null;
  isActive: boolean;
};

const company = (partial: Partial<CompanyStub>): CompanyStub => ({
  id: partial.id ?? 1,
  name: partial.name ?? 'Empresa Prueba',
  rnc: partial.rnc ?? null,
  cloudCompanyId: partial.cloudCompanyId ?? null,
  tenantKey: partial.tenantKey ?? null,
  normalizedRnc: partial.normalizedRnc ?? null,
  sourceBusinessId: partial.sourceBusinessId ?? null,
  primaryDeviceId: partial.primaryDeviceId ?? null,
  isActive: partial.isActive ?? true,
});

async function withCompanyMock<T>(companyDelegate: any, run: () => Promise<T>) {
  const originalDescriptor = Object.getOwnPropertyDescriptor(prisma, 'company');
  Object.defineProperty(prisma, 'company', {
    configurable: true,
    value: companyDelegate,
  });
  try {
    return await run();
  } finally {
    if (originalDescriptor) {
      Object.defineProperty(prisma, 'company', originalDescriptor);
    }
  }
}

test('resolveCompanyIdentity resolves exact tenant key before legacy locators', async () => {
  const tenantCompany = company({
    id: 7,
    tenantKey: 'fullpos:133080206:biz-1:terminal-1',
    rnc: '133080206',
    normalizedRnc: '133080206',
  });
  const result = await withCompanyMock(
    {
      async findUnique(input: any) {
        if (input.where?.tenantKey === tenantCompany.tenantKey) return tenantCompany;
        return null;
      },
      async findFirst() {
        assert.fail('tenant match should avoid legacy cloud/RNC lookup');
      },
    },
    () =>
      resolveCompanyIdentity({
        companyTenantKey: tenantCompany.tenantKey!,
        companyRnc: '133080206',
        source: 'test.tenant',
      }),
  );

  assert.equal(result.id, 7);
  assert.equal(result.tenantKey, tenantCompany.tenantKey);
});

test('resolveCompanyIdentity links a safe legacy cloud company to a new tenant key', async () => {
  const legacyCompany = company({ id: 8, cloudCompanyId: 'cloud-8', rnc: '133080206', normalizedRnc: '133080206' });
  let updateInput: any = null;

  const result = await withCompanyMock(
    {
      async findUnique() {
        return null;
      },
      async findFirst(input: any) {
        if (input.where?.cloudCompanyId === 'cloud-8') return legacyCompany;
        return null;
      },
      async update(input: any) {
        updateInput = input;
        return company({
          ...legacyCompany,
          tenantKey: input.data.tenantKey,
          sourceBusinessId: input.data.sourceBusinessId,
          primaryDeviceId: input.data.primaryDeviceId,
        });
      },
    },
    () =>
      resolveCompanyIdentity({
        companyTenantKey: 'fullpos:133080206:biz-8:terminal-8',
        companyCloudId: 'cloud-8',
        companyRnc: '133080206',
        businessId: 'biz-8',
        terminalId: 'terminal-8',
        source: 'test.link',
      }),
  );

  assert.equal(result.id, 8);
  assert.equal(result.tenantKey, 'fullpos:133080206:biz-8:terminal-8');
  assert.equal(updateInput.where.id, 8);
  assert.equal(updateInput.data.tenantKey, 'fullpos:133080206:biz-8:terminal-8');
  assert.equal(updateInput.data.sourceBusinessId, 'biz-8');
  assert.equal(updateInput.data.primaryDeviceId, 'terminal-8');
});

test('resolveCompanyIdentity blocks ambiguous RNC-only duplicate routing', async () => {
  await withCompanyMock(
    {
      async findUnique() {
        return null;
      },
      async findFirst() {
        return null;
      },
      async findMany(input: any) {
        assert.equal(input.where?.normalizedRnc, '133080206');
        return [
          company({ id: 1, rnc: '133080206', normalizedRnc: '133080206' }),
          company({ id: 2, rnc: '133-080206', normalizedRnc: '133080206' }),
        ];
      },
    },
    async () => {
      await assert.rejects(
        resolveCompanyIdentity({ companyRnc: '133080206', source: 'test.ambiguous' }),
        (error: any) => {
          assert.equal(error?.status, 409);
          assert.equal(error?.errorCode, 'COMPANY_RNC_AMBIGUOUS');
          assert.equal(error?.details?.matches?.length, 2);
          return true;
        },
      );
    },
  );
});

test('resolveCompanyIdentity rejects cloud ID and tenant key conflicts', async () => {
  await withCompanyMock(
    {
      async findUnique() {
        return null;
      },
      async findFirst(input: any) {
        if (input.where?.cloudCompanyId === 'cloud-9') {
          return company({ id: 9, cloudCompanyId: 'cloud-9', tenantKey: 'fullpos:other' });
        }
        return null;
      },
    },
    async () => {
      await assert.rejects(
        resolveCompanyIdentity({
          companyTenantKey: 'fullpos:requested',
          companyCloudId: 'cloud-9',
          source: 'test.conflict',
        }),
        (error: any) => {
          assert.equal(error?.status, 409);
          assert.equal(error?.errorCode, 'COMPANY_TENANT_LOCATOR_CONFLICT');
          return true;
        },
      );
    },
  );
});

test('resolveCompanyIdentity creates a tenant company when provisioning is allowed', async () => {
  let createInput: any = null;

  const result = await withCompanyMock(
    {
      async findUnique() {
        return null;
      },
      async findFirst() {
        return null;
      },
      async findMany() {
        return [];
      },
      async create(input: any) {
        createInput = input;
        return company({ id: 10, ...input.data });
      },
    },
    () =>
      resolveCompanyIdentity({
        companyTenantKey: 'fullpos:133080206:biz-10:terminal-10',
        companyRnc: '133-080206',
        businessId: 'biz-10',
        terminalId: 'terminal-10',
        companyName: 'FULLTECH',
        allowCreate: true,
        source: 'test.create',
      }),
  );

  assert.equal(result.id, 10);
  assert.equal(result.tenantKey, 'fullpos:133080206:biz-10:terminal-10');
  assert.equal(result.normalizedRnc, '133080206');
  assert.equal(createInput.data.name, 'FULLTECH');
  assert.equal(createInput.data.rnc, '133-080206');
  assert.equal(createInput.data.sourceBusinessId, 'biz-10');
  assert.equal(createInput.data.primaryDeviceId, 'terminal-10');
});

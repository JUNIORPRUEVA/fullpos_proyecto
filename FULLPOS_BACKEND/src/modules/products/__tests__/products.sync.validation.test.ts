import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeSyncProductOperationsInput,
  syncProductOperationsSchema,
} from '../products.validation';

test('syncProductOperationsSchema accepts valid create payload with companyId and uploads image', () => {
  const parsed = syncProductOperationsSchema.parse(
    normalizeSyncProductOperationsInput({
      companyId: '7',
      operations: [
        {
          clientMutationId: 'product-10-1',
          localProductId: 10,
          operationType: 'upsert',
          baseVersion: 0,
          occurredAt: '2026-04-17T15:00:00.000Z',
          lastModifiedBy: 'fullpos_local',
          product: {
            businessId: 'fp-mm2jbu6o-u352j8',
            code: 'A-100',
            name: 'Producto Nuevo',
            price: 125.5,
            cost: 75,
            stock: 8,
            imageUrl: '/uploads/products/a-100.png',
            isActive: true,
          },
        },
      ],
    }),
  );

  assert.equal(parsed.companyId, 7);
  assert.equal(parsed.operations[0].product.imageUrl, '/uploads/products/a-100.png');
});

test('syncProductOperationsSchema accepts valid status update payload with companyCloudId fallback', () => {
  const parsed = syncProductOperationsSchema.parse(
    normalizeSyncProductOperationsInput({
      companyCloudId: 'fp-mm2jbu6o-u352j8',
      operations: [
        {
          serverProductId: 55,
          operationType: 'status',
          product: {
            isActive: false,
            imageUrl: 'C:\\Users\\pc\\Pictures\\temp.png',
          },
        },
      ],
    }),
  );

  assert.equal(parsed.companyCloudId, 'fp-mm2jbu6o-u352j8');
  assert.equal(parsed.operations[0].product.isActive, false);
  assert.equal(parsed.operations[0].product.imageUrl, undefined);
});

test('syncProductOperationsSchema accepts valid delete payload with companyRnc fallback', () => {
  const parsed = syncProductOperationsSchema.parse(
    normalizeSyncProductOperationsInput({
      companyRnc: '133080206',
      operations: [
        {
          localProductId: 22,
          operationType: 'delete',
          product: {
            deletedAt: '2026-04-17T15:10:00.000Z',
          },
        },
      ],
    }),
  );

  assert.equal(parsed.companyRnc, '133080206');
  assert.equal(parsed.operations[0].operationType, 'delete');
});

test('syncProductOperationsSchema rejects payload without company locator', () => {
  assert.throws(
    () =>
      syncProductOperationsSchema.parse(
        normalizeSyncProductOperationsInput({
          operations: [
            {
              localProductId: 1,
              operationType: 'delete',
              product: {},
            },
          ],
        }),
      ),
    /companyId, RNC o companyCloudId requerido/,
  );
});

test('syncProductOperationsSchema rejects stock operation without stock field', () => {
  assert.throws(
    () =>
      syncProductOperationsSchema.parse(
        normalizeSyncProductOperationsInput({
          companyId: 1,
          operations: [
            {
              localProductId: 10,
              operationType: 'stock',
              product: {
                code: 'A-100',
              },
            },
          ],
        }),
      ),
    /El stock es requerido para operationType=stock/,
  );
});

test('syncProductOperationsSchema rejects upsert without required commercial fields', () => {
  assert.throws(
    () =>
      syncProductOperationsSchema.parse(
        normalizeSyncProductOperationsInput({
          companyId: 1,
          operations: [
            {
              localProductId: 99,
              operationType: 'upsert',
              product: {
                code: 'A-100',
              },
            },
          ],
        }),
      ),
    /El nombre es requerido para upsert|El precio es requerido para upsert/,
  );
});

test('normalizeSyncProductOperationsInput converts uploads paths and strips empty fields', () => {
  const normalized = normalizeSyncProductOperationsInput({
    companyId: '5',
    companyRnc: '   ',
    operations: [
      {
        operationType: 'upsert',
        product: {
          code: '  P-1  ',
          name: '  Producto 1  ',
          price: 10,
          imageUrl: 'uploads/products/p-1.png',
          businessId: '   ',
        },
      },
    ],
  }) as any;

  assert.equal(normalized.companyRnc, undefined);
  assert.equal(normalized.operations[0].product.code, 'P-1');
  assert.equal(normalized.operations[0].product.name, 'Producto 1');
  assert.equal(normalized.operations[0].product.imageUrl, '/uploads/products/p-1.png');
  assert.equal(normalized.operations[0].product.businessId, undefined);
});
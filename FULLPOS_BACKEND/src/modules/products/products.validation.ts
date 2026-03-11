import { z } from 'zod';

export const listProductsSchema = z.object({
  page: z.coerce.number().int().positive().optional(),
  pageSize: z.coerce.number().int().positive().max(100).optional(),
  search: z.string().trim().max(100).optional(),
});

export const createProductSchema = z.object({
  code: z.string().trim().min(1, 'El codigo es requerido'),
  name: z.string().trim().min(1, 'El nombre es requerido'),
  description: z.string().trim().max(500).optional(),
  category: z.string().trim().max(120).optional().nullable(),
  price: z.coerce.number().nonnegative(),
  cost: z.coerce.number().nonnegative().optional().default(0),
  stock: z.coerce.number().nonnegative().default(0),
  imageUrl: z.string().url().optional(),
  isDemo: z.boolean().optional(),
});

export const updateProductSchema = createProductSchema.partial().extend({
  code: z.string().trim().min(1, 'El codigo es requerido').optional(),
  name: z.string().trim().min(1, 'El nombre es requerido').optional(),
  isActive: z.boolean().optional(),
});

export const productIdParamsSchema = z.object({
  id: z.coerce.number().int().positive(),
});

export const updateProductStockSchema = z.object({
  stock: z.coerce.number().nonnegative(),
});

const syncOperationProductSchema = z.object({
  businessId: z.string().trim().min(1).optional().nullable(),
  code: z.string().trim().min(1, 'El codigo es requerido'),
  name: z.string().trim().min(1, 'El nombre es requerido'),
  category: z.string().trim().max(120).optional().nullable(),
  price: z.coerce.number().nonnegative(),
  cost: z.coerce.number().nonnegative().optional().default(0),
  stock: z.coerce.number().nonnegative().optional().default(0),
  imageUrl: z.string().url().optional().nullable(),
  isActive: z.boolean().optional().default(true),
  deletedAt: z.string().datetime().optional().nullable(),
});

export const syncProductOperationsSchema = z
  .object({
    companyRnc: z.string().trim().min(3).optional(),
    companyCloudId: z.string().trim().min(6).optional(),
    operations: z
      .array(
        z.object({
          clientMutationId: z.string().trim().min(1).optional(),
          localProductId: z.coerce.number().int().positive().optional(),
          serverProductId: z.coerce.number().int().positive().optional(),
          operationType: z.enum(['upsert', 'delete', 'stock', 'status']),
          baseVersion: z.coerce.number().int().nonnegative().optional(),
          occurredAt: z.string().datetime().optional(),
          lastModifiedBy: z.string().trim().min(1).optional(),
          product: syncOperationProductSchema,
        }),
      )
      .min(1)
      .max(100),
  })
  .refine((data) => !!data.companyRnc || !!data.companyCloudId, {
    message: 'RNC o ID interno requerido',
    path: ['companyRnc'],
  });

export const syncProductsByRncSchema = z
  .object({
    companyRnc: z.string().trim().min(3).optional(),
    companyCloudId: z.string().trim().min(6).optional(),
    products: z
      .array(
        z.object({
          code: z.string().trim().min(1, 'El codigo es requerido'),
          name: z.string().trim().min(1, 'El nombre es requerido'),
          description: z.string().trim().max(500).optional(),
          category: z.string().trim().max(120).optional().nullable(),
          price: z.coerce.number().nonnegative(),
          cost: z.coerce.number().nonnegative().optional(),
          stock: z.coerce.number().nonnegative().optional(),
          imageUrl: z.string().url().optional().nullable(),
        }),
      )
      .max(2000)
      .default([]),
    deletedProducts: z.array(z.string().trim().min(1)).max(2000).default([]),
  })
  .refine((data) => !!data.companyRnc || !!data.companyCloudId, {
    message: 'RNC o ID interno requerido',
    path: ['companyRnc'],
  });

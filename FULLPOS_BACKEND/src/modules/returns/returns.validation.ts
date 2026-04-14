import { z } from 'zod';

const returnItemSchema = z.object({
  saleItemId: z.coerce.number().int().positive().optional().nullable(),
  productId: z.coerce.number().int().positive().optional().nullable(),
  description: z.string().trim().min(1).max(200),
  qty: z.coerce.number().positive(),
  price: z.coerce.number().nonnegative(),
  total: z.coerce.number().nonnegative().optional(),
});

export const createReturnSchema = z.object({
  originalSaleId: z.coerce.number().int().positive(),
  cashSessionId: z.coerce.number().int().positive().optional().nullable(),
  note: z.string().trim().max(500).optional().nullable(),
  returnItems: z.array(returnItemSchema).min(1).max(500),
});

export const listReturnsQuerySchema = z.object({
  from: z.string().datetime().optional(),
  to: z.string().datetime().optional(),
  originalSaleId: z.coerce.number().int().positive().optional(),
});

const syncReturnItemSchema = z.object({
  localId: z.coerce.number().int().positive().optional().nullable(),
  saleItemLocalId: z.coerce.number().int().positive().optional().nullable(),
  productCodeSnapshot: z.string().trim().max(100).optional().nullable(),
  description: z.string().trim().min(1).max(200),
  qty: z.coerce.number().positive(),
  price: z.coerce.number().nonnegative(),
  total: z.coerce.number().nonnegative().optional(),
});

export const syncReturnsByRncSchema = z
  .object({
    companyRnc: z.string().trim().min(3).optional(),
    companyCloudId: z.string().trim().min(6).optional(),
    returns: z
      .array(
        z.object({
          localId: z.coerce.number().int().positive(),
          originalSaleLocalCode: z.string().trim().min(3),
          returnSaleLocalCode: z.string().trim().min(3),
          sessionLocalId: z.coerce.number().int().positive().optional().nullable(),
          note: z.string().trim().max(500).optional().nullable(),
          createdAt: z.string().datetime(),
          items: z.array(syncReturnItemSchema).min(1).max(500),
        }),
      )
      .max(2000)
      .default([]),
  })
  .refine((data) => !!data.companyRnc || !!data.companyCloudId, {
    message: 'RNC o ID interno requerido',
    path: ['companyRnc'],
  });
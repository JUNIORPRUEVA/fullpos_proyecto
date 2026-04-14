import { z } from 'zod';

const paymentKindSchema = z.enum(['credit', 'layaway']);

export const createPaymentSchema = z.object({
  saleId: z.coerce.number().int().positive(),
  kind: paymentKindSchema,
  amount: z.coerce.number().positive(),
  method: z.string().trim().min(1).max(50),
  note: z.string().trim().max(500).optional().nullable(),
  sessionId: z.coerce.number().int().positive().optional().nullable(),
});

export const listPaymentsQuerySchema = z.object({
  from: z.string().datetime().optional(),
  to: z.string().datetime().optional(),
  saleId: z.coerce.number().int().positive().optional(),
  kind: paymentKindSchema.optional(),
  page: z.coerce.number().int().positive().optional(),
  pageSize: z.coerce.number().int().positive().max(200).optional(),
});

const syncPaymentSchema = z.object({
  localId: z.coerce.number().int().positive(),
  kind: paymentKindSchema,
  saleLocalCode: z.string().trim().min(3),
  sessionLocalId: z.coerce.number().int().positive().optional().nullable(),
  amount: z.coerce.number().positive(),
  method: z.string().trim().min(1).max(50),
  note: z.string().trim().max(500).optional().nullable(),
  createdAt: z.string().datetime(),
  totalDueSnapshot: z.coerce.number().nonnegative().optional().nullable(),
  totalPaidSnapshot: z.coerce.number().nonnegative().optional().nullable(),
  pendingAmountSnapshot: z.coerce.number().nonnegative().optional().nullable(),
  statusSnapshot: z.string().trim().max(50).optional().nullable(),
});

export const syncPaymentsByRncSchema = z
  .object({
    companyRnc: z.string().trim().min(3).optional(),
    companyCloudId: z.string().trim().min(6).optional(),
    payments: z.array(syncPaymentSchema).max(5000).default([]),
  })
  .refine((data) => !!data.companyRnc || !!data.companyCloudId, {
    message: 'RNC o ID interno requerido',
    path: ['companyRnc'],
  });
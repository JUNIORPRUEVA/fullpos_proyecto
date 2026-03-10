import { z } from 'zod';

export const syncSuppliersByRncSchema = z
  .object({
    companyRnc: z.string().trim().min(3).optional(),
    companyCloudId: z.string().trim().min(6).optional(),
    suppliers: z
      .array(
        z.object({
          localId: z.coerce.number().int().positive(),
          name: z.string().trim().min(1),
          phone: z.string().trim().optional().nullable(),
          note: z.string().trim().optional().nullable(),
          isActive: z.boolean().optional().default(true),
          createdAt: z.string().datetime().optional(),
          updatedAt: z.string().datetime(),
          deletedAt: z.string().datetime().optional().nullable(),
        }),
      )
      .max(3000)
      .default([]),
  })
  .refine((data) => !!data.companyRnc || !!data.companyCloudId, {
    message: 'RNC o ID interno requerido',
    path: ['companyRnc'],
  });

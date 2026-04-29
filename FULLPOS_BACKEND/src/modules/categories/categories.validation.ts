import { z } from 'zod';

export const syncCategoriesByRncSchema = z
  .object({
    companyRnc: z.string().trim().min(3).optional(),
    companyCloudId: z.string().trim().min(6).optional(),
    companyTenantKey: z.string().trim().min(6).optional(),
    businessId: z.string().trim().min(3).optional(),
    deviceId: z.string().trim().min(3).optional(),
    terminalId: z.string().trim().min(3).optional(),
    categories: z
      .array(
        z.object({
          localId: z.coerce.number().int().positive(),
          name: z.string().trim().min(1),
          isActive: z.boolean().optional().default(true),
          createdAt: z.string().datetime().optional(),
          updatedAt: z.string().datetime(),
          deletedAt: z.string().datetime().optional().nullable(),
        }),
      )
      .max(3000)
      .default([]),
  })
  .refine((data) => !!data.companyRnc || !!data.companyCloudId || !!data.companyTenantKey, {
    message: 'companyTenantKey, RNC o ID interno requerido',
    path: ['companyRnc'],
  });

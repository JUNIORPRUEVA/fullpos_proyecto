import { z } from 'zod';

export const syncClientsByRncSchema = z
  .object({
    companyRnc: z.string().trim().min(3).optional(),
    companyCloudId: z.string().trim().min(6).optional(),
    companyTenantKey: z.string().trim().min(6).optional(),
    businessId: z.string().trim().min(3).optional(),
    deviceId: z.string().trim().min(3).optional(),
    terminalId: z.string().trim().min(3).optional(),
    clients: z
      .array(
        z.object({
          localId: z.coerce.number().int().positive(),
          nombre: z.string().trim().min(1),
          telefono: z.string().trim().optional().nullable(),
          direccion: z.string().trim().optional().nullable(),
          rnc: z.string().trim().optional().nullable(),
          cedula: z.string().trim().optional().nullable(),
          isActive: z.boolean().optional().default(true),
          hasCredit: z.boolean().optional().default(false),
          createdAt: z.string().datetime().optional(),
          updatedAt: z.string().datetime(),
          deletedAt: z.string().datetime().optional().nullable(),
        }),
      )
      .max(5000)
      .default([]),
  })
  .refine((data) => !!data.companyRnc || !!data.companyCloudId || !!data.companyTenantKey, {
    message: 'companyTenantKey, RNC o ID interno requerido',
    path: ['companyRnc'],
  });

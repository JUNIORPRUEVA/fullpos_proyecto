import { z } from 'zod';

export const loginSchema = z.object({
  identifier: z.string().min(3, 'Usuario o correo requerido'),
  password: z.string().min(4, 'Contrase\u00f1a requerida'),
});

export const refreshSchema = z.object({
  refreshToken: z.string().min(10, 'Token requerido'),
});

export const provisionOwnerSchema = z
  .object({
    companyRnc: z.string().min(3).optional(),
    companyCloudId: z.string().min(6).optional(),
    companyName: z.string().min(2, 'Nombre de empresa requerido').optional(),
    username: z.string().min(3, 'Usuario requerido'),
    password: z.string().min(6, 'Contrase\u00f1a m\u00ednima 6 caracteres'),
  })
  .refine((data) => !!data.companyRnc || !!data.companyCloudId, {
    message: 'RNC o ID interno requerido',
    path: ['companyRnc'],
  });

export const provisionUserSchema = z
  .object({
    companyRnc: z.string().min(3).optional(),
    companyCloudId: z.string().min(6).optional(),
    companyName: z.string().min(2, 'Nombre de empresa requerido').optional(),
    username: z.string().min(3, 'Usuario requerido'),
    password: z.string().min(6, 'Contrase\u00f1a m\u00ednima 6 caracteres'),
    role: z.string().optional(),
  })
  .refine((data) => !!data.companyRnc || !!data.companyCloudId, {
    message: 'RNC o ID interno requerido',
    path: ['companyRnc'],
  });

export const syncUsersSchema = z
  .object({
    companyRnc: z.string().min(3).optional(),
    companyCloudId: z.string().min(6).optional(),
    companyName: z.string().min(2).optional(),
    users: z
      .array(
        z.object({
          username: z.string().min(3),
          email: z.string().email().optional(),
          displayName: z.string().min(2).optional(),
          role: z.string().min(3).optional(),
          isActive: z.boolean().optional(),
        }),
      )
      .min(1)
      .max(500),
  })
  .refine((data) => !!data.companyRnc || !!data.companyCloudId, {
    message: 'RNC o ID interno requerido',
    path: ['companyRnc'],
  });

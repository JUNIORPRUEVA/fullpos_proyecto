import { z } from 'zod';

export const loginSchema = z.object({
  identifier: z.string().min(3, 'Usuario o correo requerido'),
  password: z.string().min(4, 'Contrase\u00f1a requerida'),
});

export const refreshSchema = z.object({
  refreshToken: z.string().min(10, 'Token requerido'),
});

export const provisionOwnerSchema = z.object({
  companyRnc: z.string().min(3, 'RNC requerido'),
  username: z.string().min(3, 'Usuario requerido'),
  password: z.string().min(6, 'Contrase\u00f1a m\u00ednima 6 caracteres'),
});

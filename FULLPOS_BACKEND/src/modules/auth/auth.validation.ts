import { z } from 'zod';

export const loginSchema = z.object({
  identifier: z.string().min(3, 'Usuario o correo requerido'),
  password: z.string().min(4, 'Contrase\u00f1a requerida'),
});

export const refreshSchema = z.object({
  refreshToken: z.string().min(10, 'Token requerido'),
});

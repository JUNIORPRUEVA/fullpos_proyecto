import { z } from 'zod';

export const createCertificateDtoSchema = z
  .object({
    alias: z.string().trim().min(2).max(100),
    filePath: z.string().trim().min(3).optional(),
    secretReference: z.string().trim().min(3).optional(),
    password: z.string().min(1),
  })
  .refine((data) => !!data.filePath || !!data.secretReference, {
    message: 'filePath o secretReference requerido',
    path: ['filePath'],
  });

export type CreateCertificateDto = z.infer<typeof createCertificateDtoSchema>;
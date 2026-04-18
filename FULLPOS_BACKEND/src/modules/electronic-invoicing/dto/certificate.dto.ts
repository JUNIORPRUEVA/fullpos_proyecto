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

export const createCertificateUploadBodySchema = z.object({
  alias: z.string().trim().min(2).max(100),
  password: z.string().min(1),
  companyId: z.coerce.number().int().positive().optional(),
  companyRnc: z.string().trim().min(1).optional(),
  companyCloudId: z.string().trim().min(1).optional(),
  uploadedBy: z.string().trim().min(1).optional(),
});

export type CreateCertificateDto = z.infer<typeof createCertificateDtoSchema>;
export type CreateCertificateUploadBodyDto = z.infer<typeof createCertificateUploadBodySchema>;

export type RegisterCertificateDto = {
  alias: string;
  password: string;
  filePath?: string;
  secretReference?: string;
  certificateBuffer?: Buffer;
  originalName?: string;
  mimeType?: string;
  companyId?: number;
  companyRnc?: string;
  companyCloudId?: string;
  uploadedBy?: string;
};
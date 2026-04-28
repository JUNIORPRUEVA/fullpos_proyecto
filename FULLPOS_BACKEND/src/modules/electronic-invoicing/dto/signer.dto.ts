import { z } from 'zod';

function normalizeDocumentNumber(value: unknown) {
  if (value == null) return '';
  return String(value).trim().replace(/[\s-]+/g, '');
}

export const signerDocumentTypeSchema = z.enum(['CEDULA', 'PASSPORT', 'RNC', 'OTHER']);

export const signerByRncQuerySchema = z.object({
  companyRnc: z.string().trim().min(3),
  companyCloudId: z.string().trim().min(6).optional(),
});

export const upsertSignerByRncSchema = z.object({
  companyRnc: z.string().trim().min(3),
  companyCloudId: z.string().trim().min(6).optional(),
  signerFullName: z.string().trim().min(1),
  signerDocumentType: signerDocumentTypeSchema,
  signerDocumentNumber: z.preprocess(normalizeDocumentNumber, z.string().trim().min(1)),
  signerAuthorizedForDgii: z.coerce.boolean().optional().default(false),
});

export type UpsertSignerByRncDto = z.infer<typeof upsertSignerByRncSchema>;

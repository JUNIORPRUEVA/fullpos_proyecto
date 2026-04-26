import { z } from 'zod';

export const sendEcfDtoSchema = z.object({
  invoiceId: z.coerce.number().int().positive(),
  force: z.coerce.boolean().optional().default(false),
  dgiiManualToken: z.string().trim().min(1).optional(),
});

export type SendEcfDto = z.infer<typeof sendEcfDtoSchema>;
import { z } from 'zod';

export const sendEcfDtoSchema = z.object({
  invoiceId: z.coerce.number().int().positive(),
  force: z.coerce.boolean().optional().default(false),
});

export type SendEcfDto = z.infer<typeof sendEcfDtoSchema>;
import { z } from 'zod';

export const createEcfDtoSchema = z.object({
  saleId: z.coerce.number().int().positive(),
  documentTypeCode: z.enum(['31', '32']),
  branchId: z.coerce.number().int().min(0).optional().default(0),
});

export type CreateEcfDto = z.infer<typeof createEcfDtoSchema>;
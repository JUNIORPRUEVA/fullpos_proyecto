import { z } from 'zod';

export const createSequenceDtoSchema = z.object({
  branchId: z.coerce.number().int().min(0).optional().default(0),
  documentTypeCode: z.enum(['31', '32', '33', '34', '41', '43', '44', '45']),
  currentNumber: z.coerce.number().int().min(0).optional().default(0),
  maxNumber: z.coerce.number().int().positive(),
  status: z.enum(['ACTIVE', 'PAUSED', 'EXHAUSTED', 'INACTIVE']).optional().default('ACTIVE'),
});

export type CreateSequenceDto = z.infer<typeof createSequenceDtoSchema>;
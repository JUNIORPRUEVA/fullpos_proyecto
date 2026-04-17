import { z } from 'zod';

export const createCreditNoteDtoSchema = z.object({
  originalInvoiceId: z.coerce.number().int().positive(),
  saleId: z.coerce.number().int().positive(),
  branchId: z.coerce.number().int().min(0).optional().default(0),
  reason: z.string().trim().min(3).max(500),
});

export type CreateCreditNoteDto = z.infer<typeof createCreditNoteDtoSchema>;
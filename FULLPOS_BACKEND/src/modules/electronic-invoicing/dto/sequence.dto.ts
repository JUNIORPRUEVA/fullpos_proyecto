import { z } from 'zod';

const documentTypeCodeSchema = z.preprocess(
  (value) => String(value ?? '').trim(),
  z.enum(['31', '32', '34']),
);

const sequenceStatusSchema = z.preprocess(
  (value) => String(value ?? 'ACTIVE').trim().toUpperCase(),
  z.enum(['ACTIVE', 'PAUSED', 'EXHAUSTED', 'INACTIVE']),
);

export const createSequenceDtoSchema = z.object({
  branchId: z.coerce.number().int().min(0).optional().default(0),
  documentTypeCode: documentTypeCodeSchema,
  prefix: z.string().trim().optional(),
  startNumber: z.coerce.number().int().min(1).optional().default(1),
  currentNumber: z.coerce.number().int().min(0).optional().default(0),
  maxNumber: z.coerce.number().int().positive().optional(),
  endNumber: z.coerce.number().int().positive().optional(),
  status: sequenceStatusSchema.optional().default('ACTIVE'),
}).superRefine((data, ctx) => {
  const expectedPrefix = `E${data.documentTypeCode}`;
  if (data.prefix != null && data.prefix.trim().toUpperCase() !== expectedPrefix) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['prefix'],
      message: `El prefijo debe ser ${expectedPrefix}`,
    });
  }

  const endNumber = data.endNumber ?? data.maxNumber;
  if (endNumber == null) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['endNumber'],
      message: 'El límite autorizado es requerido',
    });
    return;
  }
  if (endNumber <= data.currentNumber) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['endNumber'],
      message: 'El límite autorizado debe ser mayor que la secuencia actual',
    });
  }
  if (endNumber < data.startNumber) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['endNumber'],
      message: 'El límite autorizado no puede ser menor al inicio',
    });
  }
});

export type CreateSequenceDto = z.infer<typeof createSequenceDtoSchema>;
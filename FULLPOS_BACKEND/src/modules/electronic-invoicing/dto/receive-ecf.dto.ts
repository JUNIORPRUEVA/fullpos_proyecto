import { z } from 'zod';

export const receiveEcfDtoSchema = z
  .object({
    companyRnc: z.string().trim().min(9).optional(),
    companyCloudId: z.string().trim().min(6).optional(),
    xml: z.string().trim().min(20).optional(),
  })
  .refine((data) => !!data.xml, {
    message: 'XML requerido',
    path: ['xml'],
  });

export type ReceiveEcfDto = z.infer<typeof receiveEcfDtoSchema>;
import { z } from 'zod';

export const commercialApprovalDtoSchema = z
  .object({
    companyRnc: z.string().trim().min(9).optional(),
    companyCloudId: z.string().trim().min(6).optional(),
    ecf: z.string().trim().min(13).optional(),
    approved: z.coerce.boolean().optional(),
    reason: z.string().trim().max(500).optional().nullable(),
    xml: z.string().trim().optional(),
  })
  .refine((data) => !!data.ecf || !!data.xml, {
    message: 'e-CF o XML requerido',
    path: ['ecf'],
  });

export type CommercialApprovalDto = z.infer<typeof commercialApprovalDtoSchema>;
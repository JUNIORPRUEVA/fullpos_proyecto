import { z } from 'zod';

export const requestSeedDtoSchema = z
  .object({
    companyRnc: z.string().trim().min(9).optional(),
    companyCloudId: z.string().trim().min(6).optional(),
    branchId: z.coerce.number().int().min(0).optional().default(0),
  })
  .refine((data) => !!data.companyRnc || !!data.companyCloudId, {
    message: 'RNC o companyCloudId requerido',
    path: ['companyRnc'],
  });

export const validateSeedDtoSchema = z
  .object({
    companyRnc: z.string().trim().min(9).optional(),
    companyCloudId: z.string().trim().min(6).optional(),
    branchId: z.coerce.number().int().min(0).optional().default(0),
    signedSeedXml: z.string().trim().min(20),
  })
  .refine((data) => !!data.companyRnc || !!data.companyCloudId, {
    message: 'RNC o companyCloudId requerido',
    path: ['companyRnc'],
  });

export type RequestSeedDto = z.infer<typeof requestSeedDtoSchema>;
export type ValidateSeedDto = z.infer<typeof validateSeedDtoSchema>;
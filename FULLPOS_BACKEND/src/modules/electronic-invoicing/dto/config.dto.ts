import { z } from 'zod';
import { normalizeDgiiEnvironmentAlias } from '../../../config/env';

export const upsertElectronicConfigDtoSchema = z.object({
  branchId: z.coerce.number().int().min(0).optional().default(0),
  authEnabled: z.coerce.boolean().optional().default(true),
  authPath: z.string().trim().min(1).optional().default('/fe/autenticacion/api/semilla'),
  receptionPath: z.string().trim().min(1).optional().default('/fe/recepcion/api/ecf'),
  approvalPath: z.string().trim().min(1).optional().default('/fe/aprobacioncomercial/api/ecf'),
  publicBaseUrl: z.string().trim().url(),
  active: z.coerce.boolean().optional().default(true),
  outboundEnabled: z.coerce.boolean().optional().default(false),
  environment: z.preprocess(normalizeDgiiEnvironmentAlias, z.enum(['precertification', 'production'])).optional().default('precertification'),
  tokenTtlSeconds: z.coerce.number().int().min(30).max(86400).optional().default(300),
});

export type UpsertElectronicConfigDto = z.infer<typeof upsertElectronicConfigDtoSchema>;
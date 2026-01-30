import { z } from 'zod';

export const requestSchema = z.object({
  // Preferido (cloud)
  cloudCompanyId: z.string().min(3).optional(),
  // Back-compat
  companyId: z.number().int().positive().optional(),
  companyRnc: z.string().min(3).optional(),
  companyCloudId: z.string().min(3).optional(),
  actionCode: z.string().min(3),
  resourceType: z.string().optional(),
  resourceId: z.string().optional(),
  // Preferido (cloud)
  cloudUserId: z.number().int().positive().optional(),
  // Back-compat (a veces viene localId)
  requestedById: z.number().int().positive().optional(),
  userUsername: z.string().min(3).optional(),
  userEmail: z.string().email().optional(),
  terminalId: z.string().optional(),
  cloudTerminalId: z.union([z.number().int().positive(), z.string().min(3)]).optional(),
  meta: z.record(z.any()).optional(),
})
  .refine((v) => Boolean(v.cloudCompanyId || v.companyId || v.companyRnc || v.companyCloudId), {
    message: 'cloudCompanyId, companyId, companyRnc o companyCloudId requerido',
    path: ['cloudCompanyId'],
  })
  .refine((v) => Boolean(v.cloudUserId || v.requestedById || v.userUsername || v.userEmail), {
    message: 'cloudUserId, requestedById, userUsername o userEmail requerido',
    path: ['cloudUserId'],
  });

export const approveSchema = z.object({
  requestId: z.number().int().positive(),
  expiresInSeconds: z.number().int().min(30).max(600).optional(),
});

// Aprobar sin generar token (flujo "en vivo" / sin que el cajero escriba token).
export const approveDirectSchema = z.object({
  requestId: z.number().int().positive(),
});

// Consumir una solicitud ya aprobada (sin token), para que el POS pueda continuar.
export const consumeRequestSchema = z
  .object({
    requestId: z.number().int().positive(),
    // Identidad empresa
    cloudCompanyId: z.string().min(3).optional(),
    companyId: z.number().int().positive().optional(),
    companyRnc: z.string().min(3).optional(),
    companyCloudId: z.string().min(3).optional(),

    // Acción esperada (para evitar reutilizar el mismo request en otra cosa)
    actionCode: z.string().min(3),
    resourceType: z.string().optional(),
    resourceId: z.string().optional(),

    // Usuario (debe coincidir con requestedById del request)
    cloudUserId: z.number().int().positive().optional(),
    usedById: z.number().int().positive().optional(),
    userUsername: z.string().min(3).optional(),
    userEmail: z.string().email().optional(),

    // Terminal
    terminalId: z.string().optional(),
    cloudTerminalId: z.union([z.number().int().positive(), z.string().min(3)]).optional(),

    meta: z.record(z.any()).optional(),
  })
  .refine((v) => Boolean(v.cloudCompanyId || v.companyId || v.companyRnc || v.companyCloudId), {
    message: 'cloudCompanyId, companyId, companyRnc o companyCloudId requerido',
    path: ['cloudCompanyId'],
  })
  .refine((v) => Boolean(v.cloudUserId || v.usedById || v.userUsername || v.userEmail), {
    message: 'cloudUserId, usedById, userUsername o userEmail requerido',
    path: ['cloudUserId'],
  });

export const verifySchema = z
  .object({
    // Preferido (cloud)
    cloudCompanyId: z.string().min(3).optional(),
    cloudUserId: z.number().int().positive().optional(),
    cloudTerminalId: z.union([z.number().int().positive(), z.string().min(3)]).optional(),
    // Back-compat
    companyId: z.number().int().positive().optional(),
    companyRnc: z.string().min(3).optional(),
    companyCloudId: z.string().min(3).optional(),
    token: z.string().min(4),
    actionCode: z.string().min(3),
    resourceType: z.string().optional(),
    resourceId: z.string().optional(),
    usedById: z.number().int().positive().optional(),
    userUsername: z.string().min(3).optional(),
    userEmail: z.string().email().optional(),
    terminalId: z.string().optional(),
    meta: z.record(z.any()).optional(),
  })
  .refine((v) => Boolean(v.cloudCompanyId || v.companyId || v.companyRnc || v.companyCloudId), {
    message: 'cloudCompanyId, companyId, companyRnc o companyCloudId requerido',
    path: ['cloudCompanyId'],
  })
  .refine((v) => Boolean(v.cloudUserId || v.usedById || v.userUsername || v.userEmail), {
    message: 'cloudUserId, usedById, userUsername o userEmail requerido',
    path: ['cloudUserId'],
  });

export const resolveIdsSchema = z
  .object({
    cloudCompanyId: z.string().min(3).optional(),
    companyId: z.number().int().positive().optional(),
    companyRnc: z.string().min(3).optional(),
    companyCloudId: z.string().min(3).optional(),
    cloudUserId: z.number().int().positive().optional(),
    userIdCandidate: z.number().int().positive().optional(),
    userUsername: z.string().min(3).optional(),
    userEmail: z.string().email().optional(),
    cloudTerminalId: z.union([z.number().int().positive(), z.string().min(3)]).optional(),
    terminalId: z.string().min(3).optional(),
  })
  .refine((v) => Boolean(v.cloudCompanyId || v.companyId || v.companyRnc || v.companyCloudId), {
    message: 'cloudCompanyId, companyId, companyRnc o companyCloudId requerido',
    path: ['cloudCompanyId'],
  });

export const virtualProvisionSchema = z.object({
  terminalId: z.string().min(3),
  uid: z.string().min(6).optional(),
});

export const auditQuerySchema = z.object({
  companyId: z.coerce.number().int().positive().optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
});

export const requestsQuerySchema = z.object({
  companyId: z.coerce.number().int().positive().optional(),
  status: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
});

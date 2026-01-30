import crypto from 'crypto';
import { Prisma } from '@prisma/client';
import { prisma } from '../../config/prisma';
import env from '../../config/env';

const DEFAULT_TTL_SECONDS = 180;
const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function hashToken(token: string) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

type ApiError = {
  status: number;
  message: string;
  errorCode: string;
  details?: Record<string, unknown>;
};

function apiError(
  errorCode: string,
  message: string,
  status = 400,
  details?: Record<string, unknown>,
): ApiError {
  return { status, message, errorCode, details };
}

function tokenHashPrefix(hash: string | null | undefined) {
  if (!hash) return 'null';
  return hash.slice(0, 10);
}

function logOverride(level: 'info' | 'warn' | 'error', message: string, meta?: any) {
  // En prod: info/warn sin stack; stack solo en debug.
  const isProd = env.NODE_ENV === 'production';
  const line = meta ? `${message} ${JSON.stringify(meta)}` : message;
  if (level === 'error') {
    if (isProd) console.warn(line);
    else console.error(line);
    return;
  }
  if (level === 'warn') {
    console.warn(line);
    return;
  }
  console.info(line);
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf: Buffer) {
  let bits = 0;
  let value = 0;
  let output = '';

  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

function normalizeRnc(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

async function resolveCompanyIdForOverride(input: {
  companyId?: number;
  companyRnc?: string;
  companyCloudId?: string;
}) {
  if (input.companyId) {
    const company = await prisma.company.findUnique({
      where: { id: input.companyId },
      select: { id: true },
    });
    if (company) return company.id;

    const asCloudId = String(input.companyId);
    const byCloud = await prisma.company.findFirst({
      where: { cloudCompanyId: asCloudId },
      select: { id: true },
    });
    if (byCloud) return byCloud.id;
  }

  const cloudId = input.companyCloudId?.trim() ?? '';
  if (cloudId) {
    const company = await prisma.company.findFirst({
      where: { cloudCompanyId: cloudId },
      select: { id: true, rnc: true },
    });
    if (company) return company.id;
  }

  const rnc = input.companyRnc?.trim() ?? '';
  if (rnc) {
    let company = await prisma.company.findFirst({
      where: { rnc },
      select: { id: true, rnc: true },
    });

    if (!company) {
      const normalized = normalizeRnc(rnc);
      if (normalized.length > 0) {
        const candidates = await prisma.company.findMany({
          where: { rnc: { not: null } },
          select: { id: true, rnc: true },
        });
        company =
          candidates.find(
            (item) => item.rnc != null && normalizeRnc(item.rnc) === normalized,
          ) ?? null;
      }
    }

    if (company) return company.id;
  }

  throw apiError('OVERRIDE_COMPANY_NOT_FOUND', 'Datos no válidos (empresa no registrada en la nube)', 400, {
    companyId: input.companyId ?? null,
    companyRnc: input.companyRnc ?? null,
    companyCloudId: input.companyCloudId ?? null,
  });
}

async function resolveCloudUserIdForOverride(input: {
  companyId: number;
  cloudUserId?: number;
  // Back-compat: algunos clientes mandan usedById/requestedById pero a veces es localId.
  userIdCandidate?: number;
  userUsername?: string;
  userEmail?: string;
}) {
  const idCandidates = [input.cloudUserId, input.userIdCandidate].filter(
    (v): v is number => typeof v === 'number' && Number.isInteger(v) && v > 0,
  );

  for (const id of idCandidates) {
    const user = await prisma.user.findFirst({
      where: { id, companyId: input.companyId, isActive: true },
      select: { id: true },
    });
    if (user) return user.id;
  }

  const email = input.userEmail?.trim().toLowerCase() ?? '';
  const username = input.userUsername?.trim() ?? '';

  if (email || username) {
    const user = await prisma.user.findFirst({
      where: {
        companyId: input.companyId,
        isActive: true,
        OR: [
          email ? { email } : undefined,
          username ? { username } : undefined,
        ].filter(Boolean) as any,
      },
      select: { id: true },
    });
    if (user) return user.id;
  }

  if (idCandidates.length > 0) {
    throw apiError(
      'OVERRIDE_USER_NOT_FOUND',
      `Datos no válidos (usuario no registrado en la nube): id=${idCandidates[0]}`,
      400,
      { companyId: input.companyId, providedIds: idCandidates, userEmail: email || null, userUsername: username || null },
    );
  }

  throw apiError(
    'OVERRIDE_USER_NOT_FOUND',
    'Datos no válidos (usuario no registrado en la nube)',
    400,
    { companyId: input.companyId, userEmail: email || null, userUsername: username || null },
  );
}

async function resolveTerminalDeviceIdForOverride(input: {
  companyId: number;
  cloudTerminalId?: number | string;
  terminalId?: string;
  required?: boolean;
}) {
  const raw = input.cloudTerminalId ?? input.terminalId;
  if (raw == null || raw === '') {
    if (input.required) {
      throw apiError('OVERRIDE_TERMINAL_REQUIRED', 'Datos no válidos (terminal no registrada en la nube)', 400, {
        companyId: input.companyId,
      });
    }
    return null;
  }

  if (typeof raw === 'number') {
    const terminal = await prisma.terminal.findFirst({
      where: { id: raw, companyId: input.companyId, isActive: true },
      select: { deviceId: true },
    });
    if (!terminal) {
      throw apiError(
        'OVERRIDE_TERMINAL_NOT_FOUND',
        `Datos no válidos (terminal no registrada en la nube): id=${raw}`,
        400,
        { companyId: input.companyId, providedTerminalId: raw },
      );
    }
    return terminal.deviceId;
  }

  const terminalKey = String(raw).trim();
  if (!terminalKey) {
    if (input.required) {
      throw apiError('OVERRIDE_TERMINAL_REQUIRED', 'Datos no válidos (terminal no registrada en la nube)', 400, {
        companyId: input.companyId,
      });
    }
    return null;
  }

  // Si viene numérico como string, intentar por id primero.
  if (/^\d+$/.test(terminalKey)) {
    const asId = Number(terminalKey);
    if (Number.isSafeInteger(asId)) {
      const byId = await prisma.terminal.findFirst({
        where: { id: asId, companyId: input.companyId, isActive: true },
        select: { deviceId: true },
      });
      if (byId) return byId.deviceId;
    }
  }

  const terminal = await prisma.terminal.findFirst({
    where: { deviceId: terminalKey, companyId: input.companyId, isActive: true },
    select: { deviceId: true },
  });
  if (terminal) return terminal.deviceId;

  // Auto-registrar la terminal en la nube (solo rutas protegidas por overrideKeyGuard).
  // Evita bloquear operaciones por primera vez en un equipo nuevo.
  const existingByDevice = await prisma.terminal.findFirst({
    where: { deviceId: terminalKey },
    select: { companyId: true, deviceId: true },
  });
  if (existingByDevice && existingByDevice.companyId !== input.companyId) {
    throw apiError(
      'OVERRIDE_TERMINAL_CONFLICT',
      `Datos no válidos (terminal pertenece a otra empresa): deviceId=${terminalKey}`,
      400,
      {
        companyId: input.companyId,
        providedTerminalId: terminalKey,
        existingCompanyId: existingByDevice.companyId,
      },
    );
  }

  try {
    const created = await prisma.terminal.create({
      data: {
        companyId: input.companyId,
        deviceId: terminalKey,
        isActive: true,
      },
      select: { deviceId: true },
    });
    return created.deviceId;
  } catch (err: any) {
    // Concurrencia: otra petición la creó.
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
      const created = await prisma.terminal.findFirst({
        where: { deviceId: terminalKey, companyId: input.companyId },
        select: { deviceId: true },
      });
      if (created) return created.deviceId;
    }
    throw err;
  }
}

function randomToken(length: number) {
  return Array.from({ length }, () => alphabet[Math.floor(Math.random() * alphabet.length)]).join(
    '',
  );
}

const VIRTUAL_PERIOD_SECONDS = 30;
const VIRTUAL_DIGITS = 6;

function virtualTokenEnabled() {
  return Boolean(env.VIRTUAL_TOKEN_MASTER_KEY?.trim());
}

function virtualSecretFor(companyId: number, terminalId: string) {
  const masterKey = env.VIRTUAL_TOKEN_MASTER_KEY?.trim();
  if (!masterKey) {
    throw { status: 400, message: 'Token virtual no está habilitado en el servidor.' };
  }

  const h = crypto
    .createHmac('sha256', masterKey)
    .update(`${companyId}|${terminalId}`)
    .digest();

  // 160-bit secret, típico para TOTP (SHA1).
  return h.subarray(0, 20);
}

function totpAt({
  secret,
  timeMs,
  periodSeconds = VIRTUAL_PERIOD_SECONDS,
  digits = VIRTUAL_DIGITS,
}: {
  secret: Buffer;
  timeMs: number;
  periodSeconds?: number;
  digits?: number;
}) {
  const counter = Math.floor(timeMs / 1000 / periodSeconds);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));

  const hmac = crypto.createHmac('sha1', secret).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary = (hmac.readUInt32BE(offset) & 0x7fffffff) >>> 0;
  const mod = 10 ** digits;
  const code = String(binary % mod).padStart(digits, '0');

  return { code, counter };
}

function verifyTotp({
  secret,
  token,
  timeMs,
  window = 1,
}: {
  secret: Buffer;
  token: string;
  timeMs: number;
  window?: number;
}) {
  const normalized = token.trim();
  if (!normalized) return null;

  for (let drift = -window; drift <= window; drift++) {
    const t = timeMs + drift * VIRTUAL_PERIOD_SECONDS * 1000;
    const { code, counter } = totpAt({ secret, timeMs: t });
    if (code === normalized) return { counter };
  }

  return null;
}

async function safeAuditLogCreate(data: Parameters<typeof prisma.auditLog.create>[0]['data']) {
  try {
    await prisma.auditLog.create({ data });
  } catch {
  }
}

export async function createOverrideRequest(body: {
  companyId?: number;
  companyRnc?: string;
  companyCloudId?: string;
  cloudCompanyId?: string;
  actionCode: string;
  resourceType?: string;
  resourceId?: string;
  requestedById?: number;
  cloudUserId?: number;
  userUsername?: string;
  userEmail?: string;
  terminalId?: string;
  cloudTerminalId?: number | string;
  meta?: Record<string, unknown>;
}) {
  const resolvedCompanyId = await resolveCompanyIdForOverride({
    companyId: body.companyId,
    companyRnc: body.companyRnc,
    companyCloudId: body.cloudCompanyId ?? body.companyCloudId,
  });

  const requestedById = await resolveCloudUserIdForOverride({
    companyId: resolvedCompanyId,
    cloudUserId: body.cloudUserId,
    userIdCandidate: body.requestedById,
    userUsername: body.userUsername,
    userEmail: body.userEmail,
  });

  const terminalDeviceId = await resolveTerminalDeviceIdForOverride({
    companyId: resolvedCompanyId,
    cloudTerminalId: body.cloudTerminalId,
    terminalId: body.terminalId,
    required: false,
  });

  const created = await prisma.overrideRequest.create({
    data: {
      companyId: resolvedCompanyId,
      actionCode: body.actionCode,
      resourceType: body.resourceType,
      resourceId: body.resourceId,
      requestedById,
      terminalId: terminalDeviceId ?? null,
      meta: body.meta as any,
    },
  });

  await prisma.auditLog.create({
    data: {
      companyId: resolvedCompanyId,
      actionCode: body.actionCode,
      resourceType: body.resourceType,
      resourceId: body.resourceId,
      requestedById,
      approvedById: null,
      method: 'remote',
      result: 'requested',
      terminalId: terminalDeviceId ?? null,
      meta: body.meta as any,
    },
  });

  return { requestId: created.id, status: created.status };
}

export async function approveOverride(body: {
  companyId: number;
  requestId: number;
  approvedById: number;
  expiresInSeconds?: number;
}) {
  const ttl = body.expiresInSeconds ?? DEFAULT_TTL_SECONDS;
  const token = randomToken(10);
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + ttl * 1000);

  try {
    const [request, tokenRecord] = await prisma.$transaction(async (trx) => {
      const request = await trx.overrideRequest.findFirst({
        where: { id: body.requestId, companyId: body.companyId },
      });
      if (!request) throw new Error('Solicitud no encontrada');
      if (request.status !== 'pending') throw new Error('Solicitud ya resuelta');

      const updated = await trx.overrideRequest.update({
        where: { id: body.requestId },
        data: {
          status: 'approved',
          approvedById: body.approvedById,
          tokenHash,
          expiresAt,
          resolvedAt: new Date(),
        },
      });

      const tokenRecord = await trx.overrideToken.create({
        data: {
          companyId: body.companyId,
          actionCode: updated.actionCode,
          resourceType: updated.resourceType,
          resourceId: updated.resourceId,
          tokenHash,
          method: 'remote',
          nonce: randomToken(8),
          requestedById: updated.requestedById,
          approvedById: body.approvedById,
          expiresAt,
          terminalId: updated.terminalId,
          requestId: updated.id,
        },
      });

      await trx.auditLog.create({
        data: {
          companyId: body.companyId,
          actionCode: updated.actionCode,
          resourceType: updated.resourceType,
          resourceId: updated.resourceId,
          requestedById: updated.requestedById,
          approvedById: body.approvedById,
          method: 'remote',
          result: 'approved',
          terminalId: updated.terminalId,
        },
      });

      return [updated, tokenRecord] as const;
    });

    return {
      requestId: request.id,
      token,
      expiresAt,
      tokenId: tokenRecord.id,
    };
  } catch (e: any) {
    throw { status: 400, message: e.message ?? 'No se pudo aprobar la solicitud' };
  }
}

export async function verifyOverride(body: {
  companyId?: number;
  companyRnc?: string;
  companyCloudId?: string;
  cloudCompanyId?: string;
  token: string;
  actionCode: string;
  resourceType?: string;
  resourceId?: string;
  // Preferidos (cloud)
  cloudUserId?: number;
  cloudTerminalId?: number | string;
  // Back-compat
  usedById?: number;
  userUsername?: string;
  userEmail?: string;
  terminalId?: string;
  meta?: Record<string, unknown>;
}) {
  let resolvedCompanyId: number | null = null;
  let resolvedUsedById: number | null = null;
  let resolvedTerminalDeviceId: string | null = null;
  try {
    resolvedCompanyId = await resolveCompanyIdForOverride({
      companyId: body.companyId,
      companyRnc: body.companyRnc,
      companyCloudId: body.cloudCompanyId ?? body.companyCloudId,
    });

    const usedById = await resolveCloudUserIdForOverride({
      companyId: resolvedCompanyId,
      cloudUserId: body.cloudUserId,
      userIdCandidate: body.usedById,
      userUsername: body.userUsername,
      userEmail: body.userEmail,
    });
    resolvedUsedById = usedById;

    const terminalDeviceId = await resolveTerminalDeviceIdForOverride({
      companyId: resolvedCompanyId,
      cloudTerminalId: body.cloudTerminalId,
      terminalId: body.terminalId,
      required: false,
    });
    resolvedTerminalDeviceId = terminalDeviceId;

    const tokenHashForRequest = hashToken(body.token);
    logOverride('info', 'override.verify attempt', {
      companyId: resolvedCompanyId,
      actionCode: body.actionCode,
      tokenHashPrefix: tokenHashPrefix(tokenHashForRequest),
      usedById,
      terminalId: terminalDeviceId,
    });

    const result = await prisma.$transaction(async (trx) => {
      const now = new Date();
      const token = await trx.overrideToken.findFirst({
        where: {
          companyId: resolvedCompanyId!,
          actionCode: body.actionCode,
          tokenHash: tokenHashForRequest,
          method: 'remote',
        },
      });

      // Fallback: token virtual (TOTP) por terminal si el token no existe.
      if (!token) {
        if (!virtualTokenEnabled()) {
          throw apiError('OVERRIDE_TOKEN_INVALID', 'Token incorrecto', 400);
        }

        const terminalId = await resolveTerminalDeviceIdForOverride({
          companyId: resolvedCompanyId!,
          cloudTerminalId: body.cloudTerminalId,
          terminalId: body.terminalId,
          required: true,
        });

        if (!terminalId) {
          throw apiError('OVERRIDE_TERMINAL_REQUIRED', 'Datos no válidos (terminal no registrada en la nube)', 400);
        }

        const secret = virtualSecretFor(resolvedCompanyId!, terminalId);
        const match = verifyTotp({ secret, token: body.token, timeMs: now.getTime(), window: 1 });
        if (!match) {
          throw apiError('OVERRIDE_TOKEN_INVALID', 'Token incorrecto', 400);
        }

        const usedWindowHash = crypto
          .createHash('sha256')
          .update(`virtual|${resolvedCompanyId!}|${terminalId}|${match.counter}`)
          .digest('hex');

        const existing = await trx.overrideToken.findFirst({
          where: {
            companyId: resolvedCompanyId!,
            tokenHash: usedWindowHash,
            method: 'virtual',
          },
        });
        if (existing) {
          throw apiError('OVERRIDE_TOKEN_USED', 'Token ya fue usado', 400, {
            method: 'virtual',
            tokenHashPrefix: tokenHashPrefix(usedWindowHash),
          });
        }

        const expiresAt = new Date((match.counter + 1) * VIRTUAL_PERIOD_SECONDS * 1000);

        let created;
        try {
          created = await trx.overrideToken.create({
            data: {
              companyId: resolvedCompanyId!,
              actionCode: body.actionCode,
              resourceType: body.resourceType,
              resourceId: body.resourceId,
              tokenHash: usedWindowHash,
              method: 'virtual',
              nonce: randomToken(8),
              requestedById: usedById,
              approvedById: null,
              expiresAt,
              usedAt: now,
              usedById,
              terminalId,
              result: 'approved',
              meta: {
                counter: match.counter,
                periodSeconds: VIRTUAL_PERIOD_SECONDS,
                clientMeta: (body.meta ?? null) as any,
              },
            },
          });
        } catch (e: any) {
          // Si la ventana ya fue consumida por otro request concurrente.
          if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002') {
            throw apiError('OVERRIDE_TOKEN_USED', 'Token ya fue usado', 400, {
              method: 'virtual',
              tokenHashPrefix: tokenHashPrefix(usedWindowHash),
            });
          }
          throw e;
        }

        await trx.auditLog.create({
          data: {
            companyId: resolvedCompanyId!,
            actionCode: body.actionCode,
            resourceType: body.resourceType,
            resourceId: body.resourceId,
            requestedById: usedById,
            approvedById: null,
            method: 'virtual',
            result: 'approved',
            terminalId: terminalId,
            meta: {
              counter: match.counter,
              periodSeconds: VIRTUAL_PERIOD_SECONDS,
              clientMeta: (body.meta ?? null) as any,
            },
          },
        });

        return created;
      }

      if (token.revokedAt) throw apiError('OVERRIDE_TOKEN_REVOKED', 'Token revocado', 400);
      if (token.usedAt || token.usedById)
        throw apiError('OVERRIDE_TOKEN_USED', 'Token ya fue usado', 400, {
          tokenId: token.id,
          usedAt: token.usedAt?.toISOString() ?? null,
          usedById: token.usedById ?? null,
        });
      if (token.expiresAt.getTime() <= now.getTime())
        throw apiError('OVERRIDE_TOKEN_EXPIRED', 'Token expirado', 400, {
          tokenId: token.id,
          expiresAt: token.expiresAt.toISOString(),
        });
      if (token.resourceType && body.resourceType && token.resourceType !== body.resourceType)
        throw apiError('OVERRIDE_TOKEN_RESOURCE_MISMATCH', 'Token no coincide con el recurso', 400, {
          tokenId: token.id,
          expectedResourceType: token.resourceType,
          providedResourceType: body.resourceType,
        });
      if (token.resourceId && body.resourceId && token.resourceId !== body.resourceId)
        throw apiError('OVERRIDE_TOKEN_RESOURCE_MISMATCH', 'Token no coincide con el recurso', 400, {
          tokenId: token.id,
          expectedResourceId: token.resourceId,
          providedResourceId: body.resourceId,
        });

      // Consumo atómico (concurrency-safe): solo actualiza si todavía está disponible.
      const consumed = await trx.overrideToken.updateMany({
        where: {
          id: token.id,
          usedById: null,
          usedAt: null,
          revokedAt: null,
          expiresAt: { gt: now },
        },
        data: {
          usedAt: now,
          usedById,
          terminalId: terminalDeviceId ?? token.terminalId ?? null,
          result: 'approved',
        },
      });

      if (consumed.count !== 1) {
        const current = await trx.overrideToken.findUnique({ where: { id: token.id } });
        if (!current) throw apiError('OVERRIDE_TOKEN_INVALID', 'Token incorrecto', 400);
        if (current.revokedAt) throw apiError('OVERRIDE_TOKEN_REVOKED', 'Token revocado', 400);
        if (current.usedAt || current.usedById)
          throw apiError('OVERRIDE_TOKEN_USED', 'Token ya fue usado', 400, {
            tokenId: current.id,
            usedAt: current.usedAt?.toISOString() ?? null,
            usedById: current.usedById ?? null,
          });
        if (current.expiresAt.getTime() <= now.getTime())
          throw apiError('OVERRIDE_TOKEN_EXPIRED', 'Token expirado', 400, {
            tokenId: current.id,
            expiresAt: current.expiresAt.toISOString(),
          });

        throw apiError('OVERRIDE_TOKEN_CONFLICT', 'No autorizado', 409, { tokenId: token.id });
      }

      await trx.auditLog.create({
        data: {
          companyId: resolvedCompanyId!,
          actionCode: token.actionCode,
          resourceType: token.resourceType,
          resourceId: token.resourceId,
          requestedById: token.requestedById,
          approvedById: usedById,
          method: token.method,
          result: 'approved',
          terminalId: terminalDeviceId ?? null,
          meta: body.meta as any,
        },
      });

      return token;
    });

    return { ok: true, tokenId: result.id };
  } catch (e: any) {
    if (resolvedCompanyId != null) {
      const errorCode = e?.errorCode ?? 'OVERRIDE_REJECTED';
      await safeAuditLogCreate({
        companyId: resolvedCompanyId,
        actionCode: body.actionCode,
        resourceType: body.resourceType,
        resourceId: body.resourceId,
        requestedById: resolvedUsedById,
        approvedById: null,
        method: 'remote',
        result: 'rejected',
        terminalId: resolvedTerminalDeviceId ?? body.terminalId ?? null,
        meta: {
          errorCode,
          error: e?.message ?? String(e),
          tokenHashPrefix: tokenHashPrefix(body.token ? hashToken(body.token) : null),
        },
      });

      logOverride('warn', 'override.verify rejected', {
        companyId: resolvedCompanyId,
        actionCode: body.actionCode,
        errorCode,
        message: e?.message ?? String(e),
      });
    }
    if (e?.status && e?.errorCode) throw e;
    throw { status: 400, message: e?.message ?? 'No autorizado', errorCode: e?.errorCode ?? 'OVERRIDE_REJECTED' };
  }
}

export async function resolveOverrideIds(body: {
  companyId?: number;
  companyRnc?: string;
  companyCloudId?: string;
  cloudCompanyId?: string;
  cloudUserId?: number;
  userIdCandidate?: number;
  userUsername?: string;
  userEmail?: string;
  cloudTerminalId?: number | string;
  terminalId?: string;
}) {
  const companyId = await resolveCompanyIdForOverride({
    companyId: body.companyId,
    companyRnc: body.companyRnc,
    companyCloudId: body.cloudCompanyId ?? body.companyCloudId,
  });

  const userId =
    body.cloudUserId || body.userIdCandidate || body.userEmail || body.userUsername
      ? await resolveCloudUserIdForOverride({
          companyId,
          cloudUserId: body.cloudUserId,
          userIdCandidate: body.userIdCandidate,
          userUsername: body.userUsername,
          userEmail: body.userEmail,
        })
      : null;

  const terminalDeviceId =
    body.cloudTerminalId || body.terminalId
      ? await resolveTerminalDeviceIdForOverride({
          companyId,
          cloudTerminalId: body.cloudTerminalId,
          terminalId: body.terminalId,
          required: false,
        })
      : null;

  return { companyId, userId, terminalDeviceId };
}

export async function provisionVirtualToken(body: {
  companyId: number;
  userId: number;
  terminalId: string;
  uid?: string;
}) {
  const terminalId = body.terminalId.trim();
  if (!terminalId) throw { status: 400, message: 'terminalId requerido' };

  const secretBytes = virtualSecretFor(body.companyId, terminalId);
  const secret = base32Encode(secretBytes);

  const issuer = 'FULLPOS';
  const label = encodeURIComponent(`${issuer}:${body.companyId}-${terminalId}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    period: String(VIRTUAL_PERIOD_SECONDS),
    digits: String(VIRTUAL_DIGITS),
  });
  const otpauthUri = `otpauth://totp/${label}?${params.toString()}`;

  await prisma.auditLog.create({
    data: {
      companyId: body.companyId,
      actionCode: 'VIRTUAL_TOKEN',
      requestedById: body.userId,
      approvedById: body.userId,
      method: 'virtual',
      result: 'provisioned',
      terminalId,
      meta: {
        digits: VIRTUAL_DIGITS,
        periodSeconds: VIRTUAL_PERIOD_SECONDS,
        uid: body.uid ?? null,
      },
    },
  });

  return {
    terminalId,
    secret,
    digits: VIRTUAL_DIGITS,
    periodSeconds: VIRTUAL_PERIOD_SECONDS,
    otpauthUri,
  };
}

export async function getAudit(companyId: number, limit = 100) {
  const audits = await prisma.auditLog.findMany({
    where: { companyId },
    orderBy: { createdAt: 'desc' },
    take: limit,
    include: {
      requestedBy: { select: { id: true, username: true, displayName: true } },
      approvedBy: { select: { id: true, username: true, displayName: true } },
    },
  });

  return audits.map((audit) => {
    const requestedByName =
      audit.requestedBy?.displayName ?? audit.requestedBy?.username ?? null;
    const approvedByName =
      audit.approvedBy?.displayName ?? audit.approvedBy?.username ?? null;

    return {
      id: audit.id,
      actionCode: audit.actionCode,
      resourceType: audit.resourceType,
      resourceId: audit.resourceId,
      requestedById: audit.requestedById,
      approvedById: audit.approvedById,
      requestedByName,
      approvedByName,
      method: audit.method,
      result: audit.result,
      terminalId: audit.terminalId,
      meta: audit.meta,
      createdAt: audit.createdAt,
    };
  });
}

export async function getOverrideRequests(params: {
  companyId: number;
  status?: string;
  limit?: number;
}) {
  const requests = await prisma.overrideRequest.findMany({
    where: {
      companyId: params.companyId,
      status: params.status,
    },
    orderBy: { createdAt: 'desc' },
    take: params.limit ?? 50,
    include: {
      requestedBy: { select: { id: true, username: true, displayName: true } },
      approvedBy: { select: { id: true, username: true, displayName: true } },
    },
  });

  return requests;
}

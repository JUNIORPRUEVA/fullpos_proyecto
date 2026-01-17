import crypto from 'crypto';
import { prisma } from '../../config/prisma';

const DEFAULT_TTL_SECONDS = 180;
const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function hashToken(token: string) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function randomToken(length: number) {
  return Array.from({ length }, () => alphabet[Math.floor(Math.random() * alphabet.length)]).join(
    '',
  );
}

export async function createOverrideRequest(body: {
  companyId: number;
  actionCode: string;
  resourceType?: string;
  resourceId?: string;
  requestedById: number;
  terminalId?: string;
  meta?: Record<string, unknown>;
}) {
  const created = await prisma.overrideRequest.create({
    data: {
      companyId: body.companyId,
      actionCode: body.actionCode,
      resourceType: body.resourceType,
      resourceId: body.resourceId,
      requestedById: body.requestedById,
      terminalId: body.terminalId,
      meta: body.meta as any,
    },
  });

  await prisma.auditLog.create({
    data: {
      companyId: body.companyId,
      actionCode: body.actionCode,
      resourceType: body.resourceType,
      resourceId: body.resourceId,
      requestedById: body.requestedById,
      approvedById: null,
      method: 'remote',
      result: 'requested',
      terminalId: body.terminalId,
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
      const request = await trx.overrideRequest.update({
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
          actionCode: request.actionCode,
          resourceType: request.resourceType,
          resourceId: request.resourceId,
          tokenHash,
          method: 'remote',
          nonce: randomToken(8),
          requestedById: request.requestedById,
          approvedById: body.approvedById,
          expiresAt,
          terminalId: request.terminalId,
          requestId: request.id,
        },
      });

      await trx.auditLog.create({
        data: {
          companyId: body.companyId,
          actionCode: request.actionCode,
          resourceType: request.resourceType,
          resourceId: request.resourceId,
          requestedById: request.requestedById,
          approvedById: body.approvedById,
          method: 'remote',
          result: 'approved',
          terminalId: request.terminalId,
        },
      });

      return [request, tokenRecord] as const;
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
  companyId: number;
  token: string;
  actionCode: string;
  resourceType?: string;
  resourceId?: string;
  usedById: number;
  terminalId?: string;
}) {
  const tokenHash = hashToken(body.token);
  try {
    const result = await prisma.$transaction(async (trx) => {
      const token = await trx.overrideToken.findFirst({
        where: {
          companyId: body.companyId,
          actionCode: body.actionCode,
          tokenHash,
        },
      });

      if (!token) throw new Error('Token inv\u00e1lido');
      if (token.usedAt) throw new Error('Token ya usado');
      if (token.expiresAt.getTime() < Date.now()) throw new Error('Token vencido');
      if (token.resourceType && body.resourceType && token.resourceType !== body.resourceType)
        throw new Error('Token no coincide con el recurso');
      if (token.resourceId && body.resourceId && token.resourceId !== body.resourceId)
        throw new Error('Token no coincide con el recurso');

      await trx.overrideToken.update({
        where: { id: token.id },
        data: { usedAt: new Date(), usedById: body.usedById, result: 'approved' },
      });

      await trx.auditLog.create({
        data: {
          companyId: body.companyId,
          actionCode: token.actionCode,
          resourceType: token.resourceType,
          resourceId: token.resourceId,
          requestedById: token.requestedById,
          approvedById: body.usedById,
          method: token.method,
          result: 'approved',
          terminalId: body.terminalId,
        },
      });

      return token;
    });

    return { ok: true, tokenId: result.id };
  } catch (e: any) {
    await prisma.auditLog.create({
      data: {
        companyId: body.companyId,
        actionCode: body.actionCode,
        resourceType: body.resourceType,
        resourceId: body.resourceId,
        requestedById: body.usedById,
        approvedById: null,
        method: 'remote',
        result: 'rejected',
        terminalId: body.terminalId,
        meta: { error: e.message },
      },
    });
    throw { status: 400, message: e.message ?? 'No autorizado' };
  }
}

export async function getAudit(companyId: number, limit = 100) {
  const audits = await prisma.auditLog.findMany({
    where: { companyId },
    orderBy: { createdAt: 'desc' },
    take: limit,
  });

  return audits;
}

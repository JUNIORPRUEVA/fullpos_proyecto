import { prisma } from '../../config/prisma';
import { emitCashEvent } from '../../realtime/realtime.gateway';

function normalizeRnc(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

async function resolveCompanyId(companyRnc?: string, companyCloudId?: string) {
  const rnc = companyRnc?.trim() ?? '';
  const cloudId = companyCloudId?.trim() ?? '';
  if (!rnc && !cloudId) {
    throw { status: 400, message: 'RNC o ID interno requerido' };
  }

  let company = null as { id: number; rnc: string | null } | null;

  if (cloudId) {
    company = await prisma.company.findFirst({
      where: { cloudCompanyId: cloudId },
      select: { id: true, rnc: true },
    });
  }

  if (!company && rnc) {
    company = await prisma.company.findFirst({
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
  }

  if (!company) {
    throw { status: 404, message: 'Empresa no encontrada' };
  }

  return company.id;
}

export type SyncCashSessionInput = {
  localId: number;
  openedByUserName: string;
  openedAt: string;
  closedAt?: string | null;
  initialAmount: number;
  closingAmount?: number | null;
  expectedCash?: number | null;
  difference?: number | null;
  status: string;
  note?: string | null;
};

export type SyncCashMovementInput = {
  localId: number;
  sessionLocalId: number;
  type: string;
  amount: number;
  note?: string | null;
  createdAt: string;
};

export async function syncCashByRnc(
  companyRnc: string | undefined,
  companyCloudId: string | undefined,
  sessions: SyncCashSessionInput[],
  movements: SyncCashMovementInput[],
) {
  const companyId = await resolveCompanyId(companyRnc, companyCloudId);

  const defaultUser = await prisma.user.findFirst({
    where: { companyId },
    select: { id: true },
    orderBy: { id: 'asc' },
  });
  if (!defaultUser) {
    throw { status: 404, message: 'Empresa sin usuario (no se puede sincronizar caja)' };
  }

  const existingSessions = await prisma.cashSession.findMany({
    where: { companyId, localId: { in: Array.from(new Set((sessions ?? []).map((item) => item.localId))) } },
    select: {
      id: true,
      localId: true,
      status: true,
      closedAt: true,
      expectedCash: true,
      difference: true,
      updatedAt: true,
    },
  });
  const sessionMapBefore = new Map(existingSessions.map((session) => [session.localId, session]));

  const existingMovements = await prisma.cashMovement.findMany({
    where: { companyId, localId: { in: Array.from(new Set((movements ?? []).map((item) => item.localId))) } },
    select: {
      id: true,
      localId: true,
      type: true,
      amount: true,
      createdAt: true,
      sessionId: true,
    },
  });
  const movementMapBefore = new Map(existingMovements.map((movement) => [movement.localId, movement]));

  const realtimeCashEvents: Array<{
    type: 'cash.session.updated' | 'cash.movement.updated';
    cash: Record<string, unknown>;
  }> = [];

  await prisma.$transaction(async (tx) => {
    for (const s of sessions ?? []) {
      const openedAt = new Date(s.openedAt);
      const closedAt = s.closedAt ? new Date(s.closedAt) : null;
      const upserted = await tx.cashSession.upsert({
        where: { companyId_localId: { companyId, localId: s.localId } },
        update: {
          userName: s.openedByUserName,
          openedAt,
          closedAt,
          initialAmount: s.initialAmount,
          closingAmount: s.closingAmount ?? null,
          expectedCash: s.expectedCash ?? null,
          difference: s.difference ?? null,
          status: s.status,
          note: s.note ?? null,
        },
        create: {
          companyId,
          localId: s.localId,
          // No tenemos usuarios cloud por cada cajero; guardamos userName y dejamos openedBy/closedBy null.
          openedById: defaultUser.id,
          userName: s.openedByUserName,
          openedAt,
          closedAt,
          initialAmount: s.initialAmount,
          closingAmount: s.closingAmount ?? null,
          expectedCash: s.expectedCash ?? null,
          difference: s.difference ?? null,
          status: s.status,
          note: s.note ?? null,
        },
        select: {
          id: true,
          localId: true,
          status: true,
          closedAt: true,
          expectedCash: true,
          difference: true,
          updatedAt: true,
        },
      });

      const previous = sessionMapBefore.get(s.localId) ?? null;
      const changed =
        !previous ||
        previous.status !== upserted.status ||
        (previous.closedAt?.getTime() ?? null) !== (upserted.closedAt?.getTime() ?? null) ||
        Number(previous.expectedCash ?? 0) !== Number(upserted.expectedCash ?? 0) ||
        Number(previous.difference ?? 0) !== Number(upserted.difference ?? 0) ||
        (previous.updatedAt?.getTime() ?? null) !== (upserted.updatedAt?.getTime() ?? null);
      if (changed) {
        realtimeCashEvents.push({
          type: 'cash.session.updated',
          cash: {
            sessionId: upserted.id,
            localId: upserted.localId,
            status: upserted.status,
            closedAt: upserted.closedAt,
            expectedCash: upserted.expectedCash,
            difference: upserted.difference,
            updatedAt: upserted.updatedAt,
          },
        });
      }
    }

    // Re-cargar mapping de sesiones para asociar movimientos.
    const sessionLocalIds = Array.from(new Set((movements ?? []).map((m) => m.sessionLocalId)));
    const dbSessions =
      sessionLocalIds.length === 0
        ? []
        : await tx.cashSession.findMany({
            where: { companyId, localId: { in: sessionLocalIds } },
            select: { id: true, localId: true },
          });
    const sessionMap = new Map<number, number>();
    for (const s of dbSessions) {
      if (s.localId != null) sessionMap.set(s.localId, s.id);
    }

    for (const m of movements ?? []) {
      const sessionId = sessionMap.get(m.sessionLocalId);
      if (!sessionId) continue;
      const upserted = await tx.cashMovement.upsert({
        where: { companyId_localId: { companyId, localId: m.localId } },
        update: {
          sessionId,
          type: m.type,
          amount: m.amount,
          note: m.note ?? null,
          createdAt: new Date(m.createdAt),
        },
        create: {
          companyId,
          localId: m.localId,
          sessionId,
          type: m.type,
          amount: m.amount,
          note: m.note ?? null,
          createdAt: new Date(m.createdAt),
        },
        select: {
          id: true,
          localId: true,
          type: true,
          amount: true,
          createdAt: true,
          sessionId: true,
        },
      });

      const previous = movementMapBefore.get(m.localId) ?? null;
      const changed =
        !previous ||
        previous.type !== upserted.type ||
        Number(previous.amount) !== Number(upserted.amount) ||
        previous.sessionId !== upserted.sessionId ||
        previous.createdAt.getTime() !== upserted.createdAt.getTime();
      if (changed) {
        realtimeCashEvents.push({
          type: 'cash.movement.updated',
          cash: {
            movementId: upserted.id,
            localId: upserted.localId,
            sessionId: upserted.sessionId,
            type: upserted.type,
            amount: upserted.amount,
            createdAt: upserted.createdAt,
          },
        });
      }
    }
  });

  for (const event of realtimeCashEvents) {
    emitCashEvent({
      companyId,
      type: event.type,
      cash: event.cash,
    });
  }

  return {
    ok: true,
    companyId,
    upsertedSessions: sessions?.length ?? 0,
    upsertedMovements: movements?.length ?? 0,
  };
}

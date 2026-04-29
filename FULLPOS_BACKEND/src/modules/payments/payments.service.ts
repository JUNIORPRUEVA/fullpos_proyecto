import { Prisma } from '@prisma/client';
import { prisma } from '../../config/prisma';
import { emitSaleEvent } from '../../realtime/realtime.gateway';
import { buildPagination } from '../../utils/pagination';
import { CompanyIdentityLookup, resolveCompanyIdentityId } from '../companies/companyIdentity.service';

function toNumber(value: Prisma.Decimal | number | string | null | undefined) {
  if (value === null || value === undefined) return 0;
  if (typeof value === 'number') return value;
  if (typeof value === 'string') return Number(value);
  return value.toNumber();
}

function normalizeKind(value: string) {
  const normalized = value.trim().toLowerCase();
  if (normalized !== 'credit' && normalized !== 'layaway') {
    throw { status: 400, message: 'Tipo de pago no soportado' };
  }
  return normalized as 'credit' | 'layaway';
}

function calculateTotalDue(sale: {
  total: Prisma.Decimal | number;
  paymentMethod: string | null;
  creditInterestRate: Prisma.Decimal | number | null;
}) {
  const total = toNumber(sale.total);
  const method = (sale.paymentMethod ?? '').trim().toLowerCase();
  if (method === 'credit') {
    return total + (total * toNumber(sale.creditInterestRate) / 100);
  }
  return total;
}

function toSaleRealtimePayload(sale: {
  id: number;
  localCode: string;
  kind: string;
  status: string;
  total: Prisma.Decimal | number;
  paymentMethod: string | null;
  customerNameSnapshot: string | null;
  createdAt: Date;
  updatedAt: Date;
  deletedAt: Date | null;
}) {
  return {
    id: sale.id,
    localCode: sale.localCode,
    kind: sale.kind,
    status: sale.status,
    total: toNumber(sale.total),
    paymentMethod: sale.paymentMethod,
    customerName: sale.customerNameSnapshot,
    createdAt: sale.createdAt,
    updatedAt: sale.updatedAt,
    deletedAt: sale.deletedAt,
  };
}

async function recalculateSalePaymentState(
  tx: Prisma.TransactionClient,
  saleId: number,
) {
  const sale = await tx.sale.findUnique({
    where: { id: saleId },
    select: {
      id: true,
      localCode: true,
      kind: true,
      status: true,
      total: true,
      paymentMethod: true,
      paidAmount: true,
      creditInterestRate: true,
      customerNameSnapshot: true,
      createdAt: true,
      updatedAt: true,
      deletedAt: true,
    },
  });

  if (!sale) {
    throw { status: 404, message: 'Venta no encontrada para recalcular pagos' };
  }

  const method = (sale.paymentMethod ?? '').trim().toLowerCase();
  const kind = method === 'credit' ? 'credit' : method === 'layaway' ? 'layaway' : null;
  if (!kind) {
    return {
      sale,
      totalDue: calculateTotalDue(sale),
      totalReceived: toNumber(sale.paidAmount),
      pendingAmount: Math.max(0, calculateTotalDue(sale) - toNumber(sale.paidAmount)),
    };
  }

  const aggregate = await tx.payment.aggregate({
    _sum: { amount: true },
    where: { saleId, kind },
  });

  const totalReceived = toNumber(aggregate._sum.amount);
  const totalDue = calculateTotalDue(sale);
  const pendingAmount = Math.max(0, totalDue - totalReceived);

  let nextStatus = sale.status;
  if (kind === 'credit') {
    nextStatus = pendingAmount <= 0.009 ? 'PAID' : sale.status === 'PAID' ? 'completed' : sale.status;
  } else if (kind === 'layaway') {
    nextStatus = pendingAmount <= 0.009 ? 'completed' : 'LAYAWAY';
  }

  const updatedSale = await tx.sale.update({
    where: { id: saleId },
    data: {
      paidAmount: totalReceived,
      status: nextStatus,
    },
    select: {
      id: true,
      localCode: true,
      kind: true,
      status: true,
      total: true,
      paymentMethod: true,
      customerNameSnapshot: true,
      createdAt: true,
      updatedAt: true,
      deletedAt: true,
    },
  });

  return {
    sale: updatedSale,
    totalDue,
    totalReceived,
    pendingAmount,
  };
}

async function upsertSubtypeSnapshot(
  tx: Prisma.TransactionClient,
  params: {
    paymentId: number;
    kind: 'credit' | 'layaway';
    totalDueSnapshot: number;
    totalPaidSnapshot: number;
    pendingAmountSnapshot: number;
    statusSnapshot?: string | null;
  },
) {
  if (params.kind === 'credit') {
    await tx.creditPayment.upsert({
      where: { paymentId: params.paymentId },
      update: {
        totalDueSnapshot: params.totalDueSnapshot,
        totalPaidSnapshot: params.totalPaidSnapshot,
        pendingAmountSnapshot: params.pendingAmountSnapshot,
      },
      create: {
        paymentId: params.paymentId,
        totalDueSnapshot: params.totalDueSnapshot,
        totalPaidSnapshot: params.totalPaidSnapshot,
        pendingAmountSnapshot: params.pendingAmountSnapshot,
      },
    });
    return;
  }

  await tx.layawayPayment.upsert({
    where: { paymentId: params.paymentId },
    update: {
      totalDueSnapshot: params.totalDueSnapshot,
      totalPaidSnapshot: params.totalPaidSnapshot,
      pendingAmountSnapshot: params.pendingAmountSnapshot,
      statusSnapshot: params.statusSnapshot ?? null,
    },
    create: {
      paymentId: params.paymentId,
      totalDueSnapshot: params.totalDueSnapshot,
      totalPaidSnapshot: params.totalPaidSnapshot,
      pendingAmountSnapshot: params.pendingAmountSnapshot,
      statusSnapshot: params.statusSnapshot ?? null,
    },
  });
}

function mapPaymentRow(row: any) {
  return {
    id: row.id,
    localId: row.localId,
    kind: row.kind,
    method: row.method,
    amount: toNumber(row.amount),
    note: row.note,
    postedAt: row.postedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    sale: row.sale
      ? {
          id: row.sale.id,
          localCode: row.sale.localCode,
          status: row.sale.status,
          paymentMethod: row.sale.paymentMethod,
          total: toNumber(row.sale.total),
          paidAmount: toNumber(row.sale.paidAmount),
        }
      : null,
    session: row.session
      ? {
          id: row.session.id,
          localId: row.session.localId,
          status: row.session.status,
        }
      : null,
    creditPayment: row.creditPayment
      ? {
          totalDueSnapshot: toNumber(row.creditPayment.totalDueSnapshot),
          totalPaidSnapshot: toNumber(row.creditPayment.totalPaidSnapshot),
          pendingAmountSnapshot: toNumber(row.creditPayment.pendingAmountSnapshot),
        }
      : null,
    layawayPayment: row.layawayPayment
      ? {
          totalDueSnapshot: toNumber(row.layawayPayment.totalDueSnapshot),
          totalPaidSnapshot: toNumber(row.layawayPayment.totalPaidSnapshot),
          pendingAmountSnapshot: toNumber(row.layawayPayment.pendingAmountSnapshot),
          statusSnapshot: row.layawayPayment.statusSnapshot,
        }
      : null,
  };
}

export async function createPayment(companyId: number, input: {
  saleId: number;
  kind: string;
  amount: number;
  method: string;
  note?: string | null;
  sessionId?: number | null;
}) {
  const kind = normalizeKind(input.kind);
  const sale = await prisma.sale.findFirst({
    where: { id: input.saleId, companyId },
    select: {
      id: true,
      paymentMethod: true,
      total: true,
      creditInterestRate: true,
    },
  });

  if (!sale) {
    throw { status: 404, message: 'Venta no encontrada' };
  }

  const salePaymentMethod = (sale.paymentMethod ?? '').trim().toLowerCase();
  if (salePaymentMethod !== kind) {
    throw { status: 400, message: 'La venta no corresponde al tipo de pago indicado' };
  }

  if (input.sessionId != null) {
    const session = await prisma.cashSession.findFirst({
      where: { id: input.sessionId, companyId },
      select: { id: true },
    });
    if (!session) {
      throw { status: 404, message: 'Sesión de caja no encontrada' };
    }
  }

  let createdPaymentId = 0;
  let saleRealtimePayload: ReturnType<typeof toSaleRealtimePayload> | null = null;
  let paymentRow: any = null;

  await prisma.$transaction(async (tx) => {
    const payment = await tx.payment.create({
      data: {
        companyId,
        saleId: input.saleId,
        sessionId: input.sessionId ?? null,
        kind,
        method: input.method.trim(),
        amount: input.amount,
        note: input.note ?? null,
        postedAt: new Date(),
      },
    });

    const paymentState = await recalculateSalePaymentState(tx, input.saleId);

    await upsertSubtypeSnapshot(tx, {
      paymentId: payment.id,
      kind,
      totalDueSnapshot: paymentState.totalDue,
      totalPaidSnapshot: paymentState.totalReceived,
      pendingAmountSnapshot: paymentState.pendingAmount,
      statusSnapshot: paymentState.sale.status,
    });

    createdPaymentId = payment.id;
    saleRealtimePayload = toSaleRealtimePayload(paymentState.sale);
    paymentRow = await tx.payment.findUnique({
      where: { id: payment.id },
      include: {
        sale: {
          select: {
            id: true,
            localCode: true,
            status: true,
            paymentMethod: true,
            total: true,
            paidAmount: true,
          },
        },
        session: { select: { id: true, localId: true, status: true } },
        creditPayment: true,
        layawayPayment: true,
      },
    });
  });

  if (saleRealtimePayload) {
    await emitSaleEvent({
      companyId,
      type: 'sale.updated',
      sale: saleRealtimePayload,
    });
  }

  return {
    ok: true,
    companyId,
    paymentId: createdPaymentId,
    payment: mapPaymentRow(paymentRow),
  };
}

export async function listPayments(companyId: number, params: {
  from?: string;
  to?: string;
  saleId?: number;
  kind?: string;
  page?: number;
  pageSize?: number;
}) {
  const page = params.page ?? 1;
  const pageSize = params.pageSize ?? 50;
  const { skip, take } = buildPagination(page, pageSize);

  const where: Prisma.PaymentWhereInput = {
    companyId,
    ...(params.saleId != null ? { saleId: params.saleId } : {}),
    ...(params.kind ? { kind: normalizeKind(params.kind) } : {}),
    ...((params.from || params.to)
      ? {
          postedAt: {
            ...(params.from ? { gte: new Date(params.from) } : {}),
            ...(params.to ? { lte: new Date(params.to) } : {}),
          },
        }
      : {}),
  };

  const [total, rows] = await Promise.all([
    prisma.payment.count({ where }),
    prisma.payment.findMany({
      where,
      include: {
        sale: {
          select: {
            id: true,
            localCode: true,
            status: true,
            paymentMethod: true,
            total: true,
            paidAmount: true,
          },
        },
        session: { select: { id: true, localId: true, status: true } },
        creditPayment: true,
        layawayPayment: true,
      },
      orderBy: { postedAt: 'desc' },
      skip,
      take,
    }),
  ]);

  return {
    data: rows.map(mapPaymentRow),
    page,
    pageSize,
    total,
  };
}

export async function syncPaymentsByRnc(
  identity: CompanyIdentityLookup,
  payments: Array<{
    localId: number;
    kind: string;
    saleLocalCode: string;
    sessionLocalId?: number | null;
    amount: number;
    method: string;
    note?: string | null;
    createdAt: string;
    totalDueSnapshot?: number | null;
    totalPaidSnapshot?: number | null;
    pendingAmountSnapshot?: number | null;
    statusSnapshot?: string | null;
  }>,
) {
  const companyId = await resolveCompanyIdentityId(identity, 'payments.sync');
  if (!payments || payments.length === 0) {
    return { ok: true, upserted: 0, companyId };
  }

  const saleLocalCodes = Array.from(new Set(payments.map((payment) => payment.saleLocalCode).filter(Boolean)));
  const sessionLocalIds = Array.from(
    new Set(
      payments
        .map((payment) => payment.sessionLocalId)
        .filter((value): value is number => value != null),
    ),
  );

  const [sales, sessions] = await Promise.all([
    prisma.sale.findMany({
      where: { companyId, localCode: { in: saleLocalCodes } },
      select: {
        id: true,
        localCode: true,
        paymentMethod: true,
        total: true,
        creditInterestRate: true,
      },
    }),
    sessionLocalIds.length === 0
      ? Promise.resolve([])
      : prisma.cashSession.findMany({
          where: { companyId, localId: { in: sessionLocalIds } },
          select: { id: true, localId: true },
        }),
  ]);

  const saleMap = new Map(sales.map((sale) => [sale.localCode, sale]));
  const sessionMap = new Map<number, number>();
  for (const session of sessions) {
    if (session.localId != null) sessionMap.set(session.localId, session.id);
  }

  const saleIdsToEmit = new Set<number>();

  await prisma.$transaction(async (tx) => {
    for (const input of payments) {
      const kind = normalizeKind(input.kind);
      const sale = saleMap.get(input.saleLocalCode);
      if (!sale) {
        throw {
          status: 409,
          message: `No existe la venta ${input.saleLocalCode} en la nube para registrar el pago`,
        };
      }

      const saleMethod = (sale.paymentMethod ?? '').trim().toLowerCase();
      if (saleMethod && saleMethod !== kind) {
        throw {
          status: 400,
          message: `La venta ${input.saleLocalCode} no coincide con el tipo ${kind}`,
        };
      }

      const payment = await tx.payment.upsert({
        where: {
          companyId_kind_localId: {
            companyId,
            kind,
            localId: input.localId,
          },
        },
        update: {
          saleId: sale.id,
          sessionId: input.sessionLocalId != null ? (sessionMap.get(input.sessionLocalId) ?? null) : null,
          method: input.method.trim(),
          amount: input.amount,
          note: input.note ?? null,
          postedAt: new Date(input.createdAt),
        },
        create: {
          companyId,
          saleId: sale.id,
          sessionId: input.sessionLocalId != null ? (sessionMap.get(input.sessionLocalId) ?? null) : null,
          localId: input.localId,
          kind,
          method: input.method.trim(),
          amount: input.amount,
          note: input.note ?? null,
          postedAt: new Date(input.createdAt),
        },
      });

      const totalDueSnapshot = input.totalDueSnapshot ?? calculateTotalDue(sale);
      const totalPaidSnapshot = input.totalPaidSnapshot ?? 0;
      const pendingAmountSnapshot = input.pendingAmountSnapshot ?? Math.max(0, totalDueSnapshot - totalPaidSnapshot);

      await upsertSubtypeSnapshot(tx, {
        paymentId: payment.id,
        kind,
        totalDueSnapshot,
        totalPaidSnapshot,
        pendingAmountSnapshot,
        statusSnapshot: input.statusSnapshot ?? null,
      });

      saleIdsToEmit.add(sale.id);
    }

    for (const saleId of saleIdsToEmit) {
      await recalculateSalePaymentState(tx, saleId);
    }
  });

  const updatedSales = await prisma.sale.findMany({
    where: { id: { in: Array.from(saleIdsToEmit) } },
    select: {
      id: true,
      localCode: true,
      kind: true,
      status: true,
      total: true,
      paymentMethod: true,
      customerNameSnapshot: true,
      createdAt: true,
      updatedAt: true,
      deletedAt: true,
    },
  });

  for (const sale of updatedSales) {
    await emitSaleEvent({
      companyId,
      type: 'sale.updated',
      sale: toSaleRealtimePayload(sale),
    });
  }

  return {
    ok: true,
    upserted: payments.length,
    companyId,
    updatedSales: updatedSales.length,
  };
}
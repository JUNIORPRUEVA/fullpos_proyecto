import { prisma } from '../../config/prisma';
import { parseRange, ensureRangeWithinDays } from '../../utils/date';
import { buildPagination } from '../../utils/pagination';

const MAX_RANGE_DAYS = 365;

function toNumber(value: any) {
  if (value === null || value === undefined) return 0;
  if (typeof value === 'number') return value;
  if (typeof value === 'string') return Number(value);
  if (typeof (value as any).toNumber === 'function') return (value as any).toNumber();
  return Number(value);
}

export async function getReportsStatus(companyId: number, from: string, to: string) {
  const { fromDate, toDate } = parseRange(from, to);
  ensureRangeWithinDays(fromDate, toDate, MAX_RANGE_DAYS);

  const [company, salesCount, cashClosingsCount, cashMovementsCount, expensesCount, quotesCount, lastSale, lastCashClosing, lastCashMovement, lastExpense, lastQuote] =
    await Promise.all([
      prisma.company.findUnique({
        where: { id: companyId },
        select: { id: true, name: true, rnc: true, cloudCompanyId: true },
      }),
      prisma.sale.count({
        where: { companyId, status: { not: 'cancelled' }, createdAt: { gte: fromDate, lte: toDate } },
      }),
      prisma.cashSession.count({
        where: { companyId, status: 'CLOSED', closedAt: { gte: fromDate, lte: toDate } },
      }),
      prisma.cashMovement.count({
        where: { companyId, createdAt: { gte: fromDate, lte: toDate } },
      }),
      prisma.expense.count({
        where: { companyId, incurredAt: { gte: fromDate, lte: toDate } },
      }),
      prisma.quote.count({
        where: { companyId, createdAt: { gte: fromDate, lte: toDate } },
      }),
      prisma.sale.findFirst({
        where: { companyId, status: { not: 'cancelled' } },
        select: { createdAt: true },
        orderBy: { createdAt: 'desc' },
      }),
      prisma.cashSession.findFirst({
        where: { companyId, status: 'CLOSED' },
        select: { closedAt: true },
        orderBy: { closedAt: 'desc' },
      }),
      prisma.cashMovement.findFirst({
        where: { companyId },
        select: { createdAt: true },
        orderBy: { createdAt: 'desc' },
      }),
      prisma.expense.findFirst({
        where: { companyId },
        select: { incurredAt: true },
        orderBy: { incurredAt: 'desc' },
      }),
      prisma.quote.findFirst({
        where: { companyId },
        select: { createdAt: true },
        orderBy: { createdAt: 'desc' },
      }),
    ]);

  return {
    company: company ?? { id: companyId, name: 'Empresa', rnc: null, cloudCompanyId: null },
    range: { from: fromDate, to: toDate },
    counts: {
      sales: salesCount,
      cashClosings: cashClosingsCount,
      cashMovements: cashMovementsCount,
      expenses: expensesCount,
      quotes: quotesCount,
    },
    last: {
      saleAt: lastSale?.createdAt ?? null,
      cashClosingAt: lastCashClosing?.closedAt ?? null,
      cashMovementAt: lastCashMovement?.createdAt ?? null,
      expenseAt: lastExpense?.incurredAt ?? null,
      quoteAt: lastQuote?.createdAt ?? null,
    },
  };
}

export async function getSalesSummary(companyId: number, from: string, to: string) {
  const { fromDate, toDate } = parseRange(from, to);
  ensureRangeWithinDays(fromDate, toDate, MAX_RANGE_DAYS);

  const result = await prisma.sale.aggregate({
    _sum: { total: true },
    _count: { _all: true },
    where: {
      companyId,
      status: { not: 'cancelled' },
      createdAt: { gte: fromDate, lte: toDate },
    },
  });

  const total = toNumber(result._sum.total);
  const count = result._count._all;
  const average = count > 0 ? total / count : 0;

  return { total, count, average };
}

export async function getSalesByDay(companyId: number, from: string, to: string) {
  const { fromDate, toDate } = parseRange(from, to);
  ensureRangeWithinDays(fromDate, toDate, MAX_RANGE_DAYS);

  const sales = await prisma.sale.findMany({
    where: {
      companyId,
      status: { not: 'cancelled' },
      createdAt: { gte: fromDate, lte: toDate },
    },
    select: { id: true, total: true, createdAt: true },
    orderBy: { createdAt: 'asc' },
  });

  const byDay = new Map<string, { total: number; count: number }>();
  for (const sale of sales) {
    const key = sale.createdAt.toISOString().substring(0, 10);
    const entry = byDay.get(key) ?? { total: 0, count: 0 };
    entry.total += toNumber(sale.total);
    entry.count += 1;
    byDay.set(key, entry);
  }

  return Array.from(byDay.entries()).map(([date, info]) => ({
    date,
    total: info.total,
    count: info.count,
  }));
}

export async function getSalesList(
  companyId: number,
  from: string,
  to: string,
  page = 1,
  pageSize = 20,
) {
  const { fromDate, toDate } = parseRange(from, to);
  ensureRangeWithinDays(fromDate, toDate, MAX_RANGE_DAYS);
  const { skip, take } = buildPagination(page, pageSize);

  const [totalCount, rows] = await Promise.all([
    prisma.sale.count({
      where: {
        companyId,
        status: { not: 'cancelled' },
        createdAt: { gte: fromDate, lte: toDate },
      },
    }),
    prisma.sale.findMany({
      where: {
        companyId,
        status: { not: 'cancelled' },
        createdAt: { gte: fromDate, lte: toDate },
      },
      include: {
        session: true,
        createdBy: { select: { id: true, username: true, displayName: true } },
      },
      orderBy: { createdAt: 'desc' },
      skip,
      take,
    }),
  ]);

  const data = rows.map((sale) => ({
    id: sale.id,
    localCode: sale.localCode,
    total: toNumber(sale.total),
    paymentMethod: sale.paymentMethod,
    sessionId: sale.sessionId,
    sessionStatus: sale.session?.status,
    sessionOpenedAt: sale.session?.openedAt,
    createdAt: sale.createdAt,
    user: sale.createdBy
      ? {
          id: sale.createdBy.id,
          username: sale.createdBy.username,
          displayName: sale.createdBy.displayName,
        }
      : null,
  }));

  return {
    data,
    page,
    pageSize,
    total: totalCount,
  };
}

export async function getCashClosings(companyId: number, from: string, to: string) {
  const { fromDate, toDate } = parseRange(from, to);
  ensureRangeWithinDays(fromDate, toDate, MAX_RANGE_DAYS);

  const sessions = await prisma.cashSession.findMany({
    where: {
      companyId,
      status: 'CLOSED',
      closedAt: { gte: fromDate, lte: toDate },
    },
    include: {
      openedBy: { select: { id: true, username: true, displayName: true } },
      closedBy: { select: { id: true, username: true, displayName: true } },
    },
    orderBy: { closedAt: 'desc' },
  });

  const sessionIds = sessions.map((s) => s.id);
  const salesBySession =
    sessionIds.length === 0
      ? []
      : await prisma.sale.groupBy({
          by: ['sessionId'],
          _sum: { total: true },
          _count: { _all: true },
          where: {
            companyId,
            sessionId: { in: sessionIds },
            status: { not: 'cancelled' },
          },
        });

  return sessions.map((session) => {
    const saleAggregate = salesBySession.find((s) => s.sessionId === session.id);
    const totalSales = toNumber(saleAggregate?._sum.total);
    const salesCount = saleAggregate?._count._all ?? 0;
    return {
      id: session.id,
      openedAt: session.openedAt,
      closedAt: session.closedAt,
      userName: session.userName,
      openedBy: session.openedBy,
      closedBy: session.closedBy,
      totalSales,
      salesCount,
      closingAmount: toNumber(session.closingAmount),
      expectedCash: toNumber(session.expectedCash),
      difference: toNumber(session.difference),
    };
  });
}

export async function getCashClosingDetail(companyId: number, closingId: number) {
  const session = await prisma.cashSession.findFirst({
    where: { id: closingId, companyId },
    include: {
      openedBy: { select: { id: true, username: true, displayName: true } },
      closedBy: { select: { id: true, username: true, displayName: true } },
    },
  });

  if (!session) {
    throw { status: 404, message: 'Cierre no encontrado' };
  }

  const [sales, movements] = await Promise.all([
    prisma.sale.findMany({
      where: { companyId, sessionId: session.id, status: { not: 'cancelled' } },
      select: {
        id: true,
        total: true,
        paymentMethod: true,
        createdAt: true,
      },
      orderBy: { createdAt: 'asc' },
    }),
    prisma.cashMovement.findMany({
      where: { companyId, sessionId: session.id },
      orderBy: { createdAt: 'asc' },
    }),
  ]);

  const paymentBreakdown = sales.reduce<Record<string, number>>((acc, sale) => {
    const key = sale.paymentMethod ?? 'otros';
    acc[key] = (acc[key] ?? 0) + toNumber(sale.total);
    return acc;
  }, {});

  const totalSales = sales.reduce((sum, sale) => sum + toNumber(sale.total), 0);

  return {
    session: {
      id: session.id,
      openedAt: session.openedAt,
      closedAt: session.closedAt,
      initialAmount: toNumber(session.initialAmount),
      closingAmount: toNumber(session.closingAmount),
      expectedCash: toNumber(session.expectedCash),
      difference: toNumber(session.difference),
      status: session.status,
      note: session.note,
      openedBy: session.openedBy,
      closedBy: session.closedBy,
      paymentSummary: session.paymentSummary,
    },
    totals: {
      totalSales,
      paymentBreakdown,
    },
    sales,
    movements: movements.map((mov) => ({
      id: mov.id,
      type: mov.type,
      amount: toNumber(mov.amount),
      note: mov.note,
      createdAt: mov.createdAt,
    })),
  };
}

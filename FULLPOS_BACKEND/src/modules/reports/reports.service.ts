import { prisma } from '../../config/prisma';
import { parseRange, ensureRangeWithinDays } from '../../utils/date';
import { formatInTimeZone } from 'date-fns-tz';
import { buildPagination } from '../../utils/pagination';

const MAX_RANGE_DAYS = 365;
const REPORTS_TIMEZONE = process.env.REPORTS_TIMEZONE || 'America/Santo_Domingo';

function toNumber(value: any) {
  if (value === null || value === undefined) return 0;
  if (typeof value === 'number') return value;
  if (typeof value === 'string') return Number(value);
  if (typeof (value as any).toNumber === 'function') return (value as any).toNumber();
  return Number(value);
}

function toNullableNumber(value: any): number | null {
  if (value === null || value === undefined) return null;
  return toNumber(value);
}

function normalizeKey(value: any): string {
  return String(value ?? '').trim().toLowerCase();
}

function isCashPaymentMethod(paymentMethod: string | null | undefined): boolean {
  const key = normalizeKey(paymentMethod);
  return key === 'cash' || key === 'efectivo' || key === 'contado';
}

function isMovementIn(type: string | null | undefined): boolean {
  const key = normalizeKey(type);
  return key === 'in' || key === 'entrada' || key === 'deposito' || key === 'depósito';
}

function isMovementOut(type: string | null | undefined): boolean {
  const key = normalizeKey(type);
  return key === 'out' || key === 'retiro' || key === 'salida';
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
        where: {
          companyId,
          kind: { in: ['invoice', 'sale'] },
          status: { in: ['completed', 'PAID', 'PARTIAL_REFUND'] },
          deletedAt: null,
          createdAt: { gte: fromDate, lte: toDate },
        },
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
      kind: { in: ['invoice', 'sale'] },
      status: { in: ['completed', 'PAID', 'PARTIAL_REFUND'] },
      deletedAt: null,
      createdAt: { gte: fromDate, lte: toDate },
    },
  });

  const total = toNumber(result._sum.total);
  const count = result._count._all;
  const average = count > 0 ? total / count : 0;

  // Total cost of goods sold (COGS) based on SaleItem snapshots.
  const costRows = await prisma.$queryRaw<{ totalCost: any }[]>`
    SELECT COALESCE(SUM(si."purchasePriceSnapshot" * si."qty"), 0) AS "totalCost"
    FROM "SaleItem" si
    INNER JOIN "Sale" s ON s.id = si."saleId"
    WHERE s."companyId" = ${companyId}
      AND s."deletedAt" IS NULL
      AND s."kind" IN ('invoice','sale')
      AND s."status" IN ('completed','PAID','PARTIAL_REFUND')
      AND s."createdAt" >= ${fromDate}
      AND s."createdAt" <= ${toDate}
  `;

  const totalCost = toNumber(costRows?.[0]?.totalCost);
  const profit = total - totalCost;

  return { total, count, average, totalCost, profit };
}

export async function getSalesByDay(companyId: number, from: string, to: string) {
  const { fromDate, toDate } = parseRange(from, to);
  ensureRangeWithinDays(fromDate, toDate, MAX_RANGE_DAYS);

  const sales = await prisma.sale.findMany({
    where: {
      companyId,
      kind: { in: ['invoice', 'sale'] },
      status: { in: ['completed', 'PAID', 'PARTIAL_REFUND'] },
      deletedAt: null,
      createdAt: { gte: fromDate, lte: toDate },
    },
    select: { id: true, total: true, createdAt: true },
    orderBy: { createdAt: 'asc' },
  });

  const byDay = new Map<string, { total: number; count: number }>();
  for (const sale of sales) {
    // Agrupar por día en timezone de negocio (no depende del timezone del servidor).
    const key = formatInTimeZone(sale.createdAt, REPORTS_TIMEZONE, 'yyyy-MM-dd');
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
        kind: { in: ['invoice', 'sale'] },
        status: { in: ['completed', 'PAID', 'PARTIAL_REFUND'] },
        deletedAt: null,
        createdAt: { gte: fromDate, lte: toDate },
      },
    }),
    prisma.sale.findMany({
      where: {
        companyId,
        kind: { in: ['invoice', 'sale'] },
        status: { in: ['completed', 'PAID', 'PARTIAL_REFUND'] },
        deletedAt: null,
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
      closingAmount: toNullableNumber(session.closingAmount),
      expectedCash: toNullableNumber(session.expectedCash),
      difference: toNullableNumber(session.difference),
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

  // Calcular esperado/diferencia si el POS aún no lo sincronizó.
  // Aproximación: inicial + ventas en efectivo + neto movimientos.
  const openingAmount = toNumber(session.initialAmount);
  const cashSalesTotal = sales.reduce((sum, sale) => {
    if (!isCashPaymentMethod(sale.paymentMethod)) return sum;
    return sum + toNumber(sale.total);
  }, 0);
  const movementsInTotal = movements.reduce((sum, mov) => {
    if (!isMovementIn(mov.type)) return sum;
    return sum + toNumber(mov.amount);
  }, 0);
  const movementsOutTotal = movements.reduce((sum, mov) => {
    if (!isMovementOut(mov.type)) return sum;
    return sum + toNumber(mov.amount);
  }, 0);
  const computedExpectedCash = openingAmount + cashSalesTotal + movementsInTotal - movementsOutTotal;

  const closingAmount = toNullableNumber(session.closingAmount);
  const storedExpectedCash = toNullableNumber(session.expectedCash);
  const expectedCash = storedExpectedCash ?? computedExpectedCash;
  const storedDifference = toNullableNumber(session.difference);
  const difference = storedDifference ?? (closingAmount != null ? closingAmount - expectedCash : null);

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
      closingAmount,
      expectedCash,
      difference,
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

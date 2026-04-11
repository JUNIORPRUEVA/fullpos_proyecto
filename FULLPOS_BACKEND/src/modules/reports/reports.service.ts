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
    customerName: sale.customerNameSnapshot,
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

export async function getSaleDetail(companyId: number, saleId: number) {
  const sale = await prisma.sale.findFirst({
    where: {
      id: saleId,
      companyId,
      kind: { in: ['invoice', 'sale'] },
    },
    include: {
      session: true,
      createdBy: { select: { id: true, username: true, displayName: true } },
      items: {
        include: {
          product: { select: { id: true, code: true, name: true } },
        },
        orderBy: { id: 'asc' },
      },
    },
  });

  if (!sale) {
    throw { status: 404, message: 'Venta no encontrada' };
  }

  const items = sale.items.map((item) => {
    const qty = toNumber(item.qty);
    const unitPrice = toNumber(item.unitPrice);
    const cost = toNumber(item.purchasePriceSnapshot);
    const discountLine = toNumber(item.discountLine);
    const totalLine = toNumber(item.totalLine);
    const lineCost = qty * cost;
    const lineProfit = totalLine - lineCost;
    return {
      id: item.id,
      productId: item.productId,
      productCodeSnapshot: item.productCodeSnapshot ?? item.product?.code ?? null,
      productNameSnapshot: item.productNameSnapshot,
      qty,
      unitPrice,
      purchasePriceSnapshot: cost,
      discountLine,
      totalLine,
      lineCost,
      lineProfit,
      createdAt: item.createdAt,
    };
  });

  const totalCost = items.reduce((sum, item) => sum + item.lineCost, 0);
  const profit = toNumber(sale.total) - totalCost;

  return {
    id: sale.id,
    localCode: sale.localCode,
    kind: sale.kind,
    status: sale.status,
    customerName: sale.customerNameSnapshot,
    customerPhone: sale.customerPhoneSnapshot,
    customerRnc: sale.customerRncSnapshot,
    subtotal: toNumber(sale.subtotal),
    discountTotal: toNumber(sale.discountTotal),
    itbisAmount: toNumber(sale.itbisAmount),
    itbisRate: toNumber(sale.itbisRate),
    total: toNumber(sale.total),
    totalCost,
    profit,
    paymentMethod: sale.paymentMethod,
    paidAmount: toNumber(sale.paidAmount),
    changeAmount: toNumber(sale.changeAmount),
    fiscalEnabled: sale.fiscalEnabled,
    ncfFull: sale.ncfFull,
    ncfType: sale.ncfType,
    sessionId: sale.sessionId,
    sessionStatus: sale.session?.status,
    createdAt: sale.createdAt,
    updatedAt: sale.updatedAt,
    deletedAt: sale.deletedAt,
    user: sale.createdBy
      ? {
          id: sale.createdBy.id,
          username: sale.createdBy.username,
          displayName: sale.createdBy.displayName,
        }
      : null,
    items,
  };
}

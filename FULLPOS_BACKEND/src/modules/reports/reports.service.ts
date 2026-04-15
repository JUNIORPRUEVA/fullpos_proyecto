import { Prisma } from '@prisma/client';
import { prisma } from '../../config/prisma';
import { parseRange, ensureRangeWithinDays } from '../../utils/date';
import { formatInTimeZone } from 'date-fns-tz';
import { buildPagination } from '../../utils/pagination';

const MAX_RANGE_DAYS = 365;
const REPORTS_TIMEZONE = process.env.REPORTS_TIMEZONE || 'America/Santo_Domingo';
const REPORT_SALE_KINDS = ['invoice', 'sale'];
// Fully refunded sales should disappear from owner sales reports, while
// partially refunded sales must remain visible with their updated status.
const REPORT_SALE_STATUSES = ['completed', 'PAID', 'PARTIAL_REFUND'] as const;

const reportSaleInclude = {
  session: {
    select: {
      status: true,
      openedAt: true,
    },
  },
  createdBy: {
    select: {
      id: true,
      username: true,
      displayName: true,
    },
  },
} satisfies Prisma.SaleInclude;

type ReportSaleRow = Prisma.SaleGetPayload<{
  include: typeof reportSaleInclude;
}>;

function getReportSalesWhere(companyId: number, fromDate: Date, toDate: Date): Prisma.SaleWhereInput {
  return {
    companyId,
    kind: { in: [...REPORT_SALE_KINDS] },
    status: { in: [...REPORT_SALE_STATUSES] },
    deletedAt: null,
    createdAt: { gte: fromDate, lte: toDate },
  };
}

function getReportExpensesWhere(
  companyId: number,
  fromDate: Date,
  toDate: Date,
): Prisma.CashMovementWhereInput {
  return {
    companyId,
    type: 'out',
    movementType: 'expense',
    affectsProfit: true,
    createdAt: { gte: fromDate, lte: toDate },
  };
}

async function listReportSales(companyId: number, fromDate: Date, toDate: Date) {
  const rows: ReportSaleRow[] = await prisma.sale.findMany({
    where: getReportSalesWhere(companyId, fromDate, toDate),
    include: reportSaleInclude,
    orderBy: { createdAt: 'desc' },
  });

  return rows.map((sale) => ({
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
}

async function listReportExpenses(companyId: number, fromDate: Date, toDate: Date) {
  const rows = await prisma.cashMovement.findMany({
    where: getReportExpensesWhere(companyId, fromDate, toDate),
    select: {
      id: true,
      amount: true,
      note: true,
      createdAt: true,
    },
    orderBy: { createdAt: 'asc' },
  });

  return rows.map((row) => ({
    id: row.id,
    amount: toNumber(row.amount),
    note: row.note,
    createdAt: row.createdAt,
  }));
}

function buildSalesByDay(sales: Array<{ createdAt: Date; total: number }>) {
  const byDay = new Map<string, { total: number; count: number }>();

  for (const sale of sales) {
    const key = formatInTimeZone(sale.createdAt, REPORTS_TIMEZONE, 'yyyy-MM-dd');
    const entry = byDay.get(key) ?? { total: 0, count: 0 };
    entry.total += sale.total;
    entry.count += 1;
    byDay.set(key, entry);
  }

  return Array.from(byDay.entries()).map(([date, info]) => ({
    date,
    total: info.total,
    count: info.count,
  }));
}

export async function getReportData(companyId: number, from: string, to: string) {
  const { fromDate, toDate } = parseRange(from, to);
  ensureRangeWithinDays(fromDate, toDate, MAX_RANGE_DAYS);

  const [sales, expenses] = await Promise.all([
    listReportSales(companyId, fromDate, toDate),
    listReportExpenses(companyId, fromDate, toDate),
  ]);

  const totalSales = sales.reduce((sum, sale) => sum + sale.total, 0);
  const totalExpenses = expenses.reduce((sum, expense) => sum + expense.amount, 0);
  const salesCount = sales.length;
  const averageTicket = salesCount > 0 ? totalSales / salesCount : 0;
  const profit = totalSales - totalExpenses;

  return {
    sales,
    expenses,
    salesByDay: buildSalesByDay(sales),
    totalSales,
    totalExpenses,
    profit,
    salesCount,
    averageTicket,
  };
}
function toNumber(value: any) {
  if (value === null || value === undefined) return 0;
  if (typeof value === 'number') return value;
  if (typeof value === 'string') return Number(value);
  if (typeof (value as any).toNumber === 'function') return (value as any).toNumber();
  return Number(value);
}

function calculateProfit(revenue: number, cost: number, expenses: number) {
  return revenue - cost - expenses;
}

function calculateDeferredTotalDue(sale: {
  total: any;
  paymentMethod: string | null | undefined;
  creditInterestRate?: any;
}) {
  const total = toNumber(sale.total);
  const paymentMethod = (sale.paymentMethod ?? '').trim().toLowerCase();
  if (paymentMethod === 'credit') {
    return total + (total * toNumber(sale.creditInterestRate) / 100);
  }
  return total;
}

function allocateExpenseShare(totalExpenses: number, revenue: number, revenueBase: number) {
  if (Math.abs(totalExpenses) <= 0.009 || revenue <= 0 || revenueBase <= 0) {
    return 0;
  }
  return totalExpenses * (revenue / revenueBase);
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
          status: { in: [...REPORT_SALE_STATUSES] },
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
  const report = await getReportData(companyId, from, to);

  return {
    total: report.totalSales,
    count: report.salesCount,
    average: report.averageTicket,
    totalCost: 0,
    profit: report.profit,
    expenses: report.totalExpenses,
    paymentsReceived: 0,
    creditPaymentsReceived: 0,
    layawayPaymentsReceived: 0,
    paymentsCount: 0,
    paymentFlow: {
      totalReceived: 0,
      creditReceived: 0,
      layawayReceived: 0,
      count: 0,
    },
  };
}

export async function getSalesByDay(companyId: number, from: string, to: string) {
  const report = await getReportData(companyId, from, to);
  return report.salesByDay;
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

  const allSales = await listReportSales(companyId, fromDate, toDate);
  const totalCount = allSales.length;
  const data = allSales.slice(skip, skip + take);

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
      payments: {
        include: {
          creditPayment: true,
          layawayPayment: true,
        },
        orderBy: { postedAt: 'asc' },
      },
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

  const saleTotal = toNumber(sale.total);
  const [sessionRevenueAggregate, sessionExpenseAggregate] = sale.sessionId
    ? await Promise.all([
        prisma.sale.aggregate({
          _sum: { total: true },
          where: {
            companyId,
            sessionId: sale.sessionId,
            kind: { in: ['invoice', 'sale'] },
            status: { in: [...REPORT_SALE_STATUSES] },
            deletedAt: null,
          },
        }),
        prisma.cashMovement.aggregate({
          _sum: { amount: true },
          where: {
            companyId,
            sessionId: sale.sessionId,
            type: 'out',
            movementType: 'expense',
            affectsProfit: true,
          },
        }),
      ])
    : [null, null] as const;
  const sessionRevenue = toNumber(sessionRevenueAggregate?._sum.total);
  const allocatedExpenses = allocateExpenseShare(
    toNumber(sessionExpenseAggregate?._sum.amount),
    saleTotal,
    sessionRevenue,
  );
  const lineRevenueBase = sale.items.reduce((sum, item) => sum + Math.max(toNumber(item.totalLine), 0), 0);
  let remainingRevenue = saleTotal;
  let remainingExpenses = allocatedExpenses;

  const items = sale.items.map((item, index) => {
    const qty = toNumber(item.qty);
    const unitPrice = toNumber(item.unitPrice);
    const cost = toNumber(item.purchasePriceSnapshot);
    const discountLine = toNumber(item.discountLine);
    const totalLine = toNumber(item.totalLine);
    const lineCost = qty * cost;
    const isLastItem = index === sale.items.length - 1;
    const revenueWeight = Math.max(totalLine, 0);
    const revenueShare = isLastItem
      ? remainingRevenue
      : lineRevenueBase > 0
        ? saleTotal * (revenueWeight / lineRevenueBase)
        : sale.items.length > 0
          ? saleTotal / sale.items.length
          : 0;
    const expenseShare = isLastItem
      ? remainingExpenses
      : lineRevenueBase > 0
        ? allocatedExpenses * (revenueWeight / lineRevenueBase)
        : sale.items.length > 0
          ? allocatedExpenses / sale.items.length
          : 0;
    remainingRevenue -= revenueShare;
    remainingExpenses -= expenseShare;
    const lineProfit = calculateProfit(revenueShare, lineCost, expenseShare);
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
  const profit = calculateProfit(saleTotal, totalCost, allocatedExpenses);
  const totalDue = calculateDeferredTotalDue(sale);
  const deferredPayments = sale.payments.map((payment) => ({
    id: payment.id,
    kind: payment.kind,
    method: payment.method,
    amount: toNumber(payment.amount),
    note: payment.note,
    postedAt: payment.postedAt,
    creditPayment: payment.creditPayment
      ? {
          totalDueSnapshot: toNumber(payment.creditPayment.totalDueSnapshot),
          totalPaidSnapshot: toNumber(payment.creditPayment.totalPaidSnapshot),
          pendingAmountSnapshot: toNumber(payment.creditPayment.pendingAmountSnapshot),
        }
      : null,
    layawayPayment: payment.layawayPayment
      ? {
          totalDueSnapshot: toNumber(payment.layawayPayment.totalDueSnapshot),
          totalPaidSnapshot: toNumber(payment.layawayPayment.totalPaidSnapshot),
          pendingAmountSnapshot: toNumber(payment.layawayPayment.pendingAmountSnapshot),
          statusSnapshot: payment.layawayPayment.statusSnapshot,
        }
      : null,
  }));
  const deferredPaymentsReceived = deferredPayments.reduce((sum, payment) => sum + payment.amount, 0);
  const paymentCollectionsReceived = deferredPayments.length > 0
    ? deferredPaymentsReceived
    : toNumber(sale.paidAmount);
  const pendingAmount = Math.max(0, totalDue - paymentCollectionsReceived);

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
    total: saleTotal,
    totalCost,
    profit,
    paymentMethod: sale.paymentMethod,
    paidAmount: toNumber(sale.paidAmount),
    changeAmount: toNumber(sale.changeAmount),
    creditInterestRate: toNumber(sale.creditInterestRate),
    creditTermDays: sale.creditTermDays,
    creditDueDate: sale.creditDueDate,
    creditInstallments: sale.creditInstallments,
    creditNote: sale.creditNote,
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
    payments: deferredPayments,
    paymentSummary: {
      totalDue,
      totalReceived: paymentCollectionsReceived,
      pendingAmount,
      paymentsCount: deferredPayments.length,
      creditReceived: deferredPayments
        .filter((payment) => payment.kind === 'credit')
        .reduce((sum, payment) => sum + payment.amount, 0),
      layawayReceived: deferredPayments
        .filter((payment) => payment.kind === 'layaway')
        .reduce((sum, payment) => sum + payment.amount, 0),
    },
    items,
  };
}

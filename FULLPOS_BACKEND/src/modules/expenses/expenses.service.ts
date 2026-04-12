import { prisma } from '../../config/prisma';
import { ensureRangeWithinDays, parseRange } from '../../utils/date';

const MAX_RANGE_DAYS = 365;

function toNumber(value: any) {
  if (value === null || value === undefined) return 0;
  if (typeof value === 'number') return value;
  if (typeof value === 'string') return Number(value);
  if (typeof (value as any).toNumber === 'function') return (value as any).toNumber();
  return Number(value);
}

const cashExpenseTypes = [
  'out',
  'OUT',
  'retiro',
  'RETIRO',
  'salida',
  'SALIDA',
  'egreso',
  'EGRESO',
];

export async function getExpensesSummary(companyId: number, from: string, to: string) {
  const { fromDate, toDate } = parseRange(from, to);
  ensureRangeWithinDays(fromDate, toDate, MAX_RANGE_DAYS);

  const [expenseResult, cashMovementResult] = await Promise.all([
    prisma.expense.aggregate({
      _sum: { amount: true },
      _count: { _all: true },
      where: {
        companyId,
        incurredAt: { gte: fromDate, lte: toDate },
      },
    }),
    prisma.cashMovement.aggregate({
      _sum: { amount: true },
      _count: { _all: true },
      where: {
        companyId,
        type: { in: cashExpenseTypes },
        createdAt: { gte: fromDate, lte: toDate },
      },
    }),
  ]);

  const expenseCount = expenseResult._count._all;
  if (expenseCount > 0) {
    return {
      total: toNumber(expenseResult._sum.amount),
      count: expenseCount,
    };
  }

  return {
    total: toNumber(cashMovementResult._sum.amount),
    count: cashMovementResult._count._all,
  };
}

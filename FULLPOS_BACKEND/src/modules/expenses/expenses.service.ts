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

export async function getExpensesSummary(companyId: number, from: string, to: string) {
  const { fromDate, toDate } = parseRange(from, to);
  ensureRangeWithinDays(fromDate, toDate, MAX_RANGE_DAYS);

  const cashMovementResult = await prisma.cashMovement.aggregate({
    _sum: { amount: true },
    _count: { _all: true },
    where: {
      companyId,
      type: 'out',
      movementType: 'expense',
      affectsProfit: true,
      createdAt: { gte: fromDate, lte: toDate },
    },
  });

  return {
    total: toNumber(cashMovementResult._sum.amount),
    count: cashMovementResult._count._all,
  };
}

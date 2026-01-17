import { isAfter, isBefore, parseISO, startOfDay, endOfDay } from 'date-fns';

export function parseRange(from: string, to: string) {
  const fromDate = startOfDay(parseISO(from));
  const toDate = endOfDay(parseISO(to));

  if (Number.isNaN(fromDate.getTime()) || Number.isNaN(toDate.getTime())) {
    throw new Error('Rango de fechas inv\u00e1lido');
  }

  if (isAfter(fromDate, toDate)) {
    throw new Error('from must be before or equal to to');
  }

  return { fromDate, toDate };
}

export function ensureRangeWithinDays(fromDate: Date, toDate: Date, maxDays: number) {
  const limitDate = new Date(fromDate);
  limitDate.setDate(limitDate.getDate() + maxDays);
  if (isBefore(limitDate, toDate)) {
    throw new Error(`Range cannot exceed ${maxDays} days`);
  }
}

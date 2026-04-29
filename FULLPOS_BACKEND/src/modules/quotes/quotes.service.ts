import { Prisma } from '@prisma/client';
import { prisma } from '../../config/prisma';
import { parseRange, ensureRangeWithinDays } from '../../utils/date';
import { buildPagination } from '../../utils/pagination';
import { emitQuoteEvent } from '../../realtime/realtime.gateway';
import { CompanyIdentityLookup, resolveCompanyIdentityId } from '../companies/companyIdentity.service';

const MAX_RANGE_DAYS = 365;

function toNumber(value: any) {
  if (value === null || value === undefined) return 0;
  if (typeof value === 'number') return value;
  if (typeof value === 'string') return Number(value);
  if (typeof (value as any).toNumber === 'function') return (value as any).toNumber();
  return Number(value);
}

function sameDate(a: Date | null | undefined, b: Date | null | undefined) {
  return (a?.getTime() ?? null) === (b?.getTime() ?? null);
}

function toQuoteRealtimePayload(quote: {
  id: number;
  localId: number;
  clientNameSnapshot: string;
  total: number | Prisma.Decimal;
  status: string;
  createdAt: Date;
  updatedAt: Date;
}) {
  return {
    id: quote.id,
    localId: quote.localId,
    clientNameSnapshot: quote.clientNameSnapshot,
    total: toNumber(quote.total),
    status: quote.status,
    createdAt: quote.createdAt,
    updatedAt: quote.updatedAt,
  };
}

export async function listQuotes(
  companyId: number,
  from: string,
  to: string,
  page = 1,
  pageSize = 20,
) {
  const { fromDate, toDate } = parseRange(from, to);
  ensureRangeWithinDays(fromDate, toDate, MAX_RANGE_DAYS);
  const { skip, take, page: safePage } = buildPagination(page, pageSize);

  const where = {
    companyId,
    createdAt: { gte: fromDate, lte: toDate },
  } as const;

  const [total, rows] = await Promise.all([
    prisma.quote.count({ where }),
    prisma.quote.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip,
      take,
      include: { items: true },
    }),
  ]);

  return {
    data: rows.map((q) => ({
      id: q.id,
      localId: q.localId,
      clientNameSnapshot: q.clientNameSnapshot,
      clientPhoneSnapshot: q.clientPhoneSnapshot,
      clientRncSnapshot: q.clientRncSnapshot,
      ticketName: q.ticketName,
      subtotal: toNumber(q.subtotal),
      itbisEnabled: q.itbisEnabled,
      itbisRate: toNumber(q.itbisRate),
      itbisAmount: toNumber(q.itbisAmount),
      discountTotal: toNumber(q.discountTotal),
      total: toNumber(q.total),
      status: q.status,
      notes: q.notes,
      createdAt: q.createdAt,
      updatedAt: q.updatedAt,
      items: q.items.map((i) => ({
        id: i.id,
        localId: i.localId,
        productCodeSnapshot: i.productCodeSnapshot,
        productNameSnapshot: i.productNameSnapshot,
        description: i.description,
        qty: toNumber(i.qty),
        unitPrice: toNumber(i.unitPrice),
        price: toNumber(i.price),
        cost: toNumber(i.cost),
        discountLine: toNumber(i.discountLine),
        totalLine: toNumber(i.totalLine),
      })),
    })),
    total,
    page: safePage,
    pageSize: take,
  };
}

export type SyncQuoteInput = {
  localId: number;
  clientNameSnapshot: string;
  clientPhoneSnapshot?: string | null;
  clientRncSnapshot?: string | null;
  ticketName?: string | null;
  subtotal: number;
  itbisEnabled: boolean;
  itbisRate: number;
  itbisAmount: number;
  discountTotal: number;
  total: number;
  status: string;
  notes?: string | null;
  createdAt: string;
  updatedAt: string;
  items: Array<{
    localId?: number | null;
    productCodeSnapshot?: string | null;
    productNameSnapshot: string;
    description: string;
    qty: number;
    unitPrice: number;
    price: number;
    cost?: number;
    discountLine?: number;
    totalLine: number;
  }>;
};

export async function syncQuotesByRnc(
  identity: CompanyIdentityLookup,
  quotes: SyncQuoteInput[],
) {
  const companyId = await resolveCompanyIdentityId(identity, 'quotes.sync');
  if (!quotes || quotes.length === 0) {
    return { ok: true, upserted: 0, companyId };
  }

  const localIds = Array.from(new Set(quotes.map((quote) => quote.localId)));
  const existingQuotes =
    localIds.length === 0
      ? []
      : await prisma.quote.findMany({
          where: { companyId, localId: { in: localIds } },
          select: {
            id: true,
            localId: true,
            clientNameSnapshot: true,
            total: true,
            status: true,
            updatedAt: true,
          },
        });
  const existingQuoteMap = new Map(existingQuotes.map((quote) => [quote.localId, quote]));
  const realtimeEvents: Array<{
    type: 'quote.created' | 'quote.updated';
    quote: ReturnType<typeof toQuoteRealtimePayload>;
  }> = [];

  await prisma.$transaction(async (tx) => {
    for (const q of quotes) {
      const createdAt = new Date(q.createdAt);
      const updatedAt = new Date(q.updatedAt);
      const previous = existingQuoteMap.get(q.localId) ?? null;

      const upserted = await tx.quote.upsert({
        where: { companyId_localId: { companyId, localId: q.localId } },
        update: {
          clientNameSnapshot: q.clientNameSnapshot,
          clientPhoneSnapshot: q.clientPhoneSnapshot ?? null,
          clientRncSnapshot: q.clientRncSnapshot ?? null,
          ticketName: q.ticketName ?? null,
          subtotal: q.subtotal,
          itbisEnabled: q.itbisEnabled,
          itbisRate: q.itbisRate,
          itbisAmount: q.itbisAmount,
          discountTotal: q.discountTotal,
          total: q.total,
          status: q.status,
          notes: q.notes ?? null,
          updatedAt,
        },
        create: {
          companyId,
          localId: q.localId,
          clientNameSnapshot: q.clientNameSnapshot,
          clientPhoneSnapshot: q.clientPhoneSnapshot ?? null,
          clientRncSnapshot: q.clientRncSnapshot ?? null,
          ticketName: q.ticketName ?? null,
          subtotal: q.subtotal,
          itbisEnabled: q.itbisEnabled,
          itbisRate: q.itbisRate,
          itbisAmount: q.itbisAmount,
          discountTotal: q.discountTotal,
          total: q.total,
          status: q.status,
          notes: q.notes ?? null,
          createdAt,
          updatedAt,
        },
        select: {
          id: true,
          localId: true,
          clientNameSnapshot: true,
          total: true,
          status: true,
          createdAt: true,
          updatedAt: true,
        },
      });

      const changed =
        !previous ||
        previous.clientNameSnapshot !== upserted.clientNameSnapshot ||
        toNumber(previous.total) !== toNumber(upserted.total) ||
        previous.status !== upserted.status ||
        !sameDate(previous.updatedAt, upserted.updatedAt);

      if (changed) {
        realtimeEvents.push({
          type: previous == null ? 'quote.created' : 'quote.updated',
          quote: toQuoteRealtimePayload(upserted),
        });
      }

      await tx.quoteItem.deleteMany({ where: { quoteId: upserted.id } });
      if (q.items && q.items.length > 0) {
        await tx.quoteItem.createMany({
          data: q.items.map((i) => ({
            quoteId: upserted.id,
            localId: i.localId ?? null,
            productCodeSnapshot: i.productCodeSnapshot ?? null,
            productNameSnapshot: i.productNameSnapshot,
            description: i.description,
            qty: i.qty,
            unitPrice: i.unitPrice,
            price: i.price,
            cost: i.cost ?? 0,
            discountLine: i.discountLine ?? 0,
            totalLine: i.totalLine,
          })),
        });
      }
    }
  });

  for (const event of realtimeEvents) {
    emitQuoteEvent({
      companyId,
      type: event.type,
      quote: event.quote,
    });
  }

  return { ok: true, upserted: quotes.length, companyId };
}

import { Prisma } from '@prisma/client';
import { prisma } from '../../config/prisma';

function toNumber(value: Prisma.Decimal | number | null) {
  if (value === null || value === undefined) return 0;
  if (typeof value === 'number') return value;
  return value.toNumber();
}

type CursorPayload = { updatedAt: string; id: number };

function encodeCursor(payload: CursorPayload) {
  return Buffer.from(JSON.stringify(payload)).toString('base64url');
}

function decodeCursor(value: string): CursorPayload {
  const parsed = JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
  const updatedAt = typeof parsed?.updatedAt === 'string' ? parsed.updatedAt : '';
  const id = typeof parsed?.id === 'number' ? parsed.id : Number(parsed?.id);
  if (!updatedAt || !Number.isFinite(id)) {
    throw new Error('Invalid cursor');
  }
  return { updatedAt, id };
}

export async function listIntegrationProducts(
  companyId: number,
  input: { limit?: number; updatedSince?: Date; cursor?: string },
) {
  const limit = input.limit && input.limit > 0 ? Math.min(input.limit, 500) : 200;

  const baseWhere: any = {
    companyId,
    isDemo: false,
    ...(input.updatedSince
      ? {
          updatedAt: {
            gt: input.updatedSince,
          },
        }
      : {}),
  };

  let cursorWhere: any = {};
  if (input.cursor) {
    const decoded = decodeCursor(input.cursor);
    const cursorUpdatedAt = new Date(decoded.updatedAt);
    if (!Number.isFinite(cursorUpdatedAt.getTime())) {
      throw new Error('Invalid cursor');
    }
    cursorWhere = {
      OR: [
        { updatedAt: { gt: cursorUpdatedAt } },
        { updatedAt: cursorUpdatedAt, id: { gt: decoded.id } },
      ],
    };
  }

  const where = {
    ...baseWhere,
    ...(Object.keys(cursorWhere).length ? cursorWhere : {}),
  };

  const rows = await prisma.product.findMany({
    where,
    orderBy: [{ updatedAt: 'asc' }, { id: 'asc' }],
    take: limit + 1,
  });

  const hasMore = rows.length > limit;
  const items = hasMore ? rows.slice(0, limit) : rows;
  const last = items[items.length - 1];

  return {
    items: items.map((p) => ({
      id: p.id,
      sku: p.code,
      barcode: p.code,
      name: p.name,
      price: toNumber(p.price),
      cost: toNumber(p.cost),
      stock: toNumber(p.stock),
      image_url: p.imageUrl,
      active: true,
      updated_at: p.updatedAt,
    })),
    next_cursor: hasMore && last ? encodeCursor({ updatedAt: last.updatedAt.toISOString(), id: last.id }) : null,
  };
}

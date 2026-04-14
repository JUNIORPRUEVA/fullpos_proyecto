import { Prisma } from '@prisma/client';
import { prisma } from '../../config/prisma';
import { emitSaleEvent } from '../../realtime/realtime.gateway';

function toNumber(value: Prisma.Decimal | number | null | undefined) {
  if (value === null || value === undefined) return 0;
  if (typeof value === 'number') return value;
  return value.toNumber();
}

function normalizeRnc(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function generateReturnLocalCode() {
  const raw = Date.now().toString();
  return `DEV-${raw.length > 6 ? raw.substring(6) : raw}`;
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

async function resolveCompanyId(companyRnc?: string, companyCloudId?: string) {
  const rnc = companyRnc?.trim() ?? '';
  const cloudId = companyCloudId?.trim() ?? '';
  if (!rnc && !cloudId) {
    throw { status: 400, message: 'RNC o ID interno requerido' };
  }

  let company = null as { id: number; rnc: string | null } | null;

  if (cloudId) {
    company = await prisma.company.findFirst({
      where: { cloudCompanyId: cloudId },
      select: { id: true, rnc: true },
    });
  }

  if (!company && rnc) {
    company = await prisma.company.findFirst({
      where: { rnc },
      select: { id: true, rnc: true },
    });

    if (!company) {
      const normalized = normalizeRnc(rnc);
      if (normalized.length > 0) {
        const candidates = await prisma.company.findMany({
          where: { rnc: { not: null } },
          select: { id: true, rnc: true },
        });
        company =
          candidates.find(
            (item) => item.rnc != null && normalizeRnc(item.rnc) === normalized,
          ) ?? null;
      }
    }
  }

  if (!company) {
    throw { status: 404, message: 'Empresa no encontrada' };
  }

  return company.id;
}

function calculateReturnAmounts(params: {
  itbisEnabled: boolean;
  itbisRate: Prisma.Decimal | number;
  items: Array<{ qty: number; price: number }>;
}) {
  const subtotal = params.items.reduce((sum, item) => sum + (item.qty * item.price), 0);
  const rate = toNumber(params.itbisRate);
  const tax = params.itbisEnabled ? subtotal * rate : 0;
  return {
    subtotal,
    itbisAmount: tax,
    total: subtotal + tax,
  };
}

async function updateOriginalSaleStatus(tx: Prisma.TransactionClient, originalSaleId: number) {
  const existingReturns = await tx.return.count({ where: { originalSaleId } });
  const newStatus = existingReturns > 1 ? 'PARTIAL_REFUND' : 'REFUNDED';
  await tx.sale.update({
    where: { id: originalSaleId },
    data: { status: newStatus },
  });
}

async function applyStockDelta(
  tx: Prisma.TransactionClient,
  previousItems: Array<{ productId: number | null; qty: Prisma.Decimal | number }>,
  nextItems: Array<{ productId: number | null; qty: number }>,
) {
  const deltaByProduct = new Map<number, number>();

  for (const item of previousItems) {
    if (!item.productId) continue;
    deltaByProduct.set(
      item.productId,
      (deltaByProduct.get(item.productId) ?? 0) - toNumber(item.qty),
    );
  }

  for (const item of nextItems) {
    if (!item.productId) continue;
    deltaByProduct.set(
      item.productId,
      (deltaByProduct.get(item.productId) ?? 0) + item.qty,
    );
  }

  for (const [productId, delta] of deltaByProduct.entries()) {
    if (Math.abs(delta) <= 0.0001) continue;
    await tx.product.update({
      where: { id: productId },
      data: { stock: { increment: delta } },
    });
  }
}

export type CreateReturnInput = {
  originalSaleId: number;
  cashSessionId?: number | null;
  note?: string | null;
  returnItems: Array<{
    saleItemId?: number | null;
    productId?: number | null;
    description: string;
    qty: number;
    price: number;
    total?: number;
  }>;
};

export type SyncReturnInput = {
  localId: number;
  originalSaleLocalCode: string;
  returnSaleLocalCode: string;
  sessionLocalId?: number | null;
  note?: string | null;
  createdAt: string;
  items: Array<{
    localId?: number | null;
    saleItemLocalId?: number | null;
    productCodeSnapshot?: string | null;
    description: string;
    qty: number;
    price: number;
    total?: number;
  }>;
};

export async function createReturn(companyId: number, input: CreateReturnInput) {
  const originalSale = await prisma.sale.findFirst({
    where: {
      id: input.originalSaleId,
      companyId,
      kind: { in: ['invoice', 'sale'] },
    },
    select: {
      id: true,
      localCode: true,
      customerNameSnapshot: true,
      customerPhoneSnapshot: true,
      customerRncSnapshot: true,
      itbisEnabled: true,
      itbisRate: true,
      items: {
        select: { id: true, productId: true },
      },
    },
  });

  if (!originalSale) {
    throw { status: 404, message: 'Venta original no encontrada' };
  }

  const allowedSaleItemIds = new Set(originalSale.items.map((item) => item.id));
  for (const item of input.returnItems) {
    if (item.saleItemId != null && !allowedSaleItemIds.has(item.saleItemId)) {
      throw { status: 400, message: 'saleItemId no pertenece a la venta original' };
    }
  }

  const createdAt = new Date();
  const financials = calculateReturnAmounts({
    itbisEnabled: originalSale.itbisEnabled,
    itbisRate: originalSale.itbisRate,
    items: input.returnItems,
  });

  const result = await prisma.$transaction(async (tx) => {
    const returnSale = await tx.sale.create({
      data: {
        companyId,
        localCode: generateReturnLocalCode(),
        kind: 'return',
        status: 'completed',
        customerNameSnapshot: originalSale.customerNameSnapshot,
        customerPhoneSnapshot: originalSale.customerPhoneSnapshot,
        customerRncSnapshot: originalSale.customerRncSnapshot,
        itbisEnabled: originalSale.itbisEnabled,
        itbisRate: originalSale.itbisRate,
        discountTotal: 0,
        subtotal: -financials.subtotal,
        itbisAmount: -financials.itbisAmount,
        total: -financials.total,
        paymentMethod: 'return',
        paidAmount: 0,
        changeAmount: 0,
        fiscalEnabled: false,
        ncfFull: null,
        ncfType: null,
        sessionId: input.cashSessionId ?? null,
        createdAt,
        updatedAt: createdAt,
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

    const createdReturn = await tx.return.create({
      data: {
        companyId,
        originalSaleId: originalSale.id,
        returnSaleId: returnSale.id,
        note: input.note ?? null,
        createdAt,
      },
    });

    await tx.returnItem.createMany({
      data: input.returnItems.map((item) => ({
        returnId: createdReturn.id,
        saleItemId: item.saleItemId ?? null,
        productId: item.productId ?? null,
        description: item.description,
        qty: item.qty,
        price: item.price,
        total: item.total ?? item.qty * item.price,
      })),
    });

    await applyStockDelta(tx, [], input.returnItems.map((item) => ({
      productId: item.productId ?? null,
      qty: item.qty,
    })));

    await updateOriginalSaleStatus(tx, originalSale.id);

    return { createdReturn, returnSale };
  });

  await emitSaleEvent({
    companyId,
    type: 'sale.created',
    sale: toSaleRealtimePayload(result.returnSale),
  });

  return {
    ok: true,
    companyId,
    returnId: result.createdReturn.id,
    returnSaleId: result.returnSale.id,
    returnSaleLocalCode: result.returnSale.localCode,
  };
}

export async function listReturns(companyId: number, params: {
  from?: string;
  to?: string;
  originalSaleId?: number;
}) {
  const where: Prisma.ReturnWhereInput = { companyId };

  if (params.originalSaleId != null) {
    where.originalSaleId = params.originalSaleId;
  }

  if (params.from || params.to) {
    where.returnSale = {
      createdAt: {
        ...(params.from ? { gte: new Date(params.from) } : {}),
        ...(params.to ? { lte: new Date(params.to) } : {}),
      },
    };
  }

  const rows = await prisma.return.findMany({
    where,
    include: {
      originalSale: {
        select: { id: true, localCode: true, status: true },
      },
      returnSale: {
        select: {
          id: true,
          localCode: true,
          customerNameSnapshot: true,
          total: true,
          createdAt: true,
          sessionId: true,
        },
      },
      items: {
        select: {
          id: true,
          description: true,
          qty: true,
          price: true,
          total: true,
        },
      },
    },
    orderBy: { createdAt: 'desc' },
  });

  return rows.map((row) => ({
    id: row.id,
    originalSaleId: row.originalSaleId,
    originalSaleLocalCode: row.originalSale.localCode,
    originalSaleStatus: row.originalSale.status,
    returnSaleId: row.returnSaleId,
    localCode: row.returnSale.localCode,
    customerNameSnapshot: row.returnSale.customerNameSnapshot,
    total: toNumber(row.returnSale.total),
    createdAt: row.returnSale.createdAt,
    sessionId: row.returnSale.sessionId,
    note: row.note,
    items: row.items.map((item) => ({
      id: item.id,
      description: item.description,
      qty: toNumber(item.qty),
      price: toNumber(item.price),
      total: toNumber(item.total),
    })),
  }));
}

export async function syncReturnsByRnc(
  companyRnc: string | undefined,
  companyCloudId: string | undefined,
  returns: SyncReturnInput[],
) {
  const companyId = await resolveCompanyId(companyRnc, companyCloudId);
  if (!returns || returns.length === 0) {
    return { ok: true, upserted: 0, companyId };
  }

  const localSessionIds = Array.from(
    new Set(returns.map((entry) => entry.sessionLocalId).filter((value): value is number => !!value)),
  );
  const sessionMap = new Map<number, number>();
  if (localSessionIds.length > 0) {
    const sessions = await prisma.cashSession.findMany({
      where: { companyId, localId: { in: localSessionIds } },
      select: { id: true, localId: true },
    });
    for (const session of sessions) {
      if (session.localId != null) sessionMap.set(session.localId, session.id);
    }
  }

  const saleCodes = Array.from(
    new Set(
      returns.flatMap((entry) => [entry.originalSaleLocalCode, entry.returnSaleLocalCode]),
    ),
  );
  const existingSales = saleCodes.length === 0
    ? []
    : await prisma.sale.findMany({
        where: { companyId, localCode: { in: saleCodes } },
        select: {
          id: true,
          localCode: true,
          kind: true,
          status: true,
          customerNameSnapshot: true,
          customerPhoneSnapshot: true,
          customerRncSnapshot: true,
          itbisEnabled: true,
          itbisRate: true,
          total: true,
          paymentMethod: true,
          createdAt: true,
          updatedAt: true,
          deletedAt: true,
        },
      });
  const saleMap = new Map(existingSales.map((sale) => [sale.localCode, sale]));

  const localIds = returns.map((entry) => entry.localId);
  const existingReturns = await prisma.return.findMany({
    where: { companyId, localId: { in: localIds } },
    include: {
      items: true,
    },
  });
  const existingReturnMap = new Map(existingReturns.map((entry) => [entry.localId!, entry]));

  const realtimeEvents: Array<{
    type: 'sale.created' | 'sale.updated';
    sale: ReturnType<typeof toSaleRealtimePayload>;
  }> = [];

  await prisma.$transaction(async (tx) => {
    for (const entry of returns) {
      const originalSale = saleMap.get(entry.originalSaleLocalCode)
        ?? await tx.sale.findFirst({
          where: { companyId, localCode: entry.originalSaleLocalCode },
          select: {
            id: true,
            localCode: true,
            kind: true,
            status: true,
            customerNameSnapshot: true,
            customerPhoneSnapshot: true,
            customerRncSnapshot: true,
            itbisEnabled: true,
            itbisRate: true,
            total: true,
            paymentMethod: true,
            createdAt: true,
            updatedAt: true,
            deletedAt: true,
          },
        });

      if (!originalSale || (originalSale.kind !== 'invoice' && originalSale.kind !== 'sale')) {
        throw { status: 400, message: `Venta original no encontrada para ${entry.originalSaleLocalCode}` };
      }

      const createdAt = new Date(entry.createdAt);
      const sessionId = entry.sessionLocalId != null ? sessionMap.get(entry.sessionLocalId) ?? null : null;
      const financials = calculateReturnAmounts({
        itbisEnabled: originalSale.itbisEnabled,
        itbisRate: originalSale.itbisRate,
        items: entry.items,
      });
      const previousReturn = existingReturnMap.get(entry.localId) ?? null;
      const hadReturnSale = saleMap.has(entry.returnSaleLocalCode);

      const returnSale = await tx.sale.upsert({
        where: {
          companyId_localCode: {
            companyId,
            localCode: entry.returnSaleLocalCode,
          },
        },
        update: {
          kind: 'return',
          status: 'completed',
          customerNameSnapshot: originalSale.customerNameSnapshot,
          customerPhoneSnapshot: originalSale.customerPhoneSnapshot,
          customerRncSnapshot: originalSale.customerRncSnapshot,
          itbisEnabled: originalSale.itbisEnabled,
          itbisRate: originalSale.itbisRate,
          discountTotal: 0,
          subtotal: -financials.subtotal,
          itbisAmount: -financials.itbisAmount,
          total: -financials.total,
          paymentMethod: 'return',
          paidAmount: 0,
          changeAmount: 0,
          fiscalEnabled: false,
          ncfFull: null,
          ncfType: null,
          sessionId,
          updatedAt: createdAt,
          deletedAt: null,
        },
        create: {
          companyId,
          localCode: entry.returnSaleLocalCode,
          kind: 'return',
          status: 'completed',
          customerNameSnapshot: originalSale.customerNameSnapshot,
          customerPhoneSnapshot: originalSale.customerPhoneSnapshot,
          customerRncSnapshot: originalSale.customerRncSnapshot,
          itbisEnabled: originalSale.itbisEnabled,
          itbisRate: originalSale.itbisRate,
          discountTotal: 0,
          subtotal: -financials.subtotal,
          itbisAmount: -financials.itbisAmount,
          total: -financials.total,
          paymentMethod: 'return',
          paidAmount: 0,
          changeAmount: 0,
          fiscalEnabled: false,
          ncfFull: null,
          ncfType: null,
          sessionId,
          createdAt,
          updatedAt: createdAt,
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

      const originalSaleItems = await tx.saleItem.findMany({
        where: { saleId: originalSale.id },
        include: { product: { select: { code: true } } },
      });
      const originalSaleItemByLocalId = new Map(
        originalSaleItems
          .filter((item) => item.localId != null)
          .map((item) => [item.localId!, item]),
      );
      const productCodes = Array.from(
        new Set(entry.items.map((item) => item.productCodeSnapshot?.trim()).filter((value): value is string => !!value)),
      );
      const products = productCodes.length === 0
        ? []
        : await tx.product.findMany({
            where: { companyId, code: { in: productCodes } },
            select: { id: true, code: true },
          });
      const productMap = new Map(products.map((product) => [product.code, product]));

      const normalizedItems = entry.items.map((item) => {
        const resolvedSaleItem = item.saleItemLocalId != null
          ? originalSaleItemByLocalId.get(item.saleItemLocalId) ?? null
          : null;
        const fallbackCode = item.productCodeSnapshot?.trim()
          || resolvedSaleItem?.productCodeSnapshot
          || resolvedSaleItem?.product?.code
          || null;
        const resolvedProduct = fallbackCode ? productMap.get(fallbackCode) ?? null : null;
        return {
          localId: item.localId ?? null,
          saleItemId: resolvedSaleItem?.id ?? null,
          productId: resolvedSaleItem?.productId ?? resolvedProduct?.id ?? null,
          description: item.description,
          qty: item.qty,
          price: item.price,
          total: item.total ?? item.qty * item.price,
        };
      });

      const syncedReturn = previousReturn
        ? await tx.return.update({
            where: { companyId_localId: { companyId, localId: entry.localId } },
            data: {
              originalSaleId: originalSale.id,
              returnSaleId: returnSale.id,
              note: entry.note ?? null,
              createdAt,
            },
          })
        : await tx.return.create({
            data: {
              companyId,
              localId: entry.localId,
              originalSaleId: originalSale.id,
              returnSaleId: returnSale.id,
              note: entry.note ?? null,
              createdAt,
            },
          });

      if (previousReturn) {
        await tx.returnItem.deleteMany({ where: { returnId: previousReturn.id } });
      }

      if (normalizedItems.length > 0) {
        await tx.returnItem.createMany({
          data: normalizedItems.map((item) => ({
            returnId: syncedReturn.id,
            localId: item.localId,
            saleItemId: item.saleItemId,
            productId: item.productId,
            description: item.description,
            qty: item.qty,
            price: item.price,
            total: item.total,
          })),
        });
      }

      await applyStockDelta(
        tx,
        previousReturn?.items.map((item) => ({ productId: item.productId, qty: item.qty })) ?? [],
        normalizedItems.map((item) => ({ productId: item.productId, qty: item.qty })),
      );

      await updateOriginalSaleStatus(tx, originalSale.id);

      realtimeEvents.push({
        type: hadReturnSale ? 'sale.updated' : 'sale.created',
        sale: toSaleRealtimePayload(returnSale),
      });
    }
  });

  for (const event of realtimeEvents) {
    await emitSaleEvent({
      companyId,
      type: event.type,
      sale: event.sale,
    });
  }

  return { ok: true, upserted: returns.length, companyId };
}
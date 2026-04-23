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

function sameDate(a: Date | null | undefined, b: Date | null | undefined) {
  const left = a?.getTime() ?? null;
  const right = b?.getTime() ?? null;
  return left === right;
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

export type SyncSaleInput = {
  localCode: string;
  kind: string;
  status: string;
  customerNameSnapshot?: string | null;
  customerPhoneSnapshot?: string | null;
  customerRncSnapshot?: string | null;
  itbisEnabled: boolean;
  itbisRate: number;
  discountTotal: number;
  subtotal: number;
  itbisAmount: number;
  total: number;
  paymentMethod?: string | null;
  paidAmount: number;
  changeAmount: number;
  creditInterestRate?: number;
  creditTermDays?: number | null;
  creditDueDate?: string | null;
  creditInstallments?: number | null;
  creditNote?: string | null;
  fiscalEnabled: boolean;
  ncfFull?: string | null;
  ncfType?: string | null;
  sessionLocalId?: number | null;
  createdAt: string;
  updatedAt: string;
  deletedAt?: string | null;
  items: Array<{
    localId?: number | null;
    productCodeSnapshot?: string | null;
    productNameSnapshot: string;
    qty: number;
    unitPrice: number;
    purchasePriceSnapshot?: number;
    discountLine?: number;
    totalLine: number;
    createdAt?: string;
  }>;
};

export async function syncSalesByRnc(
  companyRnc: string | undefined,
  companyCloudId: string | undefined,
  sales: SyncSaleInput[],
) {
  const companyId = await resolveCompanyId(companyRnc, companyCloudId);
  if (!sales || sales.length === 0) {
    return { ok: true, upserted: 0, companyId };
  }

  const resultsByLocalCode = new Map<string, { localCode: string; id: number }>();

  const localCodes = Array.from(new Set(sales.map((sale) => sale.localCode).filter(Boolean)));
  const existingSales =
    localCodes.length === 0
      ? []
      : await prisma.sale.findMany({
          where: { companyId, localCode: { in: localCodes } },
          select: {
            id: true,
            localCode: true,
            kind: true,
            status: true,
            total: true,
            paymentMethod: true,
            customerNameSnapshot: true,
            updatedAt: true,
            deletedAt: true,
          },
        });
  const existingSaleMap = new Map(existingSales.map((sale) => [sale.localCode, sale]));

  const realtimeEvents: Array<{
    type: 'sale.created' | 'sale.updated' | 'sale.deleted';
    sale: ReturnType<typeof toSaleRealtimePayload>;
  }> = [];

  // Pre-cargar mapping de sesiones (localId -> id) para asociar ventas a cierres.
  const localSessionIds = Array.from(
    new Set(sales.map((s) => s.sessionLocalId).filter((v): v is number => !!v)),
  );

  const sessions =
    localSessionIds.length === 0
      ? []
      : await prisma.cashSession.findMany({
          where: { companyId, localId: { in: localSessionIds } },
          select: { id: true, localId: true },
        });
  const sessionMap = new Map<number, number>();
  for (const s of sessions) {
    if (s.localId != null) sessionMap.set(s.localId, s.id);
  }

  await prisma.$transaction(async (tx) => {
    for (const sale of sales) {
      const createdAt = new Date(sale.createdAt);
      const updatedAt = new Date(sale.updatedAt);
      const deletedAt = sale.deletedAt ? new Date(sale.deletedAt) : null;
      const previous = existingSaleMap.get(sale.localCode) ?? null;

      const sessionId =
        sale.sessionLocalId != null ? sessionMap.get(sale.sessionLocalId) ?? null : null;

      const upserted = await tx.sale.upsert({
        where: {
          companyId_localCode: {
            companyId,
            localCode: sale.localCode,
          },
        },
        update: {
          kind: sale.kind,
          status: sale.status,
          customerNameSnapshot: sale.customerNameSnapshot ?? null,
          customerPhoneSnapshot: sale.customerPhoneSnapshot ?? null,
          customerRncSnapshot: sale.customerRncSnapshot ?? null,
          itbisEnabled: sale.itbisEnabled,
          itbisRate: sale.itbisRate,
          discountTotal: sale.discountTotal,
          subtotal: sale.subtotal,
          itbisAmount: sale.itbisAmount,
          total: sale.total,
          paymentMethod: sale.paymentMethod ?? null,
          paidAmount: sale.paidAmount,
          changeAmount: sale.changeAmount,
          creditInterestRate: sale.creditInterestRate ?? 0,
          creditTermDays: sale.creditTermDays ?? null,
          creditDueDate: sale.creditDueDate ? new Date(sale.creditDueDate) : null,
          creditInstallments: sale.creditInstallments ?? null,
          creditNote: sale.creditNote ?? null,
          fiscalEnabled: sale.fiscalEnabled,
          ncfFull: sale.ncfFull ?? null,
          ncfType: sale.ncfType ?? null,
          sessionId,
          updatedAt,
          deletedAt,
        },
        create: {
          companyId,
          localCode: sale.localCode,
          kind: sale.kind,
          status: sale.status,
          customerNameSnapshot: sale.customerNameSnapshot ?? null,
          customerPhoneSnapshot: sale.customerPhoneSnapshot ?? null,
          customerRncSnapshot: sale.customerRncSnapshot ?? null,
          itbisEnabled: sale.itbisEnabled,
          itbisRate: sale.itbisRate,
          discountTotal: sale.discountTotal,
          subtotal: sale.subtotal,
          itbisAmount: sale.itbisAmount,
          total: sale.total,
          paymentMethod: sale.paymentMethod ?? null,
          paidAmount: sale.paidAmount,
          changeAmount: sale.changeAmount,
          creditInterestRate: sale.creditInterestRate ?? 0,
          creditTermDays: sale.creditTermDays ?? null,
          creditDueDate: sale.creditDueDate ? new Date(sale.creditDueDate) : null,
          creditInstallments: sale.creditInstallments ?? null,
          creditNote: sale.creditNote ?? null,
          fiscalEnabled: sale.fiscalEnabled,
          ncfFull: sale.ncfFull ?? null,
          ncfType: sale.ncfType ?? null,
          sessionId,
          createdAt,
          updatedAt,
          deletedAt,
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

      resultsByLocalCode.set(upserted.localCode, {
        localCode: upserted.localCode,
        id: upserted.id,
      });

      const changed =
        !previous ||
        previous.kind !== upserted.kind ||
        previous.status !== upserted.status ||
        toNumber(previous.total) !== toNumber(upserted.total) ||
        previous.paymentMethod !== upserted.paymentMethod ||
        previous.customerNameSnapshot !== upserted.customerNameSnapshot ||
        !sameDate(previous.updatedAt, upserted.updatedAt) ||
        !sameDate(previous.deletedAt, upserted.deletedAt);

      if (changed) {
        realtimeEvents.push({
          type: !previous ? 'sale.created' : upserted.deletedAt ? 'sale.deleted' : 'sale.updated',
          sale: toSaleRealtimePayload(upserted),
        });
      }

      await tx.saleItem.deleteMany({ where: { saleId: upserted.id } });
      if (sale.items && sale.items.length > 0) {
        const codes = Array.from(
          new Set(
            sale.items
              .map((i) => i.productCodeSnapshot?.trim())
              .filter((v): v is string => !!v),
          ),
        );

        const products =
          codes.length === 0
            ? []
            : await tx.product.findMany({
                where: { companyId, code: { in: codes } },
                select: { id: true, code: true, cost: true },
              });

        const productMap = new Map<string, { id: number; cost: number }>();
        for (const p of products) {
          productMap.set(p.code, { id: p.id, cost: toNumber(p.cost) });
        }

        await tx.saleItem.createMany({
          data: sale.items.map((i) => {
            const code = i.productCodeSnapshot?.trim() ?? null;
            const product = code ? productMap.get(code) : null;
            const providedCost = i.purchasePriceSnapshot ?? 0;
            const resolvedCost =
              providedCost > 0 ? providedCost : product?.cost ?? 0;

            return {
              localId: i.localId ?? null,
              productId: product?.id ?? null,
              saleId: upserted.id,
              productCodeSnapshot: code,
            productNameSnapshot: i.productNameSnapshot,
            qty: i.qty,
            unitPrice: i.unitPrice,
              purchasePriceSnapshot: resolvedCost,
            discountLine: i.discountLine ?? 0,
            totalLine: i.totalLine,
            createdAt: i.createdAt ? new Date(i.createdAt) : new Date(createdAt),
            };
          }),
        });
      }
    }
  });

  for (const event of realtimeEvents) {
    emitSaleEvent({
      companyId,
      type: event.type,
      sale: event.sale,
    });
  }

  return {
    ok: true,
    upserted: sales.length,
    companyId,
    results: Array.from(resultsByLocalCode.values()),
  };
}

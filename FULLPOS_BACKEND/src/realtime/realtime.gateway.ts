import crypto from 'crypto';
import http from 'http';
import jwt from 'jsonwebtoken';
import { Category, Product } from '@prisma/client';
import { Server } from 'socket.io';
import env, { corsOrigins } from '../config/env';
import { prisma } from '../config/prisma';
import { JwtUser } from '../modules/auth/auth.types';

type ProductEventType =
  | 'product.created'
  | 'product.updated'
  | 'product.deleted'
  | 'product.stock_updated';

type CategoryEventType =
  | 'category.created'
  | 'category.updated'
  | 'category.deleted';

type SaleEventType = 'sale.created' | 'sale.updated' | 'sale.deleted';

type QuoteEventType = 'quote.created' | 'quote.updated' | 'quote.deleted';

type CashEventType = 'cash.session.updated' | 'cash.movement.updated';

type CompanyDataEntity =
  | 'users'
  | 'company_config'
  | 'clients'
  | 'categories'
  | 'suppliers'
  | 'products'
  | 'sales'
  | 'cash'
  | 'quotes';

let ioInstance: Server | null = null;

function companyRoom(companyId: number) {
  return `company:${companyId}`;
}

function normalizeRnc(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

async function resolveCompanyIdForSocket(params: {
  companyRnc?: string;
  companyCloudId?: string;
}) {
  const cloudId = params.companyCloudId?.trim() ?? '';
  const rnc = params.companyRnc?.trim() ?? '';

  if (cloudId) {
    const company = await prisma.company.findFirst({
      where: { cloudCompanyId: cloudId },
      select: { id: true },
    });
    if (company) return company.id;
  }

  if (rnc) {
    const exact = await prisma.company.findFirst({
      where: { rnc },
      select: { id: true, rnc: true },
    });
    if (exact) return exact.id;

    const normalized = normalizeRnc(rnc);
    if (normalized) {
      const companies = await prisma.company.findMany({
        where: { rnc: { not: null } },
        select: { id: true, rnc: true },
      });
      const match = companies.find(
        (item) => item.rnc != null && normalizeRnc(item.rnc) === normalized,
      );
      if (match) return match.id;
    }
  }

  return null;
}

function serializeProduct(product: Product) {
  return {
    id: product.id,
    localId: product.localId,
    code: product.code,
    name: product.name,
    category: product.category,
    description: product.description,
    price: Number(product.price),
    cost: Number(product.cost),
    stock: Number(product.stock),
    imageUrl: product.imageUrl,
    isActive: product.isActive,
    version: product.version,
    lastModifiedBy: product.lastModifiedBy,
    updatedAt: product.updatedAt.toISOString(),
    createdAt: product.createdAt.toISOString(),
    deletedAt: product.deletedAt?.toISOString() ?? null,
  };
}

function serializeCategory(category: Category) {
  return {
    id: category.id,
    localId: category.localId,
    name: category.name,
    isActive: category.isActive,
    createdAt: category.createdAt.toISOString(),
    updatedAt: category.updatedAt.toISOString(),
    deletedAt: category.deletedAt?.toISOString() ?? null,
  };
}

export function attachRealtimeGateway(server: http.Server) {
  if (ioInstance) return ioInstance;

  ioInstance = new Server(server, {
    cors: {
      origin: corsOrigins.includes('*') ? true : corsOrigins,
      credentials: true,
    },
    transports: ['websocket', 'polling'],
  });

  ioInstance.use(async (socket, next) => {
    try {
      const authToken =
        (socket.handshake.auth?.token as string | undefined) ??
        (socket.handshake.headers.authorization as string | undefined)?.replace(
          /^Bearer\s+/i,
          '',
        );

      if (authToken) {
        const payload = jwt.verify(
          authToken,
          env.JWT_ACCESS_SECRET,
        ) as JwtUser & { exp: number };
        socket.data.companyId = payload.companyId;
        socket.data.clientType = 'owner';
        return next();
      }

      const cloudKey =
        (socket.handshake.auth?.cloudKey as string | undefined) ??
        (socket.handshake.headers['x-cloud-key'] as string | undefined);
      if (!env.ALLOW_PUBLIC_CLOUD && env.OVERRIDE_API_KEY?.trim()) {
        if (!cloudKey || cloudKey.trim() !== env.OVERRIDE_API_KEY.trim()) {
          return next(new Error('API key requerida'));
        }
      }

      const companyId = await resolveCompanyIdForSocket({
        companyCloudId:
          typeof socket.handshake.auth?.companyCloudId === 'string'
            ? socket.handshake.auth.companyCloudId
            : undefined,
        companyRnc:
          typeof socket.handshake.auth?.companyRnc === 'string'
            ? socket.handshake.auth.companyRnc
            : undefined,
      });
      if (!companyId) {
        return next(new Error('Empresa no encontrada'));
      }

      socket.data.companyId = companyId;
      socket.data.clientType = 'pos';
      return next();
    } catch (error) {
      return next(new Error('No autorizado'));
    }
  });

  ioInstance.on('connection', (socket) => {
    const companyId = socket.data.companyId as number | undefined;
    if (companyId != null) {
      socket.join(companyRoom(companyId));
    }
  });

  return ioInstance;
}

export async function emitProductEvent(params: {
  companyId: number;
  type: ProductEventType;
  product: Product;
}) {
  if (!ioInstance) return;

  ioInstance.to(companyRoom(params.companyId)).emit('product.event', {
    eventId: crypto.randomUUID(),
    type: params.type,
    product: serializeProduct(params.product),
  });

  await emitCompanyDataChangeEvent({
    companyId: params.companyId,
    entity: 'products',
    action: params.type,
  });
}

export async function emitCategoryEvent(params: {
  companyId: number;
  type: CategoryEventType;
  category: Category;
}) {
  if (!ioInstance) return;

  ioInstance.to(companyRoom(params.companyId)).emit('category.event', {
    eventId: crypto.randomUUID(),
    type: params.type,
    category: serializeCategory(params.category),
  });

  await emitCompanyDataChangeEvent({
    companyId: params.companyId,
    entity: 'categories',
    action: params.type,
  });
}

export async function emitSaleEvent(params: {
  companyId: number;
  type: SaleEventType;
  sale: Record<string, unknown>;
}) {
  if (!ioInstance) return;

  ioInstance.to(companyRoom(params.companyId)).emit('sale.event', {
    eventId: crypto.randomUUID(),
    type: params.type,
    sale: params.sale,
  });

  await emitCompanyDataChangeEvent({
    companyId: params.companyId,
    entity: 'sales',
    action: params.type,
  });
}

export async function emitQuoteEvent(params: {
  companyId: number;
  type: QuoteEventType;
  quote: Record<string, unknown>;
}) {
  if (!ioInstance) return;

  ioInstance.to(companyRoom(params.companyId)).emit('quote.event', {
    eventId: crypto.randomUUID(),
    type: params.type,
    quote: params.quote,
  });

  await emitCompanyDataChangeEvent({
    companyId: params.companyId,
    entity: 'quotes',
    action: params.type,
  });
}

export async function emitCashEvent(params: {
  companyId: number;
  type: CashEventType;
  cash: Record<string, unknown>;
}) {
  if (!ioInstance) return;

  ioInstance.to(companyRoom(params.companyId)).emit('cash.event', {
    eventId: crypto.randomUUID(),
    type: params.type,
    cash: params.cash,
  });

  await emitCompanyDataChangeEvent({
    companyId: params.companyId,
    entity: 'cash',
    action: params.type,
  });
}

export async function emitCompanyDataChangeEvent(params: {
  companyId: number;
  entity: CompanyDataEntity;
  action: string;
}) {
  if (!ioInstance) return;

  ioInstance.to(companyRoom(params.companyId)).emit('company.data_changed', {
    eventId: crypto.randomUUID(),
    entity: params.entity,
    action: params.action,
    occurredAt: new Date().toISOString(),
  });
}
import { Prisma, Product } from '@prisma/client';
import { prisma } from '../../config/prisma';
import { buildPagination } from '../../utils/pagination';
import {
  createProductSchema,
  syncProductOperationsSchema,
  updateProductSchema,
} from './products.validation';
import { emitProductEvent } from '../../realtime/realtime.gateway';

function toNumber(value: Prisma.Decimal | number | null) {
  if (value === null || value === undefined) return 0;
  if (typeof value === 'number') return value;
  return value.toNumber();
}

function normalizeRnc(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function parseIsoDate(value?: string | null) {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function productEventTypeFromOperation(operationType: string, created: boolean) {
  if (operationType === 'delete') return 'product.deleted' as const;
  if (operationType === 'stock') return 'product.stock_updated' as const;
  if (created) return 'product.created' as const;
  return 'product.updated' as const;
}

function serializeProduct(product: Product) {
  return {
    id: product.id,
    localId: product.localId,
    code: product.code,
    name: product.name,
    description: product.description,
    price: toNumber(product.price),
    cost: toNumber(product.cost),
    stock: toNumber(product.stock),
    imageUrl: product.imageUrl,
    isDemo: product.isDemo,
    isActive: product.isActive,
    version: product.version,
    lastModifiedBy: product.lastModifiedBy,
    createdAt: product.createdAt,
    updatedAt: product.updatedAt,
    deletedAt: product.deletedAt,
  };
}

async function resolveCompany(params: {
  companyId?: number;
  companyRnc?: string;
  companyCloudId?: string;
}) {
  if (params.companyId != null) {
    const company = await prisma.company.findUnique({
      where: { id: params.companyId },
      select: { id: true, rnc: true, cloudCompanyId: true },
    });
    if (!company) throw { status: 404, message: 'Empresa no encontrada' };
    return company;
  }

  const cloudId = params.companyCloudId?.trim() ?? '';
  if (cloudId) {
    const company = await prisma.company.findFirst({
      where: { cloudCompanyId: cloudId },
      select: { id: true, rnc: true, cloudCompanyId: true },
    });
    if (company) return company;
  }

  const rnc = params.companyRnc?.trim() ?? '';
  if (!rnc) {
    throw { status: 400, message: 'RNC o ID interno requerido' };
  }

  const exact = await prisma.company.findFirst({
    where: { rnc },
    select: { id: true, rnc: true, cloudCompanyId: true },
  });
  if (exact) return exact;

  const normalized = normalizeRnc(rnc);
  const companies = await prisma.company.findMany({
    where: { rnc: { not: null } },
    select: { id: true, rnc: true, cloudCompanyId: true },
  });
  const matched = companies.find(
    (item) => item.rnc != null && normalizeRnc(item.rnc) === normalized,
  );
  if (!matched) {
    throw { status: 404, message: 'Empresa no encontrada' };
  }
  return matched;
}

export type CreateProductInput = Omit<
  ReturnType<typeof createProductSchema.parse>,
  'isDemo'
> & { isDemo?: boolean };

export type UpdateProductInput = ReturnType<typeof updateProductSchema.parse>;

export type SyncProductInput = {
  code: string;
  name: string;
  description?: string;
  price: number;
  cost?: number;
  stock?: number;
  imageUrl?: string | null;
};

export type ProductSyncOperation = ReturnType<
  typeof syncProductOperationsSchema.parse
>['operations'][number];

async function findExistingProduct(params: {
  companyId: number;
  localProductId?: number;
  serverProductId?: number;
  code?: string;
}) {
  const clauses: Prisma.ProductWhereInput[] = [];
  if (params.serverProductId != null) {
    clauses.push({ id: params.serverProductId, companyId: params.companyId });
  }
  if (params.localProductId != null) {
    clauses.push({ localId: params.localProductId, companyId: params.companyId });
  }
  if (params.code && params.code.trim().length > 0) {
    clauses.push({ code: params.code.trim(), companyId: params.companyId });
  }

  if (clauses.length === 0) return null;
  return prisma.product.findFirst({ where: { OR: clauses } });
}

async function persistSyncOperation(companyId: number, operation: ProductSyncOperation) {
  const code = operation.product.code.trim();
  const name = operation.product.name.trim();
  const now = new Date();
  const deletedAt =
    operation.operationType === 'delete'
      ? parseIsoDate(operation.product.deletedAt) ?? now
      : parseIsoDate(operation.product.deletedAt);

  const existing = await findExistingProduct({
    companyId,
    localProductId: operation.localProductId,
    serverProductId: operation.serverProductId,
    code,
  });

  if (
    existing &&
    operation.clientMutationId &&
    existing.lastClientMutationId === operation.clientMutationId
  ) {
    return {
      created: false,
      eventType: productEventTypeFromOperation(operation.operationType, false),
      product: existing,
      emitted: false,
    };
  }

  if (
    existing &&
    operation.baseVersion != null &&
    operation.baseVersion !== existing.version
  ) {
    throw {
      status: 409,
      message: 'server_version_conflict',
      serverProduct: serializeProduct(existing),
    };
  }

  if (operation.operationType === 'delete' && !existing) {
    return {
      created: false,
      eventType: 'product.deleted' as const,
      product: null,
      emitted: false,
    };
  }

  const product = await prisma.$transaction(async (tx) => {
    const txExisting = await tx.product.findFirst({
      where: {
        companyId,
        OR: [
          ...(operation.serverProductId != null
              ? [{ id: operation.serverProductId }]
              : []),
          ...(operation.localProductId != null
              ? [{ localId: operation.localProductId }]
              : []),
          { code },
        ],
      },
    });

    if (
      txExisting &&
      operation.clientMutationId &&
      txExisting.lastClientMutationId === operation.clientMutationId
    ) {
      return { created: false, product: txExisting };
    }

    if (
      txExisting &&
      operation.baseVersion != null &&
      operation.baseVersion !== txExisting.version
    ) {
      throw {
        status: 409,
        message: 'server_version_conflict',
        serverProduct: serializeProduct(txExisting),
      };
    }

    if (operation.operationType === 'delete' && !txExisting) {
      return { created: false, product: null };
    }

    const baseData = {
      code,
      name,
      description: null,
      price: operation.product.price,
      cost: operation.product.cost ?? 0,
      stock: operation.product.stock ?? 0,
      imageUrl: operation.product.imageUrl?.trim() || null,
      isDemo: false,
      isActive:
        operation.operationType === 'delete'
          ? false
          : operation.product.isActive ?? true,
      lastModifiedBy: operation.lastModifiedBy?.trim() || 'fullpos_sync',
      lastClientMutationId: operation.clientMutationId?.trim() || null,
      deletedAt: operation.operationType === 'delete' ? deletedAt : deletedAt,
    };

    if (!txExisting) {
      const created = await tx.product.create({
        data: {
          companyId,
          localId: operation.localProductId,
          ...baseData,
          version: 1,
          deletedAt: operation.operationType === 'delete' ? deletedAt ?? now : null,
        },
      });
      return { created: true, product: created };
    }

    const updated = await tx.product.update({
      where: { id: txExisting.id },
      data: {
        localId: txExisting.localId ?? operation.localProductId,
        ...baseData,
        deletedAt:
          operation.operationType === 'delete'
            ? deletedAt ?? now
            : deletedAt,
        version: { increment: 1 },
      },
    });
    return { created: false, product: updated };
  });

  return {
    created: product.created,
    eventType: productEventTypeFromOperation(operation.operationType, product.created),
    product: product.product,
    emitted: true,
  };
}

async function emitIfNeeded(companyId: number, product: Product | null, eventType: ReturnType<typeof productEventTypeFromOperation>, emitted: boolean) {
  if (!product || !emitted) return;
  await emitProductEvent({ companyId, type: eventType, product });
}

export async function listProducts(
  companyId: number,
  page = 1,
  pageSize = 20,
  search?: string,
) {
  const { skip, take, page: safePage } = buildPagination(page, pageSize);

  await prisma.product.deleteMany({ where: { companyId, isDemo: true } });

  const where: Prisma.ProductWhereInput = {
    companyId,
    isDemo: false,
    deletedAt: null,
    ...(search
      ? {
          OR: [
            { name: { contains: search, mode: 'insensitive' } },
            { code: { contains: search, mode: 'insensitive' } },
          ],
        }
      : {}),
  };

  const [total, items] = await Promise.all([
    prisma.product.count({ where }),
    prisma.product.findMany({
      where,
      orderBy: [{ updatedAt: 'desc' }, { id: 'desc' }],
      skip,
      take,
    }),
  ]);

  return {
    data: items.map(serializeProduct),
    total,
    page: safePage,
    pageSize: take,
  };
}

export async function getProductById(companyId: number, productId: number) {
  const product = await prisma.product.findFirst({
    where: { id: productId, companyId, isDemo: false },
  });
  if (!product) {
    throw { status: 404, message: 'Producto no encontrado' };
  }
  return serializeProduct(product);
}

export async function createProduct(companyId: number, input: CreateProductInput) {
  try {
    const created = await prisma.product.create({
      data: {
        companyId,
        code: input.code.trim(),
        name: input.name.trim(),
        description: input.description?.trim() || null,
        price: input.price,
        cost: input.cost ?? 0,
        stock: input.stock ?? 0,
        imageUrl: input.imageUrl?.trim() || null,
        isDemo: input.isDemo ?? false,
        isActive: true,
        version: 1,
        lastModifiedBy: 'owner_api',
      },
    });

    await emitProductEvent({
      companyId,
      type: 'product.created',
      product: created,
    });
    return serializeProduct(created);
  } catch (err: any) {
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
      throw { status: 409, message: 'Ya existe un producto con ese codigo' };
    }
    throw err;
  }
}

export async function updateProduct(
  companyId: number,
  productId: number,
  input: UpdateProductInput,
) {
  const existing = await prisma.product.findFirst({
    where: { id: productId, companyId, isDemo: false },
  });
  if (!existing) {
    throw { status: 404, message: 'Producto no encontrado' };
  }

  try {
    const updated = await prisma.product.update({
      where: { id: productId },
      data: {
        code: input.code?.trim() ?? existing.code,
        name: input.name?.trim() ?? existing.name,
        description:
          input.description === undefined
            ? existing.description
            : input.description.trim() || null,
        price: input.price ?? existing.price,
        cost: input.cost ?? existing.cost,
        stock: input.stock ?? existing.stock,
        imageUrl:
          input.imageUrl === undefined
            ? existing.imageUrl
            : input.imageUrl?.trim() || null,
        isActive: input.isActive ?? existing.isActive,
        version: { increment: 1 },
        lastModifiedBy: 'owner_api',
        deletedAt: input.isActive == false ? existing.deletedAt : null,
        lastClientMutationId: null,
      },
    });

    await emitProductEvent({
      companyId,
      type: 'product.updated',
      product: updated,
    });
    return serializeProduct(updated);
  } catch (err: any) {
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
      throw { status: 409, message: 'Ya existe un producto con ese codigo' };
    }
    throw err;
  }
}

export async function softDeleteProduct(companyId: number, productId: number) {
  const existing = await prisma.product.findFirst({
    where: { id: productId, companyId, isDemo: false },
  });
  if (!existing) {
    throw { status: 404, message: 'Producto no encontrado' };
  }

  const deleted = await prisma.product.update({
    where: { id: productId },
    data: {
      isActive: false,
      deletedAt: new Date(),
      version: { increment: 1 },
      lastModifiedBy: 'owner_api',
      lastClientMutationId: null,
    },
  });
  await emitProductEvent({
    companyId,
    type: 'product.deleted',
    product: deleted,
  });
  return serializeProduct(deleted);
}

export async function updateProductStock(
  companyId: number,
  productId: number,
  stock: number,
) {
  const existing = await prisma.product.findFirst({
    where: { id: productId, companyId, isDemo: false },
  });
  if (!existing) {
    throw { status: 404, message: 'Producto no encontrado' };
  }

  const updated = await prisma.product.update({
    where: { id: productId },
    data: {
      stock,
      version: { increment: 1 },
      lastModifiedBy: 'owner_api',
      lastClientMutationId: null,
    },
  });
  await emitProductEvent({
    companyId,
    type: 'product.stock_updated',
    product: updated,
  });
  return serializeProduct(updated);
}

export async function syncProductOperations(params: {
  companyRnc?: string;
  companyCloudId?: string;
  operations: ProductSyncOperation[];
}) {
  const company = await resolveCompany({
    companyRnc: params.companyRnc,
    companyCloudId: params.companyCloudId,
  });

  const results: Array<{
    created: boolean;
    product: Product | null;
    eventType: ReturnType<typeof productEventTypeFromOperation>;
    emitted: boolean;
  }> = [];

  for (const operation of params.operations) {
    const result = await persistSyncOperation(company.id, operation);
    results.push(result);
  }

  for (const result of results) {
    await emitIfNeeded(company.id, result.product, result.eventType, result.emitted);
  }

  const last = results[results.length - 1];
  return {
    ok: true,
    companyId: company.id,
    product: last.product ? serializeProduct(last.product) : null,
    eventType: last.eventType,
    applied: results.filter((item) => item.product != null).length,
  };
}

export async function syncProductsByRnc(
  companyRnc: string | undefined,
  products: SyncProductInput[],
  companyCloudId?: string,
  deletedProducts?: string[],
) {
  const company = await resolveCompany({ companyRnc, companyCloudId });
  const events: Array<{ type: ReturnType<typeof productEventTypeFromOperation>; product: Product }> = [];

  for (const item of products) {
    const result = await persistSyncOperation(company.id, {
      operationType: 'upsert',
      product: {
        businessId: company.cloudCompanyId ?? company.rnc,
        code: item.code,
        name: item.name,
        price: item.price,
        cost: item.cost ?? 0,
        stock: item.stock ?? 0,
        imageUrl: item.imageUrl ?? null,
        isActive: true,
        deletedAt: null,
      },
      localProductId: undefined,
      serverProductId: undefined,
      baseVersion: undefined,
      occurredAt: undefined,
      clientMutationId: undefined,
      lastModifiedBy: 'legacy_full_sync',
    });
    if (result.product) {
      events.push({ type: result.eventType, product: result.product });
    }
  }

  const cleanedDeleted = (deletedProducts ?? [])
    .map((code) => code.trim())
    .filter((code) => code.length > 0);
  const uniqueDeletedCodes = Array.from(new Set(cleanedDeleted));

  if (uniqueDeletedCodes.length > 0) {
    const candidates = await prisma.product.findMany({
      where: { companyId: company.id, code: { in: uniqueDeletedCodes } },
    });
    for (const candidate of candidates) {
      const deleted = await prisma.product.update({
        where: { id: candidate.id },
        data: {
          deletedAt: new Date(),
          isActive: false,
          version: { increment: 1 },
          lastModifiedBy: 'legacy_full_sync',
          lastClientMutationId: null,
        },
      });
      events.push({ type: 'product.deleted', product: deleted });
    }
  }

  for (const event of events) {
    await emitProductEvent({ companyId: company.id, type: event.type, product: event.product });
  }

  return {
    ok: true,
    upserted: products.length,
    deleted: uniqueDeletedCodes.length,
    companyId: company.id,
  };
}
import { z } from 'zod';

function trimToUndefined(value: unknown) {
  if (typeof value !== 'string') return value;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function trimToNullOrUndefined(value: unknown) {
  if (value === null) return null;
  if (typeof value !== 'string') return value;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function looksLikeLocalOnlyImagePath(value: string) {
  const normalized = value.trim().toLowerCase();
  if (!normalized) return false;

  return (
    normalized.startsWith('file://') ||
    normalized.startsWith('content://') ||
    normalized.startsWith('blob:') ||
    normalized.startsWith('data:') ||
    normalized.startsWith('assets/') ||
    normalized.startsWith('asset:/') ||
    normalized.startsWith('/data/') ||
    normalized.startsWith('/storage/') ||
    normalized.startsWith('/var/mobile/') ||
    normalized.startsWith('/private/var/') ||
    /^[a-z]:\\/i.test(normalized)
  );
}

function isAcceptedImageUrl(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return false;
  if (trimmed.startsWith('/uploads/')) return true;
  if (trimmed.startsWith('uploads/')) return true;
  return z.string().url().safeParse(trimmed).success;
}

function normalizeSyncImageUrl(value: unknown) {
  if (value == null) return value;
  if (typeof value !== 'string') return value;

  const trimmed = value.trim();
  if (!trimmed) return undefined;
  if (trimmed.startsWith('uploads/')) return `/${trimmed}`;
  if (looksLikeLocalOnlyImagePath(trimmed)) return undefined;
  return trimmed;
}

function normalizeOptionalPositiveInt(value: unknown) {
  if (value == null) return undefined;
  if (typeof value === 'string' && value.trim().length === 0) return undefined;

  const coerced = Number(value);
  if (!Number.isFinite(coerced) || !Number.isInteger(coerced)) {
    return value;
  }

  return coerced > 0 ? coerced : undefined;
}

export function normalizeSyncProductOperationsInput(value: unknown) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return value;
  }

  const body = value as Record<string, unknown>;
  const normalized: Record<string, unknown> = {
    ...body,
    companyRnc: trimToUndefined(body.companyRnc),
    companyCloudId: trimToUndefined(body.companyCloudId),
  };

  if (Array.isArray(body.operations)) {
    normalized.operations = body.operations.map((entry) => {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
        return entry;
      }

      const operation = entry as Record<string, unknown>;
      const productInput =
        operation.product && typeof operation.product === 'object' && !Array.isArray(operation.product)
          ? (operation.product as Record<string, unknown>)
          : {};

      const product: Record<string, unknown> = {
        ...productInput,
        businessId: trimToUndefined(productInput.businessId),
        code: trimToUndefined(productInput.code),
        name: trimToUndefined(productInput.name),
        category: trimToNullOrUndefined(productInput.category),
        imageUrl: normalizeSyncImageUrl(productInput.imageUrl),
        deletedAt: trimToNullOrUndefined(productInput.deletedAt),
      };

      if (product.imageUrl === undefined) {
        delete product.imageUrl;
      }

      return {
        ...operation,
        clientMutationId: trimToUndefined(operation.clientMutationId),
        localProductId: normalizeOptionalPositiveInt(operation.localProductId),
        serverProductId: normalizeOptionalPositiveInt(operation.serverProductId),
        lastModifiedBy: trimToUndefined(operation.lastModifiedBy),
        occurredAt: trimToUndefined(operation.occurredAt),
        product,
      };
    });
  }

  return normalized;
}

export function getNestedValue(payload: unknown, path: Array<string | number>) {
  let current = payload;
  for (const segment of path) {
    if (current == null) return undefined;
    if (typeof segment === 'number') {
      if (!Array.isArray(current)) return undefined;
      current = current[segment];
      continue;
    }
    if (typeof current !== 'object' || Array.isArray(current)) return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

const imageUrlSchema = z.preprocess(
  normalizeSyncImageUrl,
  z
    .string()
    .trim()
    .refine(isAcceptedImageUrl, 'La imagen debe ser una URL valida o una ruta /uploads/...')
    .optional(),
);

export const listProductsSchema = z.object({
  page: z.coerce.number().int().positive().optional(),
  pageSize: z.coerce.number().int().positive().max(100).optional(),
  search: z.string().trim().max(100).optional(),
});

export const createProductSchema = z.object({
  code: z.string().trim().min(1, 'El codigo es requerido'),
  name: z.string().trim().min(1, 'El nombre es requerido'),
  category: z.string().trim().max(120).optional(),
  description: z.string().trim().max(500).optional(),
  price: z.coerce.number().nonnegative(),
  cost: z.coerce.number().nonnegative().optional().default(0),
  stock: z.coerce.number().nonnegative().default(0),
  imageUrl: imageUrlSchema.optional(),
  isDemo: z.boolean().optional(),
});

export const updateProductSchema = createProductSchema.partial().extend({
  code: z.string().trim().min(1, 'El codigo es requerido').optional(),
  name: z.string().trim().min(1, 'El nombre es requerido').optional(),
  isActive: z.boolean().optional(),
});

export const productIdParamsSchema = z.object({
  id: z.coerce.number().int().positive(),
});

export const updateProductStockSchema = z.object({
  stock: z.coerce.number().nonnegative(),
});

const syncOperationProductSchema = z.object({
  businessId: z.string().trim().min(1).optional(),
  code: z.string().trim().min(1, 'El codigo es requerido').optional(),
  name: z.string().trim().min(1, 'El nombre es requerido').optional(),
  category: z.string().trim().max(120).optional().nullable(),
  price: z.coerce.number().nonnegative().optional(),
  cost: z.coerce.number().nonnegative().optional().default(0),
  stock: z.coerce.number().nonnegative().optional(),
  imageUrl: imageUrlSchema.nullish(),
  isActive: z.boolean().optional(),
  deletedAt: z.string().datetime().optional().nullable(),
});

const syncOperationSchema = z
  .object({
    clientMutationId: z.string().trim().min(1).optional(),
    localProductId: z.coerce.number().int().positive().optional(),
    serverProductId: z.coerce.number().int().positive().optional(),
    operationType: z.enum(['upsert', 'delete', 'stock', 'status']),
    baseVersion: z.coerce.number().int().nonnegative().optional(),
    occurredAt: z.string().datetime().optional(),
    lastModifiedBy: z.string().trim().min(1).optional(),
    product: syncOperationProductSchema,
  })
  .superRefine((data, ctx) => {
    const hasIdentifier =
      data.localProductId != null ||
      data.serverProductId != null ||
      !!data.product.code?.trim();

    if (!hasIdentifier) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['localProductId'],
        message: 'localProductId, serverProductId o product.code requerido',
      });
    }

    if (data.operationType === 'upsert') {
      if (!data.product.code?.trim()) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['product', 'code'],
          message: 'El codigo es requerido para upsert',
        });
      }
      if (!data.product.name?.trim()) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['product', 'name'],
          message: 'El nombre es requerido para upsert',
        });
      }
      if (data.product.price == null) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['product', 'price'],
          message: 'El precio es requerido para upsert',
        });
      }
    }

    if (data.operationType === 'stock' && data.product.stock == null) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['product', 'stock'],
        message: 'El stock es requerido para operationType=stock',
      });
    }

    if (
      data.operationType === 'status' &&
      data.product.isActive == null &&
      data.product.deletedAt == null
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['product', 'isActive'],
        message: 'isActive o deletedAt requerido para operationType=status',
      });
    }
  });

export const syncProductOperationsSchema = z
  .object({
    companyId: z.coerce.number().int().positive().optional(),
    companyRnc: z.string().trim().min(3).optional(),
    companyCloudId: z.string().trim().min(6).optional(),
    operations: z.array(syncOperationSchema).min(1).max(100),
  })
  .refine((data) => data.companyId != null || !!data.companyRnc || !!data.companyCloudId, {
    message: 'companyId, RNC o companyCloudId requerido',
    path: ['companyId'],
  });

export const syncProductsByRncSchema = z
  .object({
    companyId: z.coerce.number().int().positive().optional(),
    companyRnc: z.string().trim().min(3).optional(),
    companyCloudId: z.string().trim().min(6).optional(),
    products: z
      .array(
        z.object({
          code: z.string().trim().min(1, 'El codigo es requerido'),
          name: z.string().trim().min(1, 'El nombre es requerido'),
          category: z.string().trim().max(120).optional(),
          description: z.string().trim().max(500).optional(),
          price: z.coerce.number().nonnegative(),
          cost: z.coerce.number().nonnegative().optional(),
          stock: z.coerce.number().nonnegative().optional(),
          imageUrl: imageUrlSchema.optional().nullable(),
        }),
      )
      .max(2000)
      .default([]),
    deletedProducts: z.array(z.string().trim().min(1)).max(2000).default([]),
  })
  .refine((data) => data.companyId != null || !!data.companyRnc || !!data.companyCloudId, {
    message: 'companyId, RNC o companyCloudId requerido',
    path: ['companyId'],
  });

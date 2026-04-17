import { Router } from 'express';
import { authGuard } from '../../middlewares/authGuard';
import { overrideKeyGuard } from '../../middlewares/overrideKeyGuard';
import { validate } from '../../middlewares/validate';
import {
  getNestedValue,
  normalizeSyncProductOperationsInput,
  createProductSchema,
  listProductsSchema,
  productIdParamsSchema,
  syncProductOperationsSchema,
  syncProductsByRncSchema,
  updateProductSchema,
  updateProductStockSchema,
} from './products.validation';
import {
  createProduct,
  getProductById,
  listProducts,
  softDeleteProduct,
  syncProductOperations,
  syncProductsByRnc,
  updateProduct,
  updateProductStock,
} from './products.service';

function summarizeProductSyncOperation(operation: Record<string, any>) {
  const product =
    operation.product && typeof operation.product === 'object'
      ? operation.product
      : {};

  return {
    operationType: operation.operationType ?? null,
    localProductId: operation.localProductId ?? null,
    serverProductId: operation.serverProductId ?? null,
    clientMutationId: operation.clientMutationId ?? null,
    code: product.code ?? null,
    name: product.name ?? null,
    price: product.price ?? null,
    stock: product.stock ?? null,
    isActive: product.isActive ?? null,
    imageUrl: product.imageUrl ?? null,
  };
}

function validateSyncProductOperationsRequest(req: any, res: any, next: any) {
  const rawBody = req.body;
  const normalizedBody = normalizeSyncProductOperationsInput(rawBody);

  console.info('[products.sync.operations] request_received', {
    companyId: rawBody?.companyId ?? null,
    companyRnc: rawBody?.companyRnc ?? null,
    companyCloudId: rawBody?.companyCloudId ?? null,
    operations: Array.isArray(rawBody?.operations)
      ? rawBody.operations.map((operation: Record<string, any>) =>
          summarizeProductSyncOperation(operation),
        )
      : null,
  });

  const parsed = syncProductOperationsSchema.safeParse(normalizedBody);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((issue) => ({
      path: issue.path,
      reason: issue.code,
      message: issue.message,
      value: getNestedValue(rawBody, issue.path as Array<string | number>) ?? null,
    }));

    console.warn('[products.sync.operations] validation_failed', { issues });
    return res.status(400).json({
      message: 'Validation error',
      errorCode: 'VALIDATION_ERROR',
      issues: issues.map((issue) => ({
        path: issue.path,
        reason: issue.reason,
        message: issue.message,
      })),
    });
  }

  req.body = parsed.data;
  console.info('[products.sync.operations] validation_passed', {
    companyId: parsed.data.companyId ?? null,
    companyRnc: parsed.data.companyRnc ?? null,
    companyCloudId: parsed.data.companyCloudId ?? null,
    operations: parsed.data.operations.map((operation) =>
      summarizeProductSyncOperation(operation as unknown as Record<string, any>),
    ),
  });
  next();
}

const router = Router();

// Sync de productos desde FULLPOS (por RNC o ID interno).
// No requiere JWT (POS no tiene login), solo overrideKeyGuard.
router.post(
  '/sync/by-rnc',
  overrideKeyGuard,
  validate(syncProductsByRncSchema),
  async (req, res, next) => {
    try {
      const { companyId, companyRnc, companyCloudId, products, deletedProducts } = req.body;
      console.info('[cloud_sync] products.sync.by-rnc', {
        companyId: companyId ?? null,
        companyRnc: companyRnc ?? null,
        companyCloudId: companyCloudId ?? null,
        count: Array.isArray(products) ? products.length : 0,
      });
      const result = await syncProductsByRnc(
        companyId,
        companyRnc,
        products ?? [],
        companyCloudId,
        deletedProducts ?? [],
      );
      res.json(result);
    } catch (err) {
      next(err);
    }
  },
);

router.post(
  '/sync/operations',
  overrideKeyGuard,
  validateSyncProductOperationsRequest,
  async (req, res, next) => {
    try {
      const result = await syncProductOperations({
        companyId: req.body.companyId,
        companyRnc: req.body.companyRnc,
        companyCloudId: req.body.companyCloudId,
        operations: req.body.operations,
      });
      res.json(result);
    } catch (err) {
      console.warn('[products.sync.operations] service_failed', {
        message: (err as any)?.message ?? 'Unknown error',
        errorCode: (err as any)?.errorCode ?? null,
        status: (err as any)?.status ?? null,
      });
      next(err);
    }
  },
);

// Endpoints de administración (Owner) sí requieren JWT.
router.use(authGuard);

router.get('/', validate(listProductsSchema, 'query'), async (req, res, next) => {
  try {
    const { page, pageSize, search } = req.query as any;
    const result = await listProducts(req.user!.companyId, page, pageSize, search);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

router.post('/', validate(createProductSchema), async (req, res, next) => {
  try {
    const product = await createProduct(req.user!.companyId, req.body);
    res.status(201).json(product);
  } catch (err) {
    next(err);
  }
});

router.get('/:id', validate(productIdParamsSchema, 'params'), async (req, res, next) => {
  try {
    const { id } = req.params as any;
    const product = await getProductById(req.user!.companyId, Number(id));
    res.json(product);
  } catch (err) {
    next(err);
  }
});

router.put(
  '/:id',
  validate(productIdParamsSchema, 'params'),
  validate(updateProductSchema),
  async (req, res, next) => {
    try {
      const { id } = req.params as any;
      const product = await updateProduct(req.user!.companyId, Number(id), req.body);
      res.json(product);
    } catch (err) {
      next(err);
    }
  },
);

router.delete('/:id', validate(productIdParamsSchema, 'params'), async (req, res, next) => {
  try {
    const { id } = req.params as any;
    const product = await softDeleteProduct(req.user!.companyId, Number(id));
    res.json(product);
  } catch (err) {
    next(err);
  }
});

router.patch(
  '/:id/stock',
  validate(productIdParamsSchema, 'params'),
  validate(updateProductStockSchema),
  async (req, res, next) => {
    try {
      const { id } = req.params as any;
      const product = await updateProductStock(
        req.user!.companyId,
        Number(id),
        req.body.stock,
      );
      res.json(product);
    } catch (err) {
      next(err);
    }
  },
);

export default router;

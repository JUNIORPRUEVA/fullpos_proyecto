import { Router } from 'express';
import { authGuard } from '../../middlewares/authGuard';
import { overrideKeyGuard } from '../../middlewares/overrideKeyGuard';
import { validate } from '../../middlewares/validate';
import {
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

const router = Router();

// Sync de productos desde FULLPOS (por RNC o ID interno).
// No requiere JWT (POS no tiene login), solo overrideKeyGuard.
router.post(
  '/sync/by-rnc',
  overrideKeyGuard,
  validate(syncProductsByRncSchema),
  async (req, res, next) => {
    try {
      const { companyRnc, companyCloudId, products, deletedProducts } = req.body;
      console.info('[cloud_sync] products.sync.by-rnc', {
        companyRnc: companyRnc ?? null,
        companyCloudId: companyCloudId ?? null,
        count: Array.isArray(products) ? products.length : 0,
      });
      const result = await syncProductsByRnc(
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
  validate(syncProductOperationsSchema),
  async (req, res, next) => {
    try {
      const result = await syncProductOperations({
        companyRnc: req.body.companyRnc,
        companyCloudId: req.body.companyCloudId,
        operations: req.body.operations,
      });
      res.json(result);
    } catch (err) {
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

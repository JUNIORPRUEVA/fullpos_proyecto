import { Router } from 'express';
import { authGuard } from '../../middlewares/authGuard';
import { overrideKeyGuard } from '../../middlewares/overrideKeyGuard';
import { validate } from '../../middlewares/validate';
import {
  createProductSchema,
  listProductsSchema,
  syncProductsByRncSchema,
} from './products.validation';
import { createProduct, listProducts, syncProductsByRnc } from './products.service';

const router = Router();

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

// Sync de productos desde FULLPOS (por RNC)
router.post(
  '/sync/by-rnc',
  overrideKeyGuard,
  validate(syncProductsByRncSchema),
  async (req, res, next) => {
    try {
      const { companyRnc, companyCloudId, products } = req.body;
      const result = await syncProductsByRnc(
        companyRnc,
        products ?? [],
        companyCloudId,
      );
      res.json(result);
    } catch (err) {
      next(err);
    }
  },
);

export default router;

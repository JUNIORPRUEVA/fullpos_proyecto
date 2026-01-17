import { Router } from 'express';
import { authGuard } from '../../middlewares/authGuard';
import { validate } from '../../middlewares/validate';
import { createProductSchema, listProductsSchema } from './products.validation';
import { createProduct, listProducts } from './products.service';

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

export default router;

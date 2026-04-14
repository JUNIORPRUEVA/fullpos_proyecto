import { Router } from 'express';
import { authGuard } from '../../middlewares/authGuard';
import { overrideKeyGuard } from '../../middlewares/overrideKeyGuard';
import { validate } from '../../middlewares/validate';
import { createReturn, listReturns, syncReturnsByRnc } from './returns.service';
import {
  createReturnSchema,
  listReturnsQuerySchema,
  syncReturnsByRncSchema,
} from './returns.validation';

const router = Router();

router.post('/', authGuard, validate(createReturnSchema), async (req, res, next) => {
  try {
    const result = await createReturn(req.user!.companyId, req.body);
    res.status(201).json(result);
  } catch (err) {
    next(err);
  }
});

router.get('/', authGuard, validate(listReturnsQuerySchema, 'query'), async (req, res, next) => {
  try {
    const { from, to, originalSaleId } = req.query as any;
    const result = await listReturns(req.user!.companyId, {
      from,
      to,
      originalSaleId: originalSaleId ? Number(originalSaleId) : undefined,
    });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

router.post('/sync/by-rnc', overrideKeyGuard, validate(syncReturnsByRncSchema), async (req, res, next) => {
  try {
    const { companyRnc, companyCloudId, returns } = req.body;
    console.info('[cloud_sync] returns.sync.by-rnc', {
      companyRnc: companyRnc ?? null,
      companyCloudId: companyCloudId ?? null,
      count: Array.isArray(returns) ? returns.length : 0,
    });
    const result = await syncReturnsByRnc(companyRnc, companyCloudId, returns ?? []);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

export default router;
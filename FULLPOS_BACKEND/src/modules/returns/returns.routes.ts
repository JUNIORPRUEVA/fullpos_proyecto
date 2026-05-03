import { Router } from 'express';
import { authGuard } from '../../middlewares/authGuard';
import { overrideKeyGuard } from '../../middlewares/overrideKeyGuard';
import { validate } from '../../middlewares/validate';
import { buildIdentityLog } from '../../utils/syncLogIdentity';
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
    const { companyRnc, companyCloudId, companyTenantKey, businessId, deviceId, terminalId, returns } = req.body;
    console.info('[cloud_sync] returns.sync.by-rnc', {
      ...buildIdentityLog({ companyTenantKey, companyCloudId, companyRnc }),
      count: Array.isArray(returns) ? returns.length : 0,
    });
    const result = await syncReturnsByRnc({ companyRnc, companyCloudId, companyTenantKey, businessId, deviceId, terminalId }, returns ?? []);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

export default router;
import { Router } from 'express';
import { authGuard } from '../../middlewares/authGuard';
import { overrideKeyGuard } from '../../middlewares/overrideKeyGuard';
import { validate } from '../../middlewares/validate';
import { buildIdentityLog } from '../../utils/syncLogIdentity';
import { syncCategoriesByRncSchema } from './categories.validation';
import { listCategories, syncCategoriesByRnc } from './categories.service';

const router = Router();

router.post('/sync/by-rnc', overrideKeyGuard, validate(syncCategoriesByRncSchema), async (req, res, next) => {
  try {
    const { companyRnc, companyCloudId, companyTenantKey, businessId, deviceId, terminalId, categories } = req.body;
    console.info('[cloud_sync] categories.sync.by-rnc', {
      ...buildIdentityLog({ companyTenantKey, companyCloudId, companyRnc }),
      count: Array.isArray(categories) ? categories.length : 0,
    });
    const result = await syncCategoriesByRnc({ companyRnc, companyCloudId, companyTenantKey, businessId, deviceId, terminalId }, categories ?? []);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

router.use(authGuard);

router.get('/', async (req, res, next) => {
  try {
    const result = await listCategories(req.user!.companyId);
    res.json({ data: result });
  } catch (err) {
    next(err);
  }
});

export default router;

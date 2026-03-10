import { Router } from 'express';
import { overrideKeyGuard } from '../../middlewares/overrideKeyGuard';
import { validate } from '../../middlewares/validate';
import { syncCategoriesByRncSchema } from './categories.validation';
import { syncCategoriesByRnc } from './categories.service';

const router = Router();

router.post('/sync/by-rnc', overrideKeyGuard, validate(syncCategoriesByRncSchema), async (req, res, next) => {
  try {
    const { companyRnc, companyCloudId, categories } = req.body;
    console.info('[cloud_sync] categories.sync.by-rnc', {
      companyRnc: companyRnc ?? null,
      companyCloudId: companyCloudId ?? null,
      count: Array.isArray(categories) ? categories.length : 0,
    });
    const result = await syncCategoriesByRnc(companyRnc, companyCloudId, categories ?? []);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

export default router;

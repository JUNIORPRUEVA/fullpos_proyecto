import { Router } from 'express';
import { overrideKeyGuard } from '../../middlewares/overrideKeyGuard';
import { validate } from '../../middlewares/validate';
import { syncSuppliersByRncSchema } from './suppliers.validation';
import { syncSuppliersByRnc } from './suppliers.service';

const router = Router();

router.post('/sync/by-rnc', overrideKeyGuard, validate(syncSuppliersByRncSchema), async (req, res, next) => {
  try {
    const { companyRnc, companyCloudId, suppliers } = req.body;
    console.info('[cloud_sync] suppliers.sync.by-rnc', {
      companyRnc: companyRnc ?? null,
      companyCloudId: companyCloudId ?? null,
      count: Array.isArray(suppliers) ? suppliers.length : 0,
    });
    const result = await syncSuppliersByRnc(companyRnc, companyCloudId, suppliers ?? []);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

export default router;

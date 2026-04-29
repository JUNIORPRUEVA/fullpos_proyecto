import { Router } from 'express';
import { overrideKeyGuard } from '../../middlewares/overrideKeyGuard';
import { validate } from '../../middlewares/validate';
import { emitCompanyDataChangeEvent } from '../../realtime/realtime.gateway';
import { syncSuppliersByRncSchema } from './suppliers.validation';
import { syncSuppliersByRnc } from './suppliers.service';

const router = Router();

router.post('/sync/by-rnc', overrideKeyGuard, validate(syncSuppliersByRncSchema), async (req, res, next) => {
  try {
    const { companyRnc, companyCloudId, companyTenantKey, businessId, deviceId, terminalId, suppliers } = req.body;
    console.info('[cloud_sync] suppliers.sync.by-rnc', {
      companyRnc: companyRnc ?? null,
      companyCloudId: companyCloudId ?? null,
      companyTenantKey: companyTenantKey ?? null,
      count: Array.isArray(suppliers) ? suppliers.length : 0,
    });
    const result = await syncSuppliersByRnc({ companyRnc, companyCloudId, companyTenantKey, businessId, deviceId, terminalId }, suppliers ?? []);
    await emitCompanyDataChangeEvent({
      companyId: result.companyId,
      entity: 'suppliers',
      action: 'suppliers.synced',
    });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

export default router;

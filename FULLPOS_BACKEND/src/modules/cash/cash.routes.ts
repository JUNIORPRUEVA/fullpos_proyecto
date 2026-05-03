import { Router } from 'express';
import { overrideKeyGuard } from '../../middlewares/overrideKeyGuard';
import { validate } from '../../middlewares/validate';
import { buildIdentityLog } from '../../utils/syncLogIdentity';
import { syncCashByRncSchema } from './cash.validation';
import { syncCashByRnc } from './cash.service';

const router = Router();

router.post('/sync/by-rnc', overrideKeyGuard, validate(syncCashByRncSchema), async (req, res, next) => {
  try {
    const { companyRnc, companyCloudId, companyTenantKey, businessId, deviceId, terminalId, sessions, movements } = req.body;
    console.info('[cloud_sync] cash.sync.by-rnc', {
      ...buildIdentityLog({ companyTenantKey, companyCloudId, companyRnc }),
      sessions: Array.isArray(sessions) ? sessions.length : 0,
      movements: Array.isArray(movements) ? movements.length : 0,
    });
    const result = await syncCashByRnc(
      { companyRnc, companyCloudId, companyTenantKey, businessId, deviceId, terminalId },
      sessions ?? [],
      movements ?? [],
    );
    res.json(result);
  } catch (err) {
    next(err);
  }
});

export default router;

import { Router } from 'express';
import { overrideKeyGuard } from '../../middlewares/overrideKeyGuard';
import { validate } from '../../middlewares/validate';
import { emitCompanyDataChangeEvent } from '../../realtime/realtime.gateway';
import { syncClientsByRncSchema } from './clients.validation';
import { syncClientsByRnc } from './clients.service';

const router = Router();

router.post('/sync/by-rnc', overrideKeyGuard, validate(syncClientsByRncSchema), async (req, res, next) => {
  try {
    const { companyRnc, companyCloudId, clients } = req.body;
    console.info('[cloud_sync] clients.sync.by-rnc', {
      companyRnc: companyRnc ?? null,
      companyCloudId: companyCloudId ?? null,
      count: Array.isArray(clients) ? clients.length : 0,
    });
    const result = await syncClientsByRnc(companyRnc, companyCloudId, clients ?? []);
    await emitCompanyDataChangeEvent({
      companyId: result.companyId,
      entity: 'clients',
      action: 'clients.synced',
    });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

export default router;

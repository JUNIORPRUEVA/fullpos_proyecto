import { Router } from 'express';
import { overrideKeyGuard } from '../../middlewares/overrideKeyGuard';
import { validate } from '../../middlewares/validate';
import { syncSalesByRncSchema } from './sales.validation';
import { syncSalesByRnc } from './sales.service';

const router = Router();

// Sync de ventas desde FULLPOS (por RNC o ID interno).
// No requiere JWT (POS no tiene login), solo overrideKeyGuard.
router.post('/sync/by-rnc', overrideKeyGuard, validate(syncSalesByRncSchema), async (req, res, next) => {
  try {
    const { companyRnc, companyCloudId, sales } = req.body;
    const localCodes = Array.isArray(sales)
      ? Array.from(
          new Set(
            sales
              .map((s: any) => (s?.localCode?.toString() ?? '').trim())
              .filter((v: string) => v.length > 0),
          ),
        )
      : [];
    console.info('[cloud_sync] sales.sync.by-rnc', {
      companyRnc: companyRnc ?? null,
      companyCloudId: companyCloudId ?? null,
      count: Array.isArray(sales) ? sales.length : 0,
      uniqueLocalCodes: localCodes.length,
      localCodesSample: localCodes.slice(0, 6),
    });
    const result = await syncSalesByRnc(companyRnc, companyCloudId, sales ?? []);
    console.info('[cloud_sync] sales.sync.by-rnc.done', {
      ok: (result as any)?.ok ?? null,
      upserted: (result as any)?.upserted ?? null,
      companyId: (result as any)?.companyId ?? null,
      resultsCount: Array.isArray((result as any)?.results)
        ? (result as any).results.length
        : 0,
    });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

export default router;

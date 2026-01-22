import { Router } from 'express';
import { authGuard } from '../../middlewares/authGuard';
import { overrideKeyGuard } from '../../middlewares/overrideKeyGuard';
import { validate } from '../../middlewares/validate';
import { getCompanyConfig, updateCompanyConfig, updateCompanyConfigByRnc } from './companies.service';
import { updateCompanyConfigByRncSchema, updateCompanyConfigSchema } from './companies.validation';

const router = Router();

router.get('/config', authGuard, async (req, res, next) => {
  try {
    if (!req.user) return res.status(401).json({ message: 'Token requerido' });
    const config = await getCompanyConfig(req.user.companyId);
    res.json(config);
  } catch (err) {
    next(err);
  }
});

router.put(
  '/config',
  authGuard,
  validate(updateCompanyConfigSchema),
  async (req, res, next) => {
    try {
      if (!req.user) return res.status(401).json({ message: 'Token requerido' });
      const updated = await updateCompanyConfig(req.user.companyId, req.body);
      res.json(updated);
    } catch (err) {
      next(err);
    }
  },
);

// Sync de configuración de empresa desde FULLPOS (por RNC)
router.put(
  '/config/by-rnc',
  overrideKeyGuard,
  validate(updateCompanyConfigByRncSchema),
  async (req, res, next) => {
    try {
      const { companyRnc, companyCloudId, ...payload } = req.body;
      console.info('[cloud_sync] companies.config.by-rnc', {
        companyRnc: companyRnc ?? null,
        companyCloudId: companyCloudId ?? null,
        companyName: payload?.companyName ?? null,
      });
      const updated = await updateCompanyConfigByRnc(companyRnc, {
        ...payload,
        companyCloudId,
      });
      res.json(updated);
    } catch (err) {
      next(err);
    }
  },
);

export default router;

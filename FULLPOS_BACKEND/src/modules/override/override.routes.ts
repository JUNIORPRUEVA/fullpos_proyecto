import { Router } from 'express';
import { validate } from '../../middlewares/validate';
import {
  approveSchema,
  auditQuerySchema,
  requestSchema,
  verifySchema,
} from './override.validation';
import {
  approveOverride,
  createOverrideRequest,
  getAudit,
  verifyOverride,
} from './override.service';

const router = Router();

router.post('/request', validate(requestSchema), async (req, res, next) => {
  try {
    const result = await createOverrideRequest(req.body);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

router.post('/approve', validate(approveSchema), async (req, res, next) => {
  try {
    const result = await approveOverride(req.body);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

router.post('/verify', validate(verifySchema), async (req, res, next) => {
  try {
    const result = await verifyOverride(req.body);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

router.get('/audit', validate(auditQuerySchema, 'query'), async (req, res, next) => {
  try {
    const { companyId, limit } = req.query as any;
    const audits = await getAudit(Number(companyId), limit ? Number(limit) : 100);
    res.json(audits);
  } catch (err) {
    next(err);
  }
});

export default router;

import { Router } from 'express';
import { asyncHandler } from '../../middlewares/asyncHandler';
import { releasePolicyAudit } from '../../middlewares/releasePolicyAudit';
import { releasePolicyAuthGuard } from '../../middlewares/releasePolicyAuthGuard';
import { releasePolicyRateLimit } from '../../middlewares/releasePolicyRateLimit';
import { validate } from '../../middlewares/validate';
import {
  getFullPosWindowsUpdatePolicy,
  upsertFullPosWindowsUpdatePolicy,
} from './app-updates.service';
import { upsertAppUpdatePolicySchema } from './app-updates.validation';

const router = Router();

router.get('/fullpos/windows', asyncHandler(async (_req, res) => {
  res.json(await getFullPosWindowsUpdatePolicy());
}));

router.put(
  '/fullpos/windows',
  releasePolicyAudit,
  releasePolicyRateLimit,
  releasePolicyAuthGuard,
  validate(upsertAppUpdatePolicySchema),
  asyncHandler(async (req, res) => {
    res.json(await upsertFullPosWindowsUpdatePolicy(req.body));
  }),
);

export default router;

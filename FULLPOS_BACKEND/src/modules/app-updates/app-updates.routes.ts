import { Router } from 'express';
import { authGuard } from '../../middlewares/authGuard';
import { asyncHandler } from '../../middlewares/asyncHandler';
import { requireRoles } from '../../middlewares/requireRoles';
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
  authGuard,
  requireRoles('admin', 'owner'),
  validate(upsertAppUpdatePolicySchema),
  asyncHandler(async (req, res) => {
    res.json(await upsertFullPosWindowsUpdatePolicy(req.body));
  }),
);

export default router;

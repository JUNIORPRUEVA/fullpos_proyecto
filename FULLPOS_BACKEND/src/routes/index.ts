import { Router } from 'express';
import authRoutes from '../modules/auth/auth.routes';
import reportRoutes from '../modules/reports/reports.routes';
import downloadRoutes from '../modules/downloads/downloads.routes';
import overrideRoutes from '../modules/override/override.routes';

const router = Router();

router.use('/auth', authRoutes);
router.use('/reports', reportRoutes);
router.use('/downloads', downloadRoutes);
router.use('/override', overrideRoutes);

export default router;

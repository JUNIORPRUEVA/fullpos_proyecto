import { Router } from 'express';
import authRoutes from '../modules/auth/auth.routes';
import reportRoutes from '../modules/reports/reports.routes';
import downloadRoutes from '../modules/downloads/downloads.routes';
import overrideRoutes from '../modules/override/override.routes';
import productRoutes from '../modules/products/products.routes';
import companiesRoutes from '../modules/companies/companies.routes';
import expensesRoutes from '../modules/expenses/expenses.routes';

const router = Router();

router.use('/auth', authRoutes);
router.use('/reports', reportRoutes);
router.use('/downloads', downloadRoutes);
router.use('/override', overrideRoutes);
router.use('/products', productRoutes);
router.use('/companies', companiesRoutes);
router.use('/expenses', expensesRoutes);

export default router;

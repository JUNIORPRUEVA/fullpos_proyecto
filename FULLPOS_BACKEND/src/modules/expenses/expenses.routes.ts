import { Router } from 'express';
import { authGuard } from '../../middlewares/authGuard';
import { validate } from '../../middlewares/validate';
import { getExpensesSummary } from './expenses.service';
import { listExpensesSchema } from './expenses.validation';

const router = Router();

router.use(authGuard);

router.get('/summary', validate(listExpensesSchema, 'query'), async (req, res, next) => {
  try {
    const { from, to } = req.query as any;
    const summary = await getExpensesSummary(req.user!.companyId, from, to);
    res.json(summary);
  } catch (err) {
    next(err);
  }
});

export default router;

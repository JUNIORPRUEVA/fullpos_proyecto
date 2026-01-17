import { Router } from 'express';
import { authGuard } from '../../middlewares/authGuard';
import { validate } from '../../middlewares/validate';
import { loginSchema, refreshSchema } from './auth.validation';
import { getProfile, login, refresh } from './auth.service';

const router = Router();

router.post('/login', validate(loginSchema), async (req, res, next) => {
  try {
    const { identifier, password } = req.body;
    const result = await login(identifier, password);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

router.post('/refresh', validate(refreshSchema), async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    const result = await refresh(refreshToken);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

router.get('/me', authGuard, async (req, res, next) => {
  try {
    const profile = await getProfile(req.user!.id);
    res.json(profile);
  } catch (err) {
    next(err);
  }
});

export default router;

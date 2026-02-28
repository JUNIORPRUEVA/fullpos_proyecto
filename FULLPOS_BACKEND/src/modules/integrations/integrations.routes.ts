import { Router } from 'express';
import { validate } from '../../middlewares/validate';
import { prisma } from '../../config/prisma';
import { integrationAuthGuard, requireIntegrationScope } from './integrations.auth';
import { listIntegrationProductsQuerySchema } from './integrations.validation';
import { listIntegrationProducts } from './integrations.products.service';

const router = Router();

// Health check for integrations module (no auth, no secrets).
router.get('/health', async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    return res.status(200).json({ ok: true });
  } catch {
    return res.status(503).json({ ok: false });
  }
});

router.use(integrationAuthGuard);

router.get(
  '/products',
  requireIntegrationScope('products:read'),
  validate(listIntegrationProductsQuerySchema, 'query'),
  async (req, res, next) => {
    try {
      const query = req.query as any;
      const updatedSince = query.updated_since ? new Date(query.updated_since) : undefined;
      const result = await listIntegrationProducts(req.integration!.companyId, {
        limit: query.limit,
        updatedSince,
        cursor: query.cursor,
      });
      res.json(result);
    } catch (err) {
      next(err);
    }
  },
);

export default router;

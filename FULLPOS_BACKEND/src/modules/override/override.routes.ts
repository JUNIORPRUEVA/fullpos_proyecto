import { Router } from 'express';
import { authGuard } from '../../middlewares/authGuard';
import { overrideKeyGuard } from '../../middlewares/overrideKeyGuard';
import { validate } from '../../middlewares/validate';
import {
  approveSchema,
  approveDirectSchema,
  auditQuerySchema,
  consumeRequestSchema,
  requestSchema,
  requestsQuerySchema,
  resolveIdsSchema,
  verifySchema,
  virtualProvisionSchema,
} from './override.validation';
import {
  approveOverride,
  approveOverrideDirect,
  consumeApprovedOverrideRequest,
  createOverrideRequest,
  getOverrideRequests,
  getAudit,
  provisionVirtualToken,
  resolveOverrideIds,
  verifyOverride,
} from './override.service';

const router = Router();

router.post('/request', overrideKeyGuard, validate(requestSchema), async (req, res, next) => {
  try {
    const result = await createOverrideRequest(req.body);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

router.post('/approve', authGuard, validate(approveSchema), async (req, res, next) => {
  try {
    const result = await approveOverride({
      ...req.body,
      companyId: req.user!.companyId,
      approvedById: req.user!.id,
    });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

// Aprobar sin token (el POS puede continuar sin ingresar código)
router.post('/approve-direct', authGuard, validate(approveDirectSchema), async (req, res, next) => {
  try {
    const result = await approveOverrideDirect({
      requestId: req.body.requestId,
      companyId: req.user!.companyId,
      approvedById: req.user!.id,
    });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

// Consumir una solicitud aprobada (sin token), para habilitar la acción en el POS.
router.post(
  '/request/consume',
  overrideKeyGuard,
  validate(consumeRequestSchema),
  async (req, res, next) => {
    try {
      const result = await consumeApprovedOverrideRequest(req.body);
      res.json(result);
    } catch (err) {
      next(err);
    }
  },
);

router.post('/verify', overrideKeyGuard, validate(verifySchema), async (req, res, next) => {
  try {
    const result = await verifyOverride(req.body);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

// Resolver de IDs (local->cloud) sin escribir en BD.
router.post(
  '/resolveIds',
  overrideKeyGuard,
  validate(resolveIdsSchema),
  async (req, res, next) => {
    try {
      const result = await resolveOverrideIds(req.body);
      res.json(result);
    } catch (err) {
      next(err);
    }
  },
);

// Token virtual (TOTP): el dueño "activa" (provisiona) el secret para un terminal.
router.post(
  '/virtual/provision',
  authGuard,
  validate(virtualProvisionSchema),
  async (req, res, next) => {
    try {
      const result = await provisionVirtualToken({
        companyId: req.user!.companyId,
        userId: req.user!.id,
        terminalId: req.body.terminalId,
        uid: req.body.uid,
      });
      res.json(result);
    } catch (err) {
      next(err);
    }
  },
);

router.get('/audit', authGuard, validate(auditQuerySchema, 'query'), async (req, res, next) => {
  try {
    const { companyId, limit } = req.query as any;
    const resolvedCompanyId = companyId ? Number(companyId) : req.user!.companyId;
    const audits = await getAudit(resolvedCompanyId, limit ? Number(limit) : 100);
    res.json(audits);
  } catch (err) {
    next(err);
  }
});

router.get(
  '/requests',
  authGuard,
  validate(requestsQuerySchema, 'query'),
  async (req, res, next) => {
    try {
      const { companyId, status, limit } = req.query as any;
      const resolvedCompanyId = companyId ? Number(companyId) : req.user!.companyId;
      const requests = await getOverrideRequests({
        companyId: resolvedCompanyId,
        status,
        limit: limit ? Number(limit) : 50,
      });
      res.json(requests);
    } catch (err) {
      next(err);
    }
  },
);

export default router;

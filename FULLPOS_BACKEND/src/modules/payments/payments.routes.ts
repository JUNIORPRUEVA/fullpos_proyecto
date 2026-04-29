import { Router } from 'express';
import { authGuard } from '../../middlewares/authGuard';
import { overrideKeyGuard } from '../../middlewares/overrideKeyGuard';
import { validate } from '../../middlewares/validate';
import {
  createPayment,
  listPayments,
  syncPaymentsByRnc,
} from './payments.service';
import {
  createPaymentSchema,
  listPaymentsQuerySchema,
  syncPaymentsByRncSchema,
} from './payments.validation';

const router = Router();

router.post('/', authGuard, validate(createPaymentSchema), async (req, res, next) => {
  try {
    const result = await createPayment(req.user!.companyId, req.body);
    res.status(201).json(result);
  } catch (err) {
    next(err);
  }
});

router.get('/', authGuard, validate(listPaymentsQuerySchema, 'query'), async (req, res, next) => {
  try {
    const { from, to, saleId, kind, page, pageSize } = req.query as any;
    const result = await listPayments(req.user!.companyId, {
      from,
      to,
      saleId: saleId ? Number(saleId) : undefined,
      kind,
      page: page ? Number(page) : 1,
      pageSize: pageSize ? Number(pageSize) : 50,
    });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

router.post('/sync/by-rnc', overrideKeyGuard, validate(syncPaymentsByRncSchema), async (req, res, next) => {
  try {
    const { companyRnc, companyCloudId, companyTenantKey, businessId, deviceId, terminalId, payments } = req.body;
    console.info('[cloud_sync] payments.sync.by-rnc', {
      companyRnc: companyRnc ?? null,
      companyCloudId: companyCloudId ?? null,
      companyTenantKey: companyTenantKey ?? null,
      count: Array.isArray(payments) ? payments.length : 0,
    });
    const result = await syncPaymentsByRnc({ companyRnc, companyCloudId, companyTenantKey, businessId, deviceId, terminalId }, payments ?? []);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

export default router;
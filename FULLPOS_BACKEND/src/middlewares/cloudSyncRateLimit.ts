import { NextFunction, Request, Response } from 'express';
import { consumeCloudRateLimit } from '../utils/cloudRateLimit';
import { redactIdentityValue } from '../utils/syncLogIdentity';

type LimitBucket = 'sync' | 'upload' | null;

function firstString(value: unknown): string | null {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : null;
  }
  if (Array.isArray(value) && value.length > 0) {
    return firstString(value[0]);
  }
  return null;
}

function resolveRateLimitBucket(req: Request): LimitBucket {
  const method = req.method.toUpperCase();
  const path = req.path;

  if (method === 'POST' && path === '/uploads/product-image') {
    return 'upload';
  }

  const isSyncByRnc =
    (method === 'POST' || method === 'PUT') && path.endsWith('/sync/by-rnc');
  const isProductsOperations = method === 'POST' && path === '/products/sync/operations';
  const isUsersSync = method === 'POST' && path === '/auth/sync-users';
  const isCompanyConfigSync = method === 'PUT' && path === '/companies/config/by-rnc';

  if (isSyncByRnc || isProductsOperations || isUsersSync || isCompanyConfigSync) {
    return 'sync';
  }

  return null;
}

function resolveIdentityKey(req: Request) {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const query = req.query as Record<string, unknown>;

  const tenantKey =
    firstString(body.companyTenantKey) ||
    firstString(query.companyTenantKey) ||
    firstString(req.headers['x-company-tenant-key']);
  if (tenantKey) {
    return {
      key: `tenant:${tenantKey.toLowerCase()}`,
      source: 'companyTenantKey',
      logValue: redactIdentityValue(tenantKey, 10),
    };
  }

  const cloudCompanyId =
    firstString(body.companyCloudId) ||
    firstString(query.companyCloudId) ||
    firstString(req.headers['x-company-cloud-id']);
  if (cloudCompanyId) {
    return {
      key: `cloud:${cloudCompanyId.toLowerCase()}`,
      source: 'companyCloudId',
      logValue: redactIdentityValue(cloudCompanyId, 8),
    };
  }

  return {
    key: `ip:${req.ip || 'unknown'}`,
    source: 'ip',
    logValue: req.ip || 'unknown',
  };
}

export function cloudSyncRateLimit(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const bucket = resolveRateLimitBucket(req);
  if (!bucket) return next();

  const identity = resolveIdentityKey(req);
  const result = consumeCloudRateLimit({
    bucket,
    key: identity.key,
  });

  if (result.allowed) {
    return next();
  }

  const retryAfterSec = Math.ceil(result.retryAfterMs / 1000);
  res.setHeader('Retry-After', String(retryAfterSec));
  console.warn('[rate_limit.blocked]', {
    endpoint: req.path,
    method: req.method,
    bucket,
    identitySource: identity.source,
    identity: identity.logValue,
    retryAfterSec,
  });
  return res.status(429).json({
    message: 'Demasiadas solicitudes, intente de nuevo en unos segundos.',
    errorCode: 'SYNC_RATE_LIMIT_EXCEEDED',
    retryAfterSec,
  });
}

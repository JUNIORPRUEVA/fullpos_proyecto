import { NextFunction, Request, Response } from 'express';
import { buildIdentityLog } from '../utils/syncLogIdentity';

function isTrackedEndpoint(req: Request) {
  const method = req.method.toUpperCase();
  const path = req.path;

  if (method === 'POST' && path === '/uploads/product-image') return true;
  if ((method === 'POST' || method === 'PUT') && path.endsWith('/sync/by-rnc')) {
    return true;
  }
  if (method === 'POST' && path === '/products/sync/operations') return true;
  if (method === 'POST' && path === '/auth/sync-users') return true;
  if (method === 'PUT' && path === '/companies/config/by-rnc') return true;

  return false;
}

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

export function cloudSyncAuditLog(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  if (!isTrackedEndpoint(req)) return next();

  const startedAt = Date.now();
  const body = (req.body ?? {}) as Record<string, unknown>;
  const query = req.query as Record<string, unknown>;
  const identity = {
    companyTenantKey:
      firstString(body.companyTenantKey) ?? firstString(query.companyTenantKey),
    companyCloudId:
      firstString(body.companyCloudId) ?? firstString(query.companyCloudId),
    companyRnc: firstString(body.companyRnc) ?? firstString(query.companyRnc),
  };

  res.on('finish', () => {
    const durationMs = Date.now() - startedAt;
    console.info('[cloud_sync.audit]', {
      endpoint: req.path,
      method: req.method,
      status: res.statusCode,
      durationMs,
      ...buildIdentityLog(identity),
    });
  });

  next();
}

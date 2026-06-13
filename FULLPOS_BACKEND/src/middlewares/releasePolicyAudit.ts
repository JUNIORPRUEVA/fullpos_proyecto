import { NextFunction, Request, Response } from 'express';

export function releasePolicyAudit(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const startedAt = new Date().toISOString();
  res.once('finish', () => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const statusCode = res.statusCode;
    console.info('[app_update.policy_publication]', {
      attemptedAt: startedAt,
      authenticationMethod: req.releasePolicyAuthMethod ?? 'none',
      result:
        statusCode >= 200 && statusCode < 300
          ? 'success'
          : statusCode === 401 || statusCode === 403
            ? 'authentication_failed'
            : statusCode === 429
              ? 'rate_limited'
              : statusCode >= 400 && statusCode < 500
                ? 'validation_failed'
                : 'server_failed',
      version: typeof body.version === 'string' ? body.version : null,
      buildNumber:
        typeof body.buildNumber === 'number' ||
        typeof body.buildNumber === 'string'
          ? body.buildNumber
          : null,
      statusCode,
      completedAt: new Date().toISOString(),
    });
  });
  next();
}

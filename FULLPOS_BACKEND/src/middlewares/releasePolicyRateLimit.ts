import { NextFunction, Request, Response } from 'express';

const windowMs = 10 * 60_000;
const maxAttempts = 10;
const attempts = new Map<string, number[]>();

export function releasePolicyRateLimit(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const key = req.ip || 'unknown';
  const now = Date.now();
  const recent = (attempts.get(key) ?? []).filter(
    (timestamp) => now - timestamp < windowMs,
  );
  recent.push(now);
  attempts.set(key, recent);

  if (recent.length <= maxAttempts) {
    return next();
  }

  const retryAfterSec = Math.ceil(
    (windowMs - (now - recent[0])) / 1000,
  );
  res.setHeader('Retry-After', String(Math.max(1, retryAfterSec)));
  return res.status(429).json({
    message: 'Demasiados intentos de publicación. Intenta nuevamente más tarde.',
    errorCode: 'RELEASE_POLICY_RATE_LIMITED',
  });
}

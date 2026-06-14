import { timingSafeEqual } from 'crypto';
import { NextFunction, Request, Response } from 'express';
import env from '../config/env';
import { authGuard } from './authGuard';
import { requireRoles } from './requireRoles';

export function timingSafeSecretEqual(provided: string, expected: string) {
  const providedBuffer = Buffer.from(provided, 'utf8');
  const expectedBuffer = Buffer.from(expected, 'utf8');
  if (providedBuffer.length !== expectedBuffer.length) {
    return false;
  }
  return timingSafeEqual(providedBuffer, expectedBuffer);
}

function reject(res: Response) {
  return res.status(401).json({
    message: 'Credenciales de publicación inválidas',
    errorCode: 'RELEASE_POLICY_UNAUTHORIZED',
  });
}

export function createReleasePolicyAuthGuard(
  fullPosKey = env.FULLPOS_RELEASE_API_KEY,
  fullCreditKey = env.FULLCREDIT_RELEASE_API_KEY,
) {
  const adminRoles = requireRoles('admin', 'owner');

  return (req: Request, res: Response, next: NextFunction) => {
    const rawHeader = req.headers['x-release-key'];
    if (rawHeader !== undefined) {
      req.releasePolicyAuthMethod = 'release_key';
      if (typeof rawHeader !== 'string') {
        return reject(res);
      }

      const providedKey = rawHeader;
      const isFullCredit = req.path.includes('/fullcredit/android');
      const configuredKey = (
        isFullCredit ? fullCreditKey : fullPosKey
      )?.trim() ?? '';
      if (
        providedKey.trim().length === 0 ||
        configuredKey.length < 32 ||
        !timingSafeSecretEqual(providedKey, configuredKey)
      ) {
        return reject(res);
      }
      return next();
    }

    req.releasePolicyAuthMethod = 'admin_session';
    return authGuard(req, res, (authError?: unknown) => {
      if (authError) return next(authError);
      return adminRoles(req, res, next);
    });
  };
}

export const releasePolicyAuthGuard = createReleasePolicyAuthGuard();

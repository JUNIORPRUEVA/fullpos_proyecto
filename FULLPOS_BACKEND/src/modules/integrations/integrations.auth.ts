import { NextFunction, Request, Response } from 'express';
import crypto from 'crypto';
import env from '../../config/env';
import { prisma } from '../../config/prisma';

function hashIntegrationToken(rawToken: string) {
  const pepper = env.INTEGRATION_TOKEN_PEPPER?.trim() ?? '';
  return crypto
    .createHash('sha256')
    .update(`${pepper}${rawToken}`)
    .digest('hex');
}

export function integrationAuthGuard(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Integration token requerido' });
  }

  const rawToken = authHeader.substring(7).trim();
  if (!rawToken) {
    return res.status(401).json({ message: 'Integration token requerido' });
  }

  const tokenHash = hashIntegrationToken(rawToken);

  prisma.integrationToken
    .findUnique({ where: { tokenHash } })
    .then(async (record) => {
      if (!record) {
        return res.status(401).json({ message: 'Integration token inválido' });
      }

      const now = new Date();
      if (record.revokedAt) {
        return res.status(401).json({ message: 'Integration token revocado' });
      }
      if (record.expiresAt && record.expiresAt.getTime() <= now.getTime()) {
        return res.status(401).json({ message: 'Integration token expirado' });
      }

      // Attach tenant context (companyId) server-side.
      req.integration = {
        tokenId: record.id,
        companyId: record.companyId,
        scopes: record.scopes,
      };

      // Best-effort bookkeeping.
      prisma.integrationToken
        .update({ where: { id: record.id }, data: { lastUsedAt: now } })
        .catch(() => undefined);

      return next();
    })
    .catch((err) => next(err));
}

export function requireIntegrationScope(scope: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const scopes = req.integration?.scopes ?? [];
    if (!scopes.includes(scope)) {
      return res.status(403).json({ message: 'Scope insuficiente' });
    }
    return next();
  };
}

import { Request, Response, NextFunction } from 'express';
import env from '../config/env';

export function overrideKeyGuard(req: Request, res: Response, next: NextFunction) {
  if (env.ALLOW_PUBLIC_CLOUD === true) {
    return next();
  }

  const apiKey = env.OVERRIDE_API_KEY?.trim();
  if (!apiKey) {
    return next();
  }

  const provided =
    (req.headers['x-override-key'] as string | undefined) ??
    (req.headers['x-cloud-key'] as string | undefined) ??
    bearerTokenFromHeader(req.headers.authorization);

  if (!provided || provided.trim() != apiKey) {
    return res.status(401).json({ message: 'API key requerida' });
  }

  return next();
}

function bearerTokenFromHeader(authorization: string | undefined): string | undefined {
  if (!authorization) return undefined;
  const [scheme, token] = authorization.trim().split(/\s+/, 2);
  if (!scheme || !token) return undefined;
  if (scheme.toLowerCase() !== 'bearer') return undefined;
  return token;
}

import { NextFunction, Request, Response } from 'express';

export function requireRoles(...allowedRoles: string[]) {
  const normalized = allowedRoles.map((role) => role.trim().toLowerCase());

  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Token requerido' });
    }

    const role = (req.user.role ?? '').trim().toLowerCase();
    if (!normalized.includes(role)) {
      return res.status(403).json({ message: 'No autorizado para esta operación' });
    }

    next();
  };
}
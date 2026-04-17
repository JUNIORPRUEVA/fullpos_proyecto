import crypto from 'crypto';
import { NextFunction, Request, Response } from 'express';

export function requestContext(req: Request, res: Response, next: NextFunction) {
  const forwarded = req.header('x-correlation-id')?.trim();
  const legacy = req.header('x-request-id')?.trim();
  const requestId = forwarded || legacy || crypto.randomUUID();

  req.requestId = requestId;
  res.setHeader('x-correlation-id', requestId);

  next();
}
import { NextFunction, Request, Response } from 'express';
import { ZodError } from 'zod';

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function errorHandler(err: any, _req: Request, res: Response, _next: NextFunction) {
  if (err instanceof ZodError) {
    return res.status(400).json({
      message: 'Validation error',
      errorCode: 'VALIDATION_ERROR',
      issues: err.issues.map((issue) => ({ path: issue.path, message: issue.message })),
    });
  }

  // Common upload validation errors
  if (err?.message === 'Solo imágenes') {
    return res.status(400).json({ message: 'Solo imágenes' });
  }
  if (err?.name === 'MulterError') {
    return res.status(400).json({ message: err.message ?? 'Upload error' });
  }

  if (err?.status) {
    const payload: any = { message: err.message ?? 'Request error' };
    if (err.errorCode) payload.errorCode = err.errorCode;
    if (err.details) payload.details = err.details;
    return res.status(err.status).json(payload);
  }

  console.error(err);
  return res.status(500).json({ message: 'Unexpected error' });
}

export function notFound(_req: Request, res: Response) {
  res.status(404).json({ message: 'Not found' });
}

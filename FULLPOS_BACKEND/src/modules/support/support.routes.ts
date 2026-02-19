import { Router } from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import multer from 'multer';
import env from '../../config/env';
import { overrideKeyGuard } from '../../middlewares/overrideKeyGuard';

const router = Router();

const supportLogsDir =
  env.SUPPORT_LOGS_DIR?.trim() || path.join(process.cwd(), 'uploads', 'support_logs');
if (!fs.existsSync(supportLogsDir)) {
  fs.mkdirSync(supportLogsDir, { recursive: true });
}

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, supportLogsDir),
    filename: (req, file, cb) => {
      const ticketId = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
      (req as any).supportTicketId = ticketId;
      const originalExt = path.extname(file.originalname || '').toLowerCase();
      const ext = originalExt === '.zip' ? '.zip' : '.zip';
      cb(null, `support_${ticketId}${ext}`);
    },
  }),
  limits: { fileSize: (env.MAX_SUPPORT_LOG_MB ?? 50) * 1024 * 1024 },
});

router.post('/logs', overrideKeyGuard, upload.single('file'), async (req, res, next) => {
  try {
    const file = req.file;
    if (!file) {
      return res.status(400).json({ ok: false, message: 'Archivo requerido' });
    }

    const ticketId = String((req as any).supportTicketId ?? '').trim() || null;

    const meta = {
      ok: true,
      ticketId,
      receivedAt: new Date().toISOString(),
      originalName: file.originalname,
      storedName: path.basename(file.path),
      sizeBytes: file.size,
      mimetype: file.mimetype,
      ip: req.ip,
      headers: {
        // Only include the headers we care about for debugging (avoid dumping auth/cookies).
        'user-agent': req.headers['user-agent'] ?? null,
      },
      fields: {
        appVersion: req.body?.appVersion ?? null,
        os: req.body?.os ?? null,
        osVersion: req.body?.osVersion ?? null,
        rnc: req.body?.rnc ?? null,
        cloudCompanyId: req.body?.cloudCompanyId ?? null,
        errorMessage: req.body?.errorMessage ?? null,
      },
    };

    try {
      const metaPath = path.join(
        supportLogsDir,
        ticketId ? `support_${ticketId}.json` : `${path.basename(file.path)}.json`,
      );
      await fs.promises.writeFile(metaPath, JSON.stringify(meta, null, 2), 'utf8');
    } catch (_) {
      // If meta write fails, still consider the upload successful.
    }

    return res.json({
      ok: true,
      ticketId,
      message: ticketId
        ? `Logs recibidos. Ticket: ${ticketId}`
        : 'Logs recibidos. Ticket no disponible.',
    });
  } catch (err) {
    return next(err);
  }
});

export default router;

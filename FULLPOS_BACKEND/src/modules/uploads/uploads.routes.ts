import { Router } from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import multer from 'multer';
import sharp from 'sharp';
import env from '../../config/env';
import { overrideKeyGuard } from '../../middlewares/overrideKeyGuard';
import { prisma } from '../../config/prisma';
import { resolveCompanyIdentity } from '../companies/companyIdentity.service';
import { buildIdentityLog } from '../../utils/syncLogIdentity';

const router = Router();

const uploadsRoot = env.UPLOADS_DIR?.trim() || path.join(process.cwd(), 'uploads');
const productsDir = path.join(uploadsRoot, 'products');

if (!fs.existsSync(productsDir)) {
  fs.mkdirSync(productsDir, { recursive: true });
}

function resolveBaseUrl(req: any) {
  const raw = env.PUBLIC_BASE_URL?.trim() || `${req.protocol}://${req.get('host')}`;
  try {
    const u = new URL(raw);
    const path = (u.pathname || '').trim();
    // Common misconfig: setting PUBLIC_BASE_URL to "https://host/api".
    // Uploads are served at "/uploads" (root), not under "/api".
    if (path === '/api' || path.startsWith('/api/')) {
      u.pathname = '';
    } else if (path && path !== '/') {
      // Be conservative: if any path is provided, drop it so we always return a root base URL.
      u.pathname = '';
    }
    u.search = '';
    u.hash = '';
    const normalized = u.toString();
    return normalized.endsWith('/') ? normalized.substring(0, normalized.length - 1) : normalized;
  } catch (_) {
    // Fallback: basic string normalization
    const withoutApi = raw.replace(/\/?api\/?$/, '');
    return withoutApi.endsWith('/') ? withoutApi.substring(0, withoutApi.length - 1) : withoutApi;
  }
}

function safeDeleteUploadByUrl(url: string) {
  try {
    const parsed = new URL(url);
    const pathname = parsed.pathname || '';
    if (!pathname.startsWith('/uploads/products/')) return;
    const filename = path.basename(pathname);
    const full = path.join(productsDir, filename);
    if (!full.startsWith(productsDir)) return;
    if (fs.existsSync(full)) {
      fs.unlinkSync(full);
    }
  } catch (_) {
    // Ignore invalid URL
  }
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: (env.MAX_UPLOAD_IMAGE_MB ?? 5) * 1024 * 1024 },
  // NOTE: Some clients (Flutter/Windows/Android) may send `application/octet-stream`.
  // We accept the upload here and later validate by decoding with `sharp`.
  fileFilter: (_req, _file, cb) => cb(null, true),
});

function firstString(value: unknown) {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }
  if (Array.isArray(value) && value.length > 0) {
    return firstString(value[0]);
  }
  return undefined;
}

function identityFromRequest(req: any) {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const query = (req.query ?? {}) as Record<string, unknown>;
  return {
    companyTenantKey:
      firstString(body.companyTenantKey) ?? firstString(query.companyTenantKey),
    companyRnc: firstString(body.companyRnc) ?? firstString(query.companyRnc),
    companyCloudId:
      firstString(body.companyCloudId) ?? firstString(query.companyCloudId),
    businessId: firstString(body.businessId) ?? firstString(query.businessId),
    deviceId: firstString(body.deviceId) ?? firstString(query.deviceId),
    terminalId: firstString(body.terminalId) ?? firstString(query.terminalId),
  };
}

async function resolveUploadCompany(req: any, source: string) {
  const identity = identityFromRequest(req);
  if (!identity.companyTenantKey) {
    throw {
      status: 400,
      message: 'companyTenantKey requerido para uploads',
      errorCode: 'COMPANY_TENANT_KEY_REQUIRED',
    };
  }

  const company = await resolveCompanyIdentity({
    ...identity,
    source,
  });
  return {
    companyId: company.id,
    identity,
  };
}

router.post('/product-image', overrideKeyGuard, upload.single('file'), async (req, res, next) => {
  try {
    const file = req.file;
    if (!file) return res.status(400).json({ message: 'Archivo requerido' });

    const { companyId, identity } = await resolveUploadCompany(
      req,
      'uploads.product-image',
    );

    console.info('[cloud_sync] uploads.product-image', {
      mimetype: file.mimetype,
      size: file.size,
      ...buildIdentityLog(identity),
      hasOldImageUrl: typeof req.body?.oldImageUrl === 'string' && req.body.oldImageUrl.trim().length > 0,
    });

    const maxImages = env.MAX_PRODUCT_IMAGES_PER_COMPANY ?? 200;
    const oldImageUrl = req.body?.oldImageUrl;
    if (typeof oldImageUrl !== 'string' || oldImageUrl.trim().length == 0) {
      const current = await prisma.product.count({
        where: { companyId, imageUrl: { not: null } },
      });
      if (current >= maxImages) {
        return res.status(400).json({ message: `Límite de ${maxImages} imágenes alcanzado` });
      }
    }

    const width = env.MAX_IMAGE_WIDTH ?? 1600;
    const height = env.MAX_IMAGE_HEIGHT ?? 1600;
    let processed: Buffer;
    try {
      processed = await sharp(file.buffer)
        .rotate()
        .resize({ width, height, fit: 'inside', withoutEnlargement: true })
        .jpeg({ quality: 90 })
        .toBuffer();
    } catch (_) {
      return res.status(400).json({ message: 'Solo imágenes' });
    }

    const filename = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}.jpg`;
    const fullPath = path.join(productsDir, filename);
    await fs.promises.writeFile(fullPath, processed);

    if (typeof oldImageUrl === 'string' && oldImageUrl.trim().length > 0) {
      const oldImageOwner = await prisma.product.findFirst({
        where: {
          companyId,
          imageUrl: oldImageUrl.trim(),
        },
        select: { id: true },
      });
      if (oldImageOwner) {
        safeDeleteUploadByUrl(oldImageUrl.trim());
      }
    }

    const baseUrl = resolveBaseUrl(req);
    const url = `${baseUrl}/uploads/products/${filename}`;
    return res.json({ ok: true, url, filename });
  } catch (err) {
    return next(err);
  }
});

router.delete('/product-image/:filename', overrideKeyGuard, async (req, res, next) => {
  try {
    const filename = (req.params.filename || '').trim();
    if (!filename || filename.includes('/') || filename.includes('..')) {
      return res.status(400).json({ message: 'Nombre inválido' });
    }

    const { companyId, identity } = await resolveUploadCompany(
      req,
      'uploads.product-image.delete',
    );

    const imageInCompany = await prisma.product.findFirst({
      where: {
        companyId,
        imageUrl: { endsWith: `/uploads/products/${filename}` },
      },
      select: { id: true },
    });
    if (!imageInCompany) {
      console.warn('[cloud_sync] uploads.product-image.delete denied', {
        filename,
        ...buildIdentityLog(identity),
      });
      return res.status(404).json({
        message: 'Imagen no encontrada para la empresa indicada',
        errorCode: 'UPLOAD_IMAGE_NOT_FOUND_FOR_COMPANY',
      });
    }

    const full = path.join(productsDir, filename);
    if (fs.existsSync(full)) {
      fs.unlinkSync(full);
    }

    return res.json({ ok: true });
  } catch (err) {
    const status = (err as any)?.status;
    if (status && Number.isInteger(status)) {
      return res.status(status).json({
        message: (err as any)?.message ?? 'Error de validación de identidad',
        errorCode: (err as any)?.errorCode ?? 'UPLOAD_COMPANY_IDENTITY_ERROR',
      });
    }
    return next(err);
  }
});

export default router;
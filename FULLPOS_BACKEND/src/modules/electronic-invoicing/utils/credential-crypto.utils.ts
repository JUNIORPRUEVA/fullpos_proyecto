import crypto from 'crypto';
import env from '../../../config/env';

export const INLINE_CERTIFICATE_PREFIX = 'inline-p12:';

function getRequiredFeMasterKey() {
  const key = process.env.FE_MASTER_ENCRYPTION_KEY?.trim() || env.FE_MASTER_ENCRYPTION_KEY?.trim();
  if (!key) {
    throw {
      status: 503,
      message: 'La facturación electrónica requiere FE_MASTER_ENCRYPTION_KEY configurada',
      errorCode: 'FE_MASTER_ENCRYPTION_KEY_MISSING',
    };
  }

  return key;
}

function deriveSecretKey() {
  return crypto.createHash('sha256').update(getRequiredFeMasterKey()).digest();
}

export function encryptSecret(secret: string) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', deriveSecretKey(), iv);
  const encrypted = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('base64')}.${tag.toString('base64')}.${encrypted.toString('base64')}`;
}

export function decryptSecret(secret: string) {
  const [ivB64, tagB64, payloadB64] = secret.split('.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', deriveSecretKey(), Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(payloadB64, 'base64')),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}

export function encryptBinarySecret(buffer: Buffer) {
  return encryptSecret(buffer.toString('base64'));
}

export function decryptBinarySecret(secret: string) {
  return Buffer.from(decryptSecret(secret), 'base64');
}

export function isInlineCertificateReference(secretReference?: string | null) {
  return !!secretReference?.startsWith(INLINE_CERTIFICATE_PREFIX);
}
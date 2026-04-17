import crypto from 'crypto';

export function sha256Hex(value: string | Buffer) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function sha256Base64(value: string | Buffer) {
  return crypto.createHash('sha256').update(value).digest('base64');
}

export function hashForStorage(value: string) {
  return sha256Hex(Buffer.from(value, 'utf8'));
}
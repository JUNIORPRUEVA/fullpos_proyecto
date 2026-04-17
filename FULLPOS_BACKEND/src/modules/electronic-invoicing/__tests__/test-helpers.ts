import fs from 'fs';
import os from 'os';
import path from 'path';
import forge from 'node-forge';

export function ensureFeTestEnv() {
  process.env.NODE_ENV = process.env.NODE_ENV ?? 'test';
  process.env.PORT = process.env.PORT ?? '4000';
  process.env.DATABASE_URL = process.env.DATABASE_URL ?? 'https://example.test/db';
  process.env.JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET ?? 'test-jwt-access-secret-1234';
  process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET ?? 'test-jwt-refresh-secret-1234';
  process.env.FE_MASTER_ENCRYPTION_KEY =
    process.env.FE_MASTER_ENCRYPTION_KEY ?? 'test-master-key-1234567890-abcdef';
  process.env.FE_SEED_TTL_SECONDS = process.env.FE_SEED_TTL_SECONDS ?? '300';
  process.env.FE_PUBLIC_TOKEN_TTL_SECONDS =
    process.env.FE_PUBLIC_TOKEN_TTL_SECONDS ?? '300';
  process.env.DGII_REQUEST_TIMEOUT_MS = process.env.DGII_REQUEST_TIMEOUT_MS ?? '5000';
  process.env.DGII_REQUEST_MAX_RETRIES = process.env.DGII_REQUEST_MAX_RETRIES ?? '1';
  process.env.DGII_HTTP_USER_AGENT = process.env.DGII_HTTP_USER_AGENT ?? 'FULLPOS-Test';
  process.env.DGII_PRECERT_SUBMIT_URL =
    process.env.DGII_PRECERT_SUBMIT_URL ?? 'https://precert.example.com/submit';
  process.env.DGII_PRECERT_RESULT_URL_TEMPLATE =
    process.env.DGII_PRECERT_RESULT_URL_TEMPLATE ??
    'https://precert.example.com/result/{trackId}';
  process.env.DGII_PRODUCTION_SUBMIT_URL =
    process.env.DGII_PRODUCTION_SUBMIT_URL ?? 'https://prod.example.com/submit';
  process.env.DGII_PRODUCTION_RESULT_URL_TEMPLATE =
    process.env.DGII_PRODUCTION_RESULT_URL_TEMPLATE ??
    'https://prod.example.com/result/{trackId}';
}

type TempPkcs12Options = {
  password?: string;
  commonName?: string;
  validFrom?: Date;
  validTo?: Date;
};

function binaryToBuffer(binary: string) {
  return Buffer.from(binary, 'binary');
}

export function createTempPkcs12(options: TempPkcs12Options = {}) {
  const password = options.password ?? 'secret123';
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey;
  certificate.serialNumber = '1001';
  certificate.validity.notBefore =
    options.validFrom ?? new Date('2025-01-01T00:00:00.000Z');
  certificate.validity.notAfter =
    options.validTo ?? new Date('2027-01-01T00:00:00.000Z');
  const attrs = [{ name: 'commonName', value: options.commonName ?? 'FULLPOS Test Cert' }];
  certificate.setSubject(attrs);
  certificate.setIssuer(attrs);
  certificate.sign(keys.privateKey, forge.md.sha256.create());

  const asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, [certificate], password, {
    algorithm: '3des',
  });
  const der = forge.asn1.toDer(asn1).getBytes();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fullpos-fe-cert-'));
  const filePath = path.join(dir, 'certificado.p12');
  fs.writeFileSync(filePath, binaryToBuffer(der));

  return {
    filePath,
    password,
    certPem: forge.pki.certificateToPem(certificate),
    privateKeyPem: forge.pki.privateKeyToPem(keys.privateKey),
    cleanup() {
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}
#!/usr/bin/env node

/**
 * Safe FULLTECH FE certificate inspection tool.
 *
 * Does not print certificate password, private key, full certificate, or tokens.
 * Does not call DGII.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const forge = require('node-forge');
const { PrismaClient } = require('@prisma/client');
require('dotenv').config();

const INLINE_CERTIFICATE_PREFIX = 'inline-p12:';
const COMPANY_RNC = process.env.INSPECT_FE_COMPANY_RNC || '133080206';
const COMPANY_CLOUD_ID = process.env.INSPECT_FE_COMPANY_CLOUD_ID || 'fp-mnuoujbs-rmt12y';

function getRequiredFeMasterKey() {
  const key = process.env.FE_MASTER_ENCRYPTION_KEY?.trim();
  if (!key) {
    throw new Error('FE_MASTER_ENCRYPTION_KEY_MISSING');
  }
  return key;
}

function deriveSecretKey() {
  return crypto.createHash('sha256').update(getRequiredFeMasterKey()).digest();
}

function decryptSecret(secret) {
  const [ivB64, tagB64, payloadB64] = String(secret || '').split('.');
  if (!ivB64 || !tagB64 || !payloadB64) {
    throw new Error('ENCRYPTED_SECRET_INVALID_FORMAT');
  }

  const decipher = crypto.createDecipheriv('aes-256-gcm', deriveSecretKey(), Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(payloadB64, 'base64')),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}

function decryptBinarySecret(secret) {
  return Buffer.from(decryptSecret(secret), 'base64');
}

function isInlineCertificateReference(secretReference) {
  return !!secretReference?.startsWith(INLINE_CERTIFICATE_PREFIX);
}

function attrsToText(attrs) {
  return attrs.map((attr) => `${attr.shortName || attr.name}=${attr.value}`).join(', ');
}

function getAttribute(cert, nameOrShortName) {
  const normalized = nameOrShortName.toLowerCase();
  const attr = cert.subject.attributes.find((item) => (
    String(item.name || '').toLowerCase() === normalized ||
    String(item.shortName || '').toLowerCase() === normalized
  ));
  return attr?.value || null;
}

function isCaCertificate(cert) {
  const basicConstraints = cert.extensions?.find((extension) => extension.name === 'basicConstraints');
  if (basicConstraints && basicConstraints.cA === true) return true;
  return attrsToText(cert.subject.attributes) === attrsToText(cert.issuer.attributes);
}

function normalizeLocalKeyId(value) {
  if (value == null) return null;
  if (typeof value === 'string') return forge.util.bytesToHex(value);
  if (Array.isArray(value)) return value.map((item) => Number(item).toString(16).padStart(2, '0')).join('');
  if (Buffer.isBuffer(value)) return value.toString('hex');
  return String(value);
}

function keyMatchesCertificate(privateKey, cert) {
  const publicKey = cert.publicKey;
  return !!(
    publicKey?.n &&
    publicKey?.e &&
    privateKey?.n &&
    privateKey?.e &&
    publicKey.n.equals(privateKey.n) &&
    publicKey.e.equals(privateKey.e)
  );
}

function fingerprint(cert, algorithm) {
  const derBytes = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  return crypto
    .createHash(algorithm)
    .update(Buffer.from(derBytes, 'binary'))
    .digest('hex')
    .match(/.{2}/g)
    .join(':')
    .toUpperCase();
}

function selectSigningPair(certEntries, keyEntries) {
  for (const keyEntry of keyEntries) {
    const sameLocalKeyId = keyEntry.localKeyId
      ? certEntries.filter((certEntry) => certEntry.localKeyId === keyEntry.localKeyId)
      : [];
    const localKeyMatch = sameLocalKeyId.find(
      (certEntry) => !isCaCertificate(certEntry.cert) && keyMatchesCertificate(keyEntry.key, certEntry.cert),
    );
    if (localKeyMatch) {
      return { certEntry: localKeyMatch, keyEntry, keyMatchesCertificate: true, selectionMethod: 'localKeyId_and_key_match' };
    }
  }

  for (const keyEntry of keyEntries) {
    const keyMatch = certEntries.find(
      (certEntry) => !isCaCertificate(certEntry.cert) && keyMatchesCertificate(keyEntry.key, certEntry.cert),
    );
    if (keyMatch) {
      return { certEntry: keyMatch, keyEntry, keyMatchesCertificate: true, selectionMethod: 'leaf_key_match' };
    }
  }

  for (const keyEntry of keyEntries) {
    const keyMatch = certEntries.find((certEntry) => keyMatchesCertificate(keyEntry.key, certEntry.cert));
    if (keyMatch) {
      return { certEntry: keyMatch, keyEntry, keyMatchesCertificate: true, selectionMethod: 'any_key_match' };
    }
  }

  const fallbackCert = certEntries.find((certEntry) => !isCaCertificate(certEntry.cert)) || certEntries[0];
  const fallbackKey = keyEntries[0];
  if (!fallbackCert || !fallbackKey) return null;
  return {
    certEntry: fallbackCert,
    keyEntry: fallbackKey,
    keyMatchesCertificate: keyMatchesCertificate(fallbackKey.key, fallbackCert.cert),
    selectionMethod: 'fallback',
  };
}

function inspectPkcs12(buffer, password) {
  const asn1 = forge.asn1.fromDer(buffer.toString('binary'));
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, false, password);
  const shroudedBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] || [];
  const keyBagEntries = p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag] || [];
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];

  const keyEntries = [...shroudedBags, ...keyBagEntries].flatMap((bag, index) => {
    if (!bag.key) return [];
    return [{
      key: bag.key,
      localKeyId: normalizeLocalKeyId(bag.localKeyId),
      friendlyName: bag.friendlyName || null,
      index,
    }];
  });

  const certEntries = certBags.flatMap((bag, index) => {
    if (!bag.cert) return [];
    return [{
      cert: bag.cert,
      localKeyId: normalizeLocalKeyId(bag.localKeyId),
      friendlyName: bag.friendlyName || null,
      index,
      isCa: isCaCertificate(bag.cert),
      subject: attrsToText(bag.cert.subject.attributes),
      issuer: attrsToText(bag.cert.issuer.attributes),
      validFrom: bag.cert.validity.notBefore.toISOString(),
      validTo: bag.cert.validity.notAfter.toISOString(),
      serialNumber: bag.cert.serialNumber,
      fingerprintSha256: fingerprint(bag.cert, 'sha256'),
    }];
  });

  const selected = selectSigningPair(certEntries, keyEntries);
  if (!selected) {
    throw new Error('PKCS12_NO_USABLE_SIGNING_PAIR');
  }

  const cert = selected.certEntry.cert;
  const subject = attrsToText(cert.subject.attributes);
  const issuer = attrsToText(cert.issuer.attributes);
  const now = Date.now();
  const validDate = cert.validity.notBefore.getTime() <= now && cert.validity.notAfter.getTime() >= now;
  const normalizedSubject = subject.toUpperCase();
  const containsYunior = normalizedSubject.includes('YUNIOR LOPEZ DE LA ROSA');
  const containsDocument = subject.includes('40238377333');
  const hasPrivateKey = !!selected.keyEntry?.key;

  return {
    subject,
    commonName: getAttribute(cert, 'commonName') || getAttribute(cert, 'CN'),
    givenName: getAttribute(cert, 'givenName'),
    surname: getAttribute(cert, 'surname'),
    serialNumber: cert.serialNumber,
    issuer,
    validFrom: cert.validity.notBefore.toISOString(),
    validTo: cert.validity.notAfter.toISOString(),
    fingerprintSha1: fingerprint(cert, 'sha1'),
    fingerprintSha256: fingerprint(cert, 'sha256'),
    certificateCount: certEntries.length,
    selectedCertificateIndex: selected.certEntry.index,
    selectionMethod: selected.selectionMethod,
    selectedCertificateIsCa: isCaCertificate(cert),
    privateKeyExists: hasPrivateKey,
    keyMatchesCertificate: selected.keyMatchesCertificate,
    certificateExpired: !validDate,
    subjectContainsYunior: containsYunior,
    subjectContainsDocument40238377333: containsDocument,
    allCertificates: certEntries.map((entry) => ({
      index: entry.index,
      isCa: entry.isCa,
      subject: entry.subject,
      issuer: entry.issuer,
      validFrom: entry.validFrom,
      validTo: entry.validTo,
      serialNumber: entry.serialNumber,
      fingerprintSha256: entry.fingerprintSha256,
    })),
    CERTIFICATE_MATCHES_YUNIOR: containsYunior && containsDocument,
    CERTIFICATE_HAS_PRIVATE_KEY: hasPrivateKey && selected.keyMatchesCertificate,
    CERTIFICATE_VALID_DATE: validDate,
    BACKEND_CERTIFICATE_READY: containsYunior && containsDocument && hasPrivateKey && selected.keyMatchesCertificate && validDate,
  };
}

function resolveCertificateFilePath(filePath, secretReference) {
  if (filePath && filePath.trim()) return path.resolve(filePath.trim());
  if (secretReference?.startsWith('env:')) {
    const envKey = secretReference.slice(4).trim();
    const resolved = process.env[envKey]?.trim();
    if (!resolved) throw new Error(`CERTIFICATE_PATH_ENV_MISSING:${envKey}`);
    return path.resolve(resolved);
  }
  throw new Error('CERTIFICATE_PATH_NOT_RESOLVABLE');
}

function assertPostgresDatabaseUrl() {
  const databaseUrl = process.env.DATABASE_URL || '';
  if (!databaseUrl) {
    throw new Error('DATABASE_URL_MISSING');
  }
  if (!databaseUrl.startsWith('postgresql://') && !databaseUrl.startsWith('postgres://')) {
    throw new Error('DATABASE_URL_NOT_POSTGRESQL');
  }
}

async function main() {
  assertPostgresDatabaseUrl();
  const prisma = new PrismaClient();
  try {
    const company = await prisma.company.findFirst({
      where: {
        OR: [
          { cloudCompanyId: COMPANY_CLOUD_ID },
          { rnc: COMPANY_RNC },
        ],
      },
      orderBy: [{ cloudCompanyId: 'desc' }],
      select: { id: true, name: true, rnc: true, cloudCompanyId: true },
    });

    if (!company) throw new Error('COMPANY_NOT_FOUND');

    const certificate = await prisma.electronicCertificate.findFirst({
      where: { companyId: company.id, status: 'ACTIVE' },
      orderBy: { updatedAt: 'desc' },
    });

    if (!certificate) throw new Error('ACTIVE_CERTIFICATE_NOT_FOUND');

    const password = decryptSecret(certificate.passwordEncrypted);
    const certificateSource = isInlineCertificateReference(certificate.secretReference)
      ? 'inline-encrypted-db'
      : certificate.filePath?.trim()
        ? 'file-path'
        : certificate.secretReference?.startsWith('env:')
          ? 'env-file-path'
          : 'unknown';
    const p12Buffer = isInlineCertificateReference(certificate.secretReference)
      ? decryptBinarySecret(certificate.secretReference.slice(INLINE_CERTIFICATE_PREFIX.length))
      : fs.readFileSync(resolveCertificateFilePath(certificate.filePath, certificate.secretReference));
    const inspected = inspectPkcs12(p12Buffer, password);

    const output = {
      companyRequested: { companyRnc: COMPANY_RNC, companyCloudId: COMPANY_CLOUD_ID },
      companyResolved: company,
      certificateRecord: {
        id: certificate.id,
        alias: certificate.alias,
        status: certificate.status,
        source: certificateSource,
        filePathPresent: !!certificate.filePath,
        inlineStored: isInlineCertificateReference(certificate.secretReference),
        updatedAt: certificate.updatedAt,
      },
      selectedCertificate: inspected,
      finalResult: {
        CERTIFICATE_MATCHES_YUNIOR: inspected.CERTIFICATE_MATCHES_YUNIOR,
        CERTIFICATE_HAS_PRIVATE_KEY: inspected.CERTIFICATE_HAS_PRIVATE_KEY,
        CERTIFICATE_VALID_DATE: inspected.CERTIFICATE_VALID_DATE,
        BACKEND_CERTIFICATE_READY: inspected.BACKEND_CERTIFICATE_READY,
      },
    };

    console.log(JSON.stringify(output, null, 2));
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((error) => {
  console.error(JSON.stringify({ ok: false, errorCode: error.message || 'INSPECT_CERTIFICATE_FAILED' }, null, 2));
  process.exit(1);
});

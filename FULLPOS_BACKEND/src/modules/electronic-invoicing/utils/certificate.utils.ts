import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import forge from 'node-forge';

export interface LoadedPkcs12Certificate {
  certPem: string;
  privateKeyPem: string;
  serialNumber: string;
  issuer: string;
  subject: string;
  validFrom: Date;
  validTo: Date;
  chainPems: string[];
  keyMatchesCertificate: boolean;
  certificateCount: number;
  selectedCertificateIndex: number;
  fingerprintSha1: string;
  fingerprintSha256: string;
}

export interface CertificateSubjectAnalysis {
  isNaturalPerson: boolean;
  isLegalEntity: boolean;
  rncInCertificate: string | null;
  rncMatchesCompany: boolean;
  certSubjectShort: string;
  chainCertCount: number;
}

export interface CertificateIdentitySnapshot {
  certificateSubjectName: string | null;
  certificateDocumentNumber: string | null;
  certificateAppearsNaturalPerson: boolean;
}

function attrsToText(attrs: forge.pki.CertificateField[]) {
  return attrs
    .map((attr) => `${attr.shortName ?? attr.name}=${attr.value}`)
    .join(', ');
}

function bufferToBinary(buffer: Buffer) {
  return buffer.toString('binary');
}

function normalizeLocalKeyId(value: unknown) {
  if (value == null) return null;
  if (typeof value === 'string') {
    return forge.util.bytesToHex(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => Number(item).toString(16).padStart(2, '0')).join('');
  }
  if (Buffer.isBuffer(value)) {
    return value.toString('hex');
  }
  return String(value);
}

function isCaCertificate(cert: forge.pki.Certificate) {
  const basicConstraints = cert.extensions?.find((extension) => extension.name === 'basicConstraints');
  if (basicConstraints && (basicConstraints as any).cA === true) return true;
  return attrsToText(cert.subject.attributes) === attrsToText(cert.issuer.attributes);
}

function keyMatchesCertificate(privateKey: forge.pki.PrivateKey, cert: forge.pki.Certificate) {
  const certPublicKey = cert.publicKey as forge.pki.rsa.PublicKey;
  const rsaPrivateKey = privateKey as forge.pki.rsa.PrivateKey;
  return !!(
    certPublicKey?.n &&
    certPublicKey?.e &&
    rsaPrivateKey?.n &&
    rsaPrivateKey?.e &&
    certPublicKey.n.equals(rsaPrivateKey.n) &&
    certPublicKey.e.equals(rsaPrivateKey.e)
  );
}

function certificateFingerprint(cert: forge.pki.Certificate, algorithm: 'sha1' | 'sha256') {
  const derBytes = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  return crypto
    .createHash(algorithm)
    .update(Buffer.from(derBytes, 'binary'))
    .digest('hex')
    .match(/.{2}/g)!
    .join(':')
    .toUpperCase();
}

type CertBagEntry = {
  cert: forge.pki.Certificate;
  localKeyId: string | null;
  friendlyName: string | null;
  index: number;
};

type KeyBagEntry = {
  key: forge.pki.rsa.PrivateKey;
  localKeyId: string | null;
  friendlyName: string | null;
  index: number;
};

function getBagFriendlyName(bag: forge.pkcs12.Bag) {
  const value = (bag as any).friendlyName;
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : null;
}

function selectSigningPair(certEntries: CertBagEntry[], keyEntries: KeyBagEntry[]) {
  for (const keyEntry of keyEntries) {
    const sameLocalKeyId = keyEntry.localKeyId
      ? certEntries.filter((certEntry) => certEntry.localKeyId === keyEntry.localKeyId)
      : [];
    const localKeyMatch = sameLocalKeyId.find(
      (certEntry) => !isCaCertificate(certEntry.cert) && keyMatchesCertificate(keyEntry.key, certEntry.cert),
    );
    if (localKeyMatch) {
      return { certEntry: localKeyMatch, keyEntry, keyMatchesCertificate: true };
    }
  }

  for (const keyEntry of keyEntries) {
    const keyMatch = certEntries.find(
      (certEntry) => !isCaCertificate(certEntry.cert) && keyMatchesCertificate(keyEntry.key, certEntry.cert),
    );
    if (keyMatch) {
      return { certEntry: keyMatch, keyEntry, keyMatchesCertificate: true };
    }
  }

  for (const keyEntry of keyEntries) {
    const keyMatch = certEntries.find((certEntry) => keyMatchesCertificate(keyEntry.key, certEntry.cert));
    if (keyMatch) {
      return { certEntry: keyMatch, keyEntry, keyMatchesCertificate: true };
    }
  }

  const fallbackCert = certEntries.find((certEntry) => !isCaCertificate(certEntry.cert)) ?? certEntries[0];
  const fallbackKey = keyEntries[0];
  if (!fallbackCert || !fallbackKey) return null;
  return {
    certEntry: fallbackCert,
    keyEntry: fallbackKey,
    keyMatchesCertificate: keyMatchesCertificate(fallbackKey.key, fallbackCert.cert),
  };
}

export function resolveCertificateFilePath(filePath?: string | null, secretReference?: string | null) {
  if (filePath?.trim()) {
    return path.resolve(filePath.trim());
  }

  if (secretReference?.startsWith('env:')) {
    const envKey = secretReference.slice(4).trim();
    const resolved = process.env[envKey]?.trim();
    if (!resolved) {
      throw new Error(`No se encontró la ruta de certificado en la variable ${envKey}`);
    }
    return path.resolve(resolved);
  }

  throw new Error('No hay una ruta de certificado resoluble');
}

export function loadPkcs12Certificate(certificatePath: string, password: string): LoadedPkcs12Certificate {
  const fileBuffer = fs.readFileSync(certificatePath);
  return loadPkcs12CertificateFromBuffer(fileBuffer, password);
}

export function loadPkcs12CertificateFromBuffer(fileBuffer: Buffer, password: string): LoadedPkcs12Certificate {
  const asn1 = forge.asn1.fromDer(bufferToBinary(fileBuffer));
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, false, password);
  const shroudedBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] ?? [];
  const keyBagEntries = p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag] ?? [];
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] ?? [];

  const keyEntries: KeyBagEntry[] = [...shroudedBags, ...keyBagEntries].flatMap((bag, index) => {
    if (!bag.key) return [];
    return [{
      key: bag.key as forge.pki.rsa.PrivateKey,
      localKeyId: normalizeLocalKeyId((bag as any).localKeyId),
      friendlyName: getBagFriendlyName(bag),
      index,
    }];
  });
  const certEntries: CertBagEntry[] = certBags
    .map((bag, index) => ({
      cert: bag.cert,
      localKeyId: normalizeLocalKeyId((bag as any).localKeyId),
      friendlyName: getBagFriendlyName(bag),
      index,
    }))
    .filter((entry): entry is CertBagEntry => !!entry.cert);

  const selected = selectSigningPair(certEntries, keyEntries);
  if (!selected) {
    throw new Error('El PKCS12 no contiene clave privada y certificado utilizables');
  }

  const cert = selected.certEntry.cert;
  const privateKeyPem = forge.pki.privateKeyToPem(selected.keyEntry.key);
  const certPem = forge.pki.certificateToPem(cert);
  const chainPems = certEntries
    .filter((entry) => entry.index !== selected.certEntry.index)
    .map((entry) => forge.pki.certificateToPem(entry.cert))
    .filter((pem): pem is string => !!pem);

  return {
    certPem,
    privateKeyPem,
    serialNumber: cert.serialNumber,
    issuer: attrsToText(cert.issuer.attributes),
    subject: attrsToText(cert.subject.attributes),
    validFrom: cert.validity.notBefore,
    validTo: cert.validity.notAfter,
    chainPems,
    keyMatchesCertificate: selected.keyMatchesCertificate,
    certificateCount: certEntries.length,
    selectedCertificateIndex: selected.certEntry.index,
    fingerprintSha1: certificateFingerprint(cert, 'sha1'),
    fingerprintSha256: certificateFingerprint(cert, 'sha256'),
  };
}

export function assertCertificateIsCurrentlyValid(validFrom: Date, validTo: Date) {
  const now = Date.now();
  if (validFrom.getTime() > now || validTo.getTime() < now) {
    throw new Error('El certificado está fuera de vigencia');
  }
}

export function certPemToBase64(certPem: string) {
  return certPem
    .replace('-----BEGIN CERTIFICATE-----', '')
    .replace('-----END CERTIFICATE-----', '')
    .replace(/\s+/g, '');
}

export function analyzeCertificateForDgii(
  subject: string,
  issuer: string,
  companyRnc: string | null,
  chainCertCount: number,
): CertificateSubjectAnalysis {
  const subjectUpper = subject.toUpperCase();
  const issuerUpper = issuer.toUpperCase();
  const isNaturalPerson =
    subjectUpper.includes('NATURAL PERSON') ||
    subjectUpper.includes('PERSONA NATURAL') ||
    subjectUpper.includes('PERSONA FISICA') ||
    issuerUpper.includes('NATURAL PERSON');
  const isLegalEntity =
    subjectUpper.includes('LEGAL ENTITY') ||
    subjectUpper.includes('PERSONA JURIDICA') ||
    subjectUpper.includes('JURIDICA') ||
    subjectUpper.includes('LEGAL PERSON');
  const rncInCertificate = subject.match(/\b\d{9}\b/)?.[0] ?? null;
  const normalizedCompanyRnc = companyRnc?.replace(/\D/g, '') ?? null;
  const rncMatchesCompany = !!(rncInCertificate && normalizedCompanyRnc && rncInCertificate === normalizedCompanyRnc);
  const certSubjectShort = subject.match(/CN=([^,]+)/i)?.[1]?.trim() ?? subject.slice(0, 100);

  return {
    isNaturalPerson,
    isLegalEntity,
    rncInCertificate,
    rncMatchesCompany,
    certSubjectShort,
    chainCertCount,
  };
}

export function normalizeSignerDocumentNumber(value: string | null | undefined) {
  return (value ?? '').trim().replace(/[\s-]+/g, '');
}

export function extractCertificateIdentity(subject: string, serialNumber: string): CertificateIdentitySnapshot {
  const certificateSubjectName = subject.match(/CN=([^,]+)/i)?.[1]?.trim() ?? null;
  const source = `${serialNumber} ${subject}`;
  const documentMatch =
    source.match(/IDCDO[-: ]?(\d{11,13})/i) ??
    source.match(/CEDULA[-: ]?(\d{11,13})/i) ??
    source.match(/(?:^|\D)(\d{11,13})(?:\D|$)/);
  const certificateDocumentNumber = documentMatch?.[1] ?? null;
  const subjectUpper = subject.toUpperCase();
  const certificateAppearsNaturalPerson =
    subjectUpper.includes('NATURAL PERSON') ||
    subjectUpper.includes('PERSONA NATURAL') ||
    subjectUpper.includes('PERSONA FISICA');

  return {
    certificateSubjectName,
    certificateDocumentNumber,
    certificateAppearsNaturalPerson,
  };
}
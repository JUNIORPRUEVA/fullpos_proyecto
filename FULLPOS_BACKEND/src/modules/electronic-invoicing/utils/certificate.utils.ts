import fs from 'fs';
import path from 'path';
import forge from 'node-forge';

export interface LoadedPkcs12Certificate {
  certPem: string;
  privateKeyPem: string;
  serialNumber: string;
  issuer: string;
  subject: string;
  validFrom: Date;
  validTo: Date;
}

function attrsToText(attrs: forge.pki.CertificateField[]) {
  return attrs
    .map((attr) => `${attr.shortName ?? attr.name}=${attr.value}`)
    .join(', ');
}

function bufferToBinary(buffer: Buffer) {
  return buffer.toString('binary');
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

  const keyBags = [...shroudedBags, ...keyBagEntries];

  const keyBag = keyBags[0];
  const certBag = certBags[0];
  if (!keyBag?.key || !certBag?.cert) {
    throw new Error('El PKCS12 no contiene clave privada y certificado utilizables');
  }

  const cert = certBag.cert;
  const privateKeyPem = forge.pki.privateKeyToPem(keyBag.key);
  const certPem = forge.pki.certificateToPem(cert);

  return {
    certPem,
    privateKeyPem,
    serialNumber: cert.serialNumber,
    issuer: attrsToText(cert.issuer.attributes),
    subject: attrsToText(cert.subject.attributes),
    validFrom: cert.validity.notBefore,
    validTo: cert.validity.notAfter,
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
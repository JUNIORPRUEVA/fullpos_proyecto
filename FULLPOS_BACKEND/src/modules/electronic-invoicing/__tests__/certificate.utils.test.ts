import test from 'node:test';
import assert from 'node:assert/strict';
import forge from 'node-forge';
import { loadPkcs12CertificateFromBuffer } from '../utils/certificate.utils';

function createCertificate(input: {
  commonName: string;
  keys: forge.pki.rsa.KeyPair;
  issuerCert?: forge.pki.Certificate;
  issuerKey?: forge.pki.rsa.PrivateKey;
  serialNumber: string;
  isCa: boolean;
}) {
  const cert = forge.pki.createCertificate();
  cert.publicKey = input.keys.publicKey;
  cert.serialNumber = input.serialNumber;
  cert.validity.notBefore = new Date('2025-01-01T00:00:00.000Z');
  cert.validity.notAfter = new Date('2027-01-01T00:00:00.000Z');
  const subject = [{ name: 'commonName', value: input.commonName }];
  cert.setSubject(subject);
  cert.setIssuer(input.issuerCert?.subject.attributes ?? subject);
  cert.setExtensions([{ name: 'basicConstraints', cA: input.isCa }]);
  cert.sign(input.issuerKey ?? input.keys.privateKey, forge.md.sha256.create());
  return cert;
}

test('loadPkcs12CertificateFromBuffer extracts the leaf signer certificate, not CA/root', () => {
  const password = 'test-password';
  const caKeys = forge.pki.rsa.generateKeyPair(2048);
  const leafKeys = forge.pki.rsa.generateKeyPair(2048);
  const caCert = createCertificate({
    commonName: 'FULLPOS Test Root CA',
    keys: caKeys,
    serialNumber: '01',
    isCa: true,
  });
  const leafCert = createCertificate({
    commonName: 'DGII Leaf Signer',
    keys: leafKeys,
    issuerCert: caCert,
    issuerKey: caKeys.privateKey,
    serialNumber: '02',
    isCa: false,
  });
  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(leafKeys.privateKey, [caCert, leafCert], password, {
    algorithm: '3des',
  });
  const p12Der = forge.asn1.toDer(p12Asn1).getBytes();

  const loaded = loadPkcs12CertificateFromBuffer(Buffer.from(p12Der, 'binary'), password);

  assert.match(loaded.subject, /CN=DGII Leaf Signer/);
  assert.doesNotMatch(loaded.subject, /Root CA/);
  assert.equal(loaded.keyMatchesCertificate, true);
  assert.ok(loaded.chainPems.length >= 1);
});
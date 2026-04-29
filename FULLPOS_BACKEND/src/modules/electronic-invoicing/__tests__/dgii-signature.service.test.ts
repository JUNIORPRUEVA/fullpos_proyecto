import test from 'node:test';
import assert from 'node:assert/strict';
import forge from 'node-forge';
import { DgiiSignatureService } from '../services/dgii-signature.service';

function createSelfSignedCertificate() {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey;
  certificate.serialNumber = '01';
  certificate.validity.notBefore = new Date('2025-01-01T00:00:00.000Z');
  certificate.validity.notAfter = new Date('2026-01-01T00:00:00.000Z');
  const attrs = [{ name: 'commonName', value: 'FULLPOS Test Cert' }];
  certificate.setSubject(attrs);
  certificate.setIssuer(attrs);
  certificate.sign(keys.privateKey, forge.md.sha256.create());

  return {
    certPem: forge.pki.certificateToPem(certificate),
    privateKeyPem: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

test('DgiiSignatureService signs and verifies XML', () => {
  const { certPem, privateKeyPem } = createSelfSignedCertificate();
  const service = new DgiiSignatureService();
  const xml = '<?xml version="1.0" encoding="UTF-8"?><eCF><Encabezado><IdDoc><eNCF>E310000000001</eNCF></IdDoc></Encabezado></eCF>';

  const signed = service.signXml(xml, privateKeyPem, certPem);
  const verification = service.verifySignedXml(signed);

  assert.match(signed, /<Signature/);
  assert.match(signed, /<DigestValue>/);
  assert.match(signed, /<SignatureValue>/);
  assert.match(signed, /<X509Certificate>/);
  assert.equal(verification.valid, true);
  assert.equal(verification.errors.length, 0);
});

test('DgiiSignatureService signs DGII SemillaModel with empty Reference URI and no root Id', () => {
  const { certPem, privateKeyPem } = createSelfSignedCertificate();
  const service = new DgiiSignatureService();
  const xml = '<?xml version="1.0" encoding="UTF-8"?><SemillaModel xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><valor>abc123</valor><fecha>2026-04-26T00:00:00</fecha></SemillaModel>';

  const signed = service.signSeedXml(xml, privateKeyPem, certPem);
  const diagnostics = service.inspectSignedXml(signed);
  const verification = service.verifySignedXml(signed);

  assert.doesNotMatch(signed, /<SemillaModel[^>]+\s(?:Id|ID|id)="/);
  assert.match(signed, /<Signature/);
  assert.match(signed, /<Reference URI=""/);
  assert.match(signed, /<valor>abc123<\/valor>\s*<fecha>2026-04-26T00:00:00<\/fecha>\s*<Signature/);
  assert.equal(diagnostics.signedXmlRoot, 'SemillaModel');
  assert.equal(diagnostics.signedXmlHasSignature, true);
  assert.equal(diagnostics.signedXmlHasIdAttributeOnRoot, false);
  assert.equal(diagnostics.signedXmlRootId, null);
  assert.equal(diagnostics.signatureReferenceUri, '');
  assert.equal(diagnostics.canonicalizationAlgorithm, 'http://www.w3.org/2001/10/xml-exc-c14n#');
  assert.equal(diagnostics.signatureAlgorithm, 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
  assert.equal(diagnostics.digestAlgorithm, 'http://www.w3.org/2001/04/xmlenc#sha256');
  assert.equal(verification.valid, true);
  assert.equal(verification.errors.length, 0);
});

test('DgiiSignatureService does not mutate signed XML during local verification', () => {
  const { certPem, privateKeyPem } = createSelfSignedCertificate();
  const service = new DgiiSignatureService();
  const xml = '<?xml version="1.0" encoding="UTF-8"?><SemillaModel><valor>abc123</valor><fecha>2026-04-26T00:00:00</fecha></SemillaModel>';

  const signed = service.signSeedXml(xml, privateKeyPem, certPem);
  const beforeVerify = signed;
  const verification = service.verifySignedXml(signed);

  assert.equal(verification.valid, true);
  assert.equal(signed, beforeVerify);
});
#!/usr/bin/env node

/**
 * DGII Postulation XML Signer
 * 
 * Signs a DGII postulation XML file with a .p12/.pfx certificate.
 * Uses XMLDSig standard signing.
 * 
 * Usage:
 *   node tools/sign-dgii-postulation-xml.js \
 *     --xml "path/to/postulation.xml" \
 *     --p12 "path/to/certificate.p12" \
 *     --password "certificate_password" \
 *     --out "path/to/output.xml"
 * 
 * Example:
 *   node tools/sign-dgii-postulation-xml.js \
 *     --xml "C:\\Users\\pc\\Downloads\\202604281552373.xml" \
 *     --p12 "C:\\Users\\pc\\cert.p12" \
 *     --password "MyPassword123" \
 *     --out "C:\\Users\\pc\\Downloads\\202604281552373_firmado.xml"
 */

const fs = require('fs');
const path = require('path');
const forge = require('node-forge');
const { DOMParser, XMLSerializer } = require('@xmldom/xmldom');
const { SignedXml } = require('xml-crypto');

// ============================================================================
// Parse command line arguments
// ============================================================================

function parseArgs() {
  const args = process.argv.slice(2);
  const result = {};
  
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i].replace(/^--/, '');
    const value = args[i + 1];
    result[key] = value;
  }
  
  return result;
}

// ============================================================================
// Validate inputs
// ============================================================================

function validateInputs(args) {
  const errors = [];
  
  if (!args.xml) errors.push('Missing required argument: --xml <path>');
  if (!args.p12) errors.push('Missing required argument: --p12 <path>');
  if (!args.password) errors.push('Missing required argument: --password <password>');
  if (!args.out) errors.push('Missing required argument: --out <path>');
  
  if (args.xml && !fs.existsSync(args.xml)) {
    errors.push(`XML file not found: ${args.xml}`);
  }
  
  if (args.p12 && !fs.existsSync(args.p12)) {
    errors.push(`P12 certificate file not found: ${args.p12}`);
  }
  
  if (errors.length > 0) {
    console.error('\n❌ Validation failed:\n');
    errors.forEach(err => console.error(`  ${err}`));
    console.error('\nUsage:');
    console.error('  node tools/sign-dgii-postulation-xml.js \\');
    console.error('    --xml "path/to/postulation.xml" \\');
    console.error('    --p12 "path/to/certificate.p12" \\');
    console.error('    --password "certificate_password" \\');
    console.error('    --out "path/to/output.xml"\n');
    process.exit(1);
  }
}

// ============================================================================
// Load and parse P12 certificate with chain support
// ============================================================================

function formatCertificateSubject(cert) {
  return cert.subject.attributes.map(attr => `${attr.name}=${attr.value}`).join(', ');
}

function formatCertificateIssuer(cert) {
  return cert.issuer.attributes.map(attr => `${attr.name}=${attr.value}`).join(', ');
}

function isCAcertificate(cert) {
  // Check BasicConstraints extension
  if (cert.extensions && cert.extensions.length > 0) {
    const basicConstraints = cert.extensions.find(ext => ext.name === 'basicConstraints');
    if (basicConstraints && basicConstraints.cA === true) {
      return true;
    }
  }
  // Check if subject === issuer (self-signed, likely CA/root)
  const subjectStr = formatCertificateSubject(cert);
  const issuerStr = formatCertificateIssuer(cert);
  return subjectStr === issuerStr;
}

function isCertificateMatch(cert, keywords) {
  const subject = formatCertificateSubject(cert);
  return keywords.some(keyword => subject.includes(keyword));
}

function loadCertificate(p12Path, password) {
  try {
    const p12Data = fs.readFileSync(p12Path, 'binary');
    const asn1 = forge.asn1.fromDer(p12Data);
    const pkcs12 = forge.pkcs12.pkcs12FromAsn1(asn1, false, password);
    
    // Extract all bags
    if (!pkcs12.getBags) {
      throw new Error('PRIVATE_KEY_NOT_FOUND_IN_P12');
    }
    
    // Get all certificate bags
    // NOTE: getBags returns an object with bagType as key, so we access the array via the OID string
    const certBagsObj = pkcs12.getBags({ bagType: forge.pki.oids.certBag });
    const certBagsRaw = certBagsObj[forge.pki.oids.certBag] || [];
    
    if (!Array.isArray(certBagsRaw) || certBagsRaw.length === 0) {
      throw new Error('CERTIFICATE_NOT_FOUND_IN_P12');
    }
    
    // Extract certificates from bags
    const certificates = [];
    for (let i = 0; i < certBagsRaw.length; i++) {
      const bag = certBagsRaw[i];
      if (bag && bag.cert) {
        certificates.push({
          index: i,
          cert: bag.cert,
          localKeyId: bag.localKeyId,
          friendlyName: bag.friendlyName,
        });
      }
    }
    
    if (certificates.length === 0) {
      throw new Error('CERTIFICATE_NOT_FOUND_IN_P12');
    }
    
    // Get all private key bags
    const pkcs8KeyBagsObj = pkcs12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
    const pkcs8KeyBags = pkcs8KeyBagsObj[forge.pki.oids.pkcs8ShroudedKeyBag] || [];
    
    const keyBagsObj = pkcs12.getBags({ bagType: forge.pki.oids.keyBag });
    const keyBags = keyBagsObj[forge.pki.oids.keyBag] || [];
    
    const allKeyBags = [...pkcs8KeyBags, ...keyBags];
    
    if (allKeyBags.length === 0) {
      throw new Error('PRIVATE_KEY_NOT_FOUND_IN_P12');
    }
    
    // Extract private keys from bags
    const privateKeys = [];
    for (let i = 0; i < allKeyBags.length; i++) {
      const bag = allKeyBags[i];
      if (bag && bag.key) {
        privateKeys.push({
          index: i,
          key: bag.key,
          localKeyId: bag.localKeyId,
          friendlyName: bag.friendlyName,
        });
      }
    }
    
    if (privateKeys.length === 0) {
      throw new Error('PRIVATE_KEY_NOT_FOUND_IN_P12');
    }
    
    // SELECT SIGNING CERTIFICATE
    // Priority:
    // 1. Match by localKeyId/friendlyName if available
    // 2. Match by subject (YUNIOR, IDCDO-40238377333, QUALIFIED CERTIFICATE)
    // 3. Choose end-entity (CA=false or subject != issuer)
    // 4. Never choose root CA unless it's the only one
    
    let selectedCert = null;
    let selectionMethod = 'unknown';
    
    // Method 1: Try to match by localKeyId
    if (privateKeys[0].localKeyId) {
      const matchedCert = certificates.find(c => c.localKeyId === privateKeys[0].localKeyId);
      if (matchedCert) {
        selectedCert = matchedCert.cert;
        selectionMethod = 'localKeyId_match';
      }
    }
    
    // Method 2: Try to match by subject keywords (YUNIOR, IDCDO-40238377333, QUALIFIED)
    if (!selectedCert) {
      const keywords = ['YUNIOR', 'IDCDO-40238377333', 'QUALIFIED CERTIFICATE FOR NATURAL PERSON'];
      const matchedCertObj = certificates.find(c => isCertificateMatch(c.cert, keywords) && !isCAcertificate(c.cert));
      if (matchedCertObj) {
        selectedCert = matchedCertObj.cert;
        selectionMethod = 'subject_match';
      }
    }
    
    // Method 3: Choose end-entity certificates (CA=false or subject != issuer)
    if (!selectedCert) {
      const endEntityCerts = certificates.filter(c => !isCAcertificate(c.cert));
      if (endEntityCerts.length > 0) {
        selectedCert = endEntityCerts[0].cert;
        selectionMethod = 'end_entity_fallback';
      }
    }
    
    // Method 4: If all are CA or only one, use any cert that has matching private key
    if (!selectedCert && certificates.length > 0) {
      selectedCert = certificates[0].cert;
      selectionMethod = 'first_available';
    }
    
    if (!selectedCert) {
      throw new Error('SIGNING_CERTIFICATE_NOT_FOUND');
    }
    
    // Use first available private key (assumed to match)
    const privateKey = privateKeys[0].key;
    
    if (!privateKey) {
      throw new Error('PRIVATE_KEY_NOT_FOUND_IN_P12');
    }
    
    return {
      certificate: selectedCert,
      privateKey,
      certificateCount: certificates.length,
      subject: formatCertificateSubject(selectedCert),
      issuer: formatCertificateIssuer(selectedCert),
      validFrom: selectedCert.validity ? selectedCert.validity.notBefore : null,
      validTo: selectedCert.validity ? selectedCert.validity.notAfter : null,
      selectionMethod,
      isCA: isCAcertificate(selectedCert),
    };
  } catch (error) {
    console.error('\n❌ Certificate loading failed:');
    const errorCode = error.message;
    if (errorCode === 'PRIVATE_KEY_NOT_FOUND_IN_P12') {
      console.error('  Error: No private key found in P12 file');
    } else if (errorCode === 'CERTIFICATE_NOT_FOUND_IN_P12') {
      console.error('  Error: No certificate found in P12 file');
    } else if (errorCode === 'SIGNING_CERTIFICATE_NOT_FOUND') {
      console.error('  Error: Could not select a signing certificate from chain');
    } else if (error.message.includes('password')) {
      console.error('  Error: Certificate password may be incorrect');
    } else {
      console.error(`  ${error.message}`);
    }
    console.error();
    process.exit(1);
  }
}

// ============================================================================
// Sign XML with XMLDSig
// ============================================================================

function signXml(xmlContent, certificate, privateKey) {
  try {
    const doc = new DOMParser().parseFromString(xmlContent, 'text/xml');
    if (doc.documentElement.tagName.includes('parsererror')) {
      throw new Error('Invalid XML: ' + xmlContent.substring(0, 200));
    }

    const privateKeyPem = forge.pki.privateKeyToPem(privateKey);
    const certDerBase64 = forge.util
      .encode64(forge.asn1.toDer(forge.pki.certificateToAsn1(certificate)).bytes())
      .replace(/\s+/g, '');

    const sig = new SignedXml({
      privateKey: privateKeyPem,
      canonicalizationAlgorithm: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
      signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    });

    sig.addReference({
      xpath: '/*',
      transforms: [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
      ],
      digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
      uri: '',
      isEmptyUri: true,
    });

    sig.getKeyInfoContent = () => `<X509Data><X509Certificate>${certDerBase64}</X509Certificate></X509Data>`;
    sig.computeSignature(xmlContent, {
      location: {
        reference: '/*',
        action: 'append',
      },
    });

    return sig.getSignedXml();
  } catch (error) {
    console.error('\n❌ XML signing failed:');
    console.error(`  ${error.message}\n`);
    process.exit(1);
  }
}

// ============================================================================
// Verify signature locally
// ============================================================================

function verifySignatureLocal(signedXml, certificate) {
  try {
    const doc = new DOMParser().parseFromString(signedXml, 'text/xml');
    const signatureElements = doc.getElementsByTagName('Signature');
    if (signatureElements.length === 0) {
      return false;
    }

    const certPem = forge.pki.certificateToPem(certificate);
    const verifier = new SignedXml({ publicCert: certPem });
    verifier.loadSignature(signatureElements[0]);
    return verifier.checkSignature(signedXml);
  } catch (error) {
    return false;
  }
}

function getFirstByTagNameAnyNs(doc, localName) {
  const byLocal = doc.getElementsByTagName(localName);
  if (byLocal.length > 0) return byLocal[0];
  const byNs = doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', localName);
  return byNs.length > 0 ? byNs[0] : null;
}

function collectSafeSignatureDiagnostics(signedXml) {
  const doc = new DOMParser().parseFromString(signedXml, 'text/xml');
  const parserError = doc.getElementsByTagName('parsererror');
  const root = doc.documentElement;
  const signature = getFirstByTagNameAnyNs(doc, 'Signature');
  const signedInfo = getFirstByTagNameAnyNs(doc, 'SignedInfo');
  const reference = getFirstByTagNameAnyNs(doc, 'Reference');
  const canonicalizationMethod = getFirstByTagNameAnyNs(doc, 'CanonicalizationMethod');
  const signatureMethod = getFirstByTagNameAnyNs(doc, 'SignatureMethod');
  const digestMethod = getFirstByTagNameAnyNs(doc, 'DigestMethod');
  const x509Certificate = getFirstByTagNameAnyNs(doc, 'X509Certificate');

  const transforms = [];
  if (signedInfo) {
    const transformNodes = signedInfo.getElementsByTagName('Transform');
    for (let i = 0; i < transformNodes.length; i++) {
      const alg = transformNodes[i].getAttribute('Algorithm');
      if (alg) transforms.push(alg);
    }
  }

  let signaturePosition = 'not_present';
  if (signature && signature.parentNode === root) {
    const rootChildren = Array.from(root.childNodes).filter(n => n.nodeType === 1);
    const index = rootChildren.indexOf(signature);
    signaturePosition = index === rootChildren.length - 1 ? 'child_of_root_last' : `child_of_root_index_${index}`;
  }

  const x509Value = x509Certificate ? (x509Certificate.textContent || '') : '';
  const x509HasLineBreaks = /\r|\n/.test(x509Value);
  const x509IsCleanBase64 = x509Value.length > 0 && /^[A-Za-z0-9+/=]+$/.test(x509Value) && !/\s/.test(x509Value);

  return {
    xmlWellFormed: parserError.length === 0,
    rootElement: root ? root.tagName : null,
    hasSignature: Boolean(signature),
    signaturePosition,
    referenceUri: reference ? reference.getAttribute('URI') : null,
    rootHasId: root ? root.hasAttribute('Id') || root.hasAttribute('id') || root.hasAttribute('ID') : false,
    rootIdAttributeName: root
      ? (root.hasAttribute('Id') ? 'Id' : root.hasAttribute('id') ? 'id' : root.hasAttribute('ID') ? 'ID' : null)
      : null,
    canonicalizationAlgorithm: canonicalizationMethod ? canonicalizationMethod.getAttribute('Algorithm') : null,
    signatureAlgorithm: signatureMethod ? signatureMethod.getAttribute('Algorithm') : null,
    digestAlgorithm: digestMethod ? digestMethod.getAttribute('Algorithm') : null,
    transforms,
    hasX509Certificate: Boolean(x509Certificate),
    x509HasLineBreaks,
    x509IsCleanBase64,
  };
}

// ============================================================================
// Main execution
// ============================================================================

async function main() {
  console.log('\n📋 DGII Postulation XML Signer\n');
  
  // Parse arguments
  const args = parseArgs();
  validateInputs(args);
  
  // Read XML
  console.log('📖 Reading XML file...');
  const xmlContent = fs.readFileSync(args.xml, 'utf8');
  const xmlDoc = new DOMParser().parseFromString(xmlContent, 'text/xml');
  const rootBefore = xmlDoc.documentElement.tagName;
  
  console.log(`   ✓ Input file: ${args.xml}`);
  console.log(`   ✓ Root element: ${rootBefore}`);
  
  // Load certificate
  console.log('\n🔐 Loading certificate...');
  const certInfo = loadCertificate(args.p12, args.password);
  console.log(`   ✓ Subject: ${certInfo.subject}`);
  console.log(`   ✓ Issuer: ${certInfo.issuer}`);
  console.log(`   ✓ Selection method: ${certInfo.selectionMethod}`);
  console.log(`   ✓ Is CA: ${certInfo.isCA}`);
  console.log(`   ✓ Valid from: ${certInfo.validFrom}`);
  console.log(`   ✓ Valid to: ${certInfo.validTo}`);
  
  // Sign XML
  console.log('\n✍️  Signing XML...');
  const signedXml = signXml(xmlContent, certInfo.certificate, certInfo.privateKey);
  
  // Verify signature locally
  const hasSignature = verifySignatureLocal(signedXml, certInfo.certificate);
  console.log(`   ✓ Signature inserted: ${hasSignature}`);
  
  // Check root element preserved
  const signedDoc = new DOMParser().parseFromString(signedXml, 'text/xml');
  const rootAfter = signedDoc.documentElement.tagName;
  const rootPreserved = rootBefore === rootAfter;
  console.log(`   ✓ Root element preserved: ${rootPreserved} (${rootAfter})`);

  const dsig = collectSafeSignatureDiagnostics(signedXml);
  console.log(`   ✓ Reference URI: ${dsig.referenceUri}`);
  console.log(`   ✓ XML well-formed: ${dsig.xmlWellFormed}`);
  
  // Write to file
  console.log('\n💾 Writing output file...');
  const outputDir = path.dirname(args.out);
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }
  fs.writeFileSync(args.out, signedXml, 'utf8');
  console.log(`   ✓ Output file: ${args.out}`);
  
  // Print diagnostics
  console.log('\n📊 Signing Complete - Diagnostics:');
  console.log(`   Input file:              ${args.xml}`);
  console.log(`   Output file:             ${args.out}`);
  console.log(`   Root before:             ${rootBefore}`);
  console.log(`   Root after:              ${rootAfter}`);
  console.log(`   Has signature:           ${hasSignature}`);
  console.log(`   Signature position:      ${dsig.signaturePosition}`);
  console.log(`   Reference URI:           ${dsig.referenceUri}`);
  console.log(`   Root has Id/id/ID:       ${dsig.rootHasId}`);
  console.log(`   Root Id attribute:       ${dsig.rootIdAttributeName}`);
  console.log(`   Canonicalization alg:    ${dsig.canonicalizationAlgorithm}`);
  console.log(`   Signature alg:           ${dsig.signatureAlgorithm}`);
  console.log(`   Digest alg:              ${dsig.digestAlgorithm}`);
  console.log(`   Transforms:              ${dsig.transforms.join(' | ')}`);
  console.log(`   KeyInfo/X509Certificate: ${dsig.hasX509Certificate}`);
  console.log(`   X509 has line breaks:    ${dsig.x509HasLineBreaks}`);
  console.log(`   X509 clean base64:       ${dsig.x509IsCleanBase64}`);
  console.log(`   XML well-formed:         ${dsig.xmlWellFormed}`);
  console.log(`   Certificate subject:     ${certInfo.subject}`);
  console.log(`   Certificate issuer:      ${certInfo.issuer}`);
  console.log(`   Certificate count in P12:${certInfo.certificateCount}`);
  console.log(`   Selection method:        ${certInfo.selectionMethod}`);
  console.log(`   Valid from:              ${certInfo.validFrom}`);
  console.log(`   Valid to:                ${certInfo.validTo}`);
  console.log(`   Is CA certificate:       ${certInfo.isCA}`);
  console.log(`   Local signature verify:  ${hasSignature}`);
  
  console.log('\n✅ XML signed successfully!\n');
}

// Run
main().catch(error => {
  console.error('\n❌ Unexpected error:', error.message, '\n');
  process.exit(1);
});

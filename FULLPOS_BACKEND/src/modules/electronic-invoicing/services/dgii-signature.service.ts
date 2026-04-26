import { DOMParser } from '@xmldom/xmldom';
import { SignedXml } from 'xml-crypto';
import { certPemToBase64 } from '../utils/certificate.utils';
import { extractEmbeddedCertificate } from '../utils/xml.utils';

export class DgiiSignatureService {
  signXml(xml: string, privateKeyPem: string, certPem: string) {
    const normalizedXml = xml.replace(/^\uFEFF/, '');
    const document = new DOMParser().parseFromString(normalizedXml, 'text/xml');
    const rootName = document.documentElement?.localName || document.documentElement?.nodeName;
    if (!rootName) {
      throw new Error('No se pudo determinar el nodo raíz del XML a firmar');
    }
    if (rootName.toLowerCase().includes('parsererror')) {
      throw new Error('XML inválido: parsererror al intentar firmar');
    }

    const rootXpath = `/*[local-name()='${rootName.replace(/^.*:/, '')}']`;
    const signature = new SignedXml();
    (signature as any).signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    (signature as any).canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    (signature as any).privateKey = privateKeyPem;
    (signature as any).publicCert = certPem;
    (signature as any).keyInfoProvider = {
      getKeyInfo: () =>
        `<X509Data><X509Certificate>${certPemToBase64(certPem)}</X509Certificate></X509Data>`,
    };

    signature.addReference({
      xpath: rootXpath,
      transforms: [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#',
      ],
      digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    });

    signature.computeSignature(normalizedXml, {
      location: {
        reference: rootXpath,
        action: 'append',
      },
    });

    return signature.getSignedXml();
  }

  verifySignedXml(xml: string) {
    const certPem = extractEmbeddedCertificate(xml);
    if (!certPem) {
      return { valid: false, certificatePem: null, errors: ['No se encontró X509Certificate en el XML firmado'] };
    }

    const document = new DOMParser().parseFromString(xml, 'text/xml');
    const signatureNode =
      document.getElementsByTagName('Signature')[0] ?? document.getElementsByTagName('ds:Signature')[0];

    if (!signatureNode) {
      return { valid: false, certificatePem: certPem, errors: ['No se encontró nodo Signature en el XML firmado'] };
    }

    const verifier = new SignedXml();
    (verifier as any).publicCert = certPem;
    verifier.loadSignature(signatureNode as unknown as Node);
    const valid = verifier.checkSignature(xml);

    return {
      valid,
      certificatePem: certPem,
      errors: [...((verifier as any).validationErrors ?? [])],
    };
  }
}
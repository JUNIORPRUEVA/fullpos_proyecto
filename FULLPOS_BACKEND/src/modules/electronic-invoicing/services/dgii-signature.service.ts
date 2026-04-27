import { DOMParser } from '@xmldom/xmldom';
import { SignedXml } from 'xml-crypto';
import { certPemToBase64 } from '../utils/certificate.utils';
import { extractEmbeddedCertificate } from '../utils/xml.utils';

export type SignedXmlDiagnostics = {
  signedXmlRoot: string | null;
  signedXmlHasSignature: boolean;
  signedXmlHasIdAttributeOnRoot: boolean;
  signatureReferenceUri: string | null;
  canonicalizationAlgorithm: string | null;
  signatureAlgorithm: string | null;
  digestAlgorithm: string | null;
};

const SIGNATURE_ALGORITHM = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
const CANONICALIZATION_ALGORITHM = 'http://www.w3.org/2001/10/xml-exc-c14n#';
const DIGEST_ALGORITHM = 'http://www.w3.org/2001/04/xmlenc#sha256';
const ENVELOPED_SIGNATURE_TRANSFORM = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

function findFirstElementByLocalName(node: any, localName: string): Element | null {
  const current = node as Element;
  if (current.nodeType === 1 && (current.localName === localName || current.nodeName.split(':').pop() === localName)) {
    return current;
  }

  for (let i = 0; i < node.childNodes.length; i += 1) {
    const found = findFirstElementByLocalName(node.childNodes[i], localName);
    if (found) return found;
  }

  return null;
}

export class DgiiSignatureService {
  signXml(xml: string, privateKeyPem: string, certPem: string) {
    return this.signXmlInternal(xml, privateKeyPem, certPem, { emptyReferenceUri: false });
  }

  signSeedXml(xml: string, privateKeyPem: string, certPem: string) {
    return this.signXmlInternal(xml, privateKeyPem, certPem, { emptyReferenceUri: true });
  }

  inspectSignedXml(xml: string): SignedXmlDiagnostics {
    const document = new DOMParser().parseFromString(xml.replace(/^\uFEFF/, ''), 'text/xml');
    const root = document.documentElement;
    const signature = findFirstElementByLocalName(document, 'Signature');
    const reference = signature ? findFirstElementByLocalName(signature, 'Reference') : null;
    const canonicalizationMethod = signature ? findFirstElementByLocalName(signature, 'CanonicalizationMethod') : null;
    const signatureMethod = signature ? findFirstElementByLocalName(signature, 'SignatureMethod') : null;
    const digestMethod = signature ? findFirstElementByLocalName(signature, 'DigestMethod') : null;

    return {
      signedXmlRoot: root?.localName || root?.nodeName || null,
      signedXmlHasSignature: !!signature,
      signedXmlHasIdAttributeOnRoot: !!root?.hasAttribute('Id') || !!root?.hasAttribute('ID') || !!root?.hasAttribute('id'),
      signatureReferenceUri: reference?.getAttribute('URI') ?? null,
      canonicalizationAlgorithm: canonicalizationMethod?.getAttribute('Algorithm') ?? null,
      signatureAlgorithm: signatureMethod?.getAttribute('Algorithm') ?? null,
      digestAlgorithm: digestMethod?.getAttribute('Algorithm') ?? null,
    };
  }

  private signXmlInternal(
    xml: string,
    privateKeyPem: string,
    certPem: string,
    options: { emptyReferenceUri: boolean },
  ) {
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
  (signature as any).signatureAlgorithm = SIGNATURE_ALGORITHM;
  (signature as any).canonicalizationAlgorithm = CANONICALIZATION_ALGORITHM;
    (signature as any).privateKey = privateKeyPem;
    (signature as any).publicCert = certPem;
    (signature as any).keyInfoProvider = {
      getKeyInfo: () =>
        `<X509Data><X509Certificate>${certPemToBase64(certPem)}</X509Certificate></X509Data>`,
    };

    signature.addReference({
      xpath: rootXpath,
      transforms: [
        ENVELOPED_SIGNATURE_TRANSFORM,
        CANONICALIZATION_ALGORITHM,
      ],
      digestAlgorithm: DIGEST_ALGORITHM,
      isEmptyUri: options.emptyReferenceUri,
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
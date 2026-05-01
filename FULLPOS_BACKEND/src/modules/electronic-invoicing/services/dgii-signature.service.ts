import { DOMParser, XMLSerializer } from '@xmldom/xmldom';
import { SignedXml } from 'xml-crypto';
import { certPemToBase64 } from '../utils/certificate.utils';
import { extractEmbeddedCertificate } from '../utils/xml.utils';

export type SignedXmlDiagnostics = {
  signedXmlRoot: string | null;
  signedXmlHasSignature: boolean;
  signedXmlHasSignedInfo: boolean;
  signedXmlHasX509Certificate: boolean;
  signedXmlHasIdAttributeOnRoot: boolean;
  signatureReferenceUri: string | null;
  canonicalizationAlgorithm: string | null;
  signatureAlgorithm: string | null;
  digestAlgorithm: string | null;
  signedXmlRootId: string | null;
};

const SIGNATURE_ALGORITHM = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
const CANONICALIZATION_ALGORITHM = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
const DIGEST_ALGORITHM = 'http://www.w3.org/2001/04/xmlenc#sha256';
const ENVELOPED_SIGNATURE_TRANSFORM = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

export type SeedSignatureMode = {
  label: string;
  signatureAlgorithm: string;
  canonicalizationAlgorithm: string;
  digestAlgorithm: string;
  keyInfoMode: 'leaf-only' | 'chain';
};

export const SEED_SIGNATURE_MODES: SeedSignatureMode[] = [
  {
    label: 'official-inc-c14n/rsa-sha256/sha256/leaf',
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    canonicalizationAlgorithm: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    keyInfoMode: 'leaf-only',
  },
  {
    label: 'exc-c14n/rsa-sha256/sha256/leaf',
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    keyInfoMode: 'leaf-only',
  },
  {
    label: 'exc-c14n/rsa-sha1/sha1/leaf',
    signatureAlgorithm: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
    digestAlgorithm: 'http://www.w3.org/2000/09/xmldsig#sha1',
    keyInfoMode: 'leaf-only',
  },
  {
    label: 'inc-c14n/rsa-sha1/sha1/leaf',
    signatureAlgorithm: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    canonicalizationAlgorithm: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
    digestAlgorithm: 'http://www.w3.org/2000/09/xmldsig#sha1',
    keyInfoMode: 'leaf-only',
  },
  {
    label: 'official-inc-c14n/rsa-sha256/sha256/chain',
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    canonicalizationAlgorithm: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    keyInfoMode: 'chain',
  },
];

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
    return this.signXmlInternal(xml, privateKeyPem, certPem, { emptyReferenceUri: true });
  }

  signSeedXml(xml: string, privateKeyPem: string, certPem: string) {
    return this.signDgiiSeedXmlInternal(xml, privateKeyPem, certPem, {
      signatureAlgorithm: SIGNATURE_ALGORITHM,
      canonicalizationAlgorithm: CANONICALIZATION_ALGORITHM,
      digestAlgorithm: DIGEST_ALGORITHM,
      keyInfoCertificates: [certPem],
    });
  }

  signSeedXmlWithMode(
    xml: string,
    privateKeyPem: string,
    certPem: string,
    chainPems: string[],
    mode: SeedSignatureMode,
  ) {
    return this.signDgiiSeedXmlInternal(xml, privateKeyPem, certPem, {
      signatureAlgorithm: mode.signatureAlgorithm,
      canonicalizationAlgorithm: mode.canonicalizationAlgorithm,
      digestAlgorithm: mode.digestAlgorithm,
      keyInfoCertificates: mode.keyInfoMode === 'chain' && chainPems.length > 0 ? [certPem, ...chainPems] : [certPem],
    });
  }

  inspectSignedXml(xml: string): SignedXmlDiagnostics {
    const document = new DOMParser().parseFromString(xml.replace(/^\uFEFF/, ''), 'text/xml');
    const root = document.documentElement;
    const signature = findFirstElementByLocalName(document, 'Signature');
    const signedInfo = signature ? findFirstElementByLocalName(signature, 'SignedInfo') : null;
    const x509Certificate = signature ? findFirstElementByLocalName(signature, 'X509Certificate') : null;
    const reference = signature ? findFirstElementByLocalName(signature, 'Reference') : null;
    const canonicalizationMethod = signature ? findFirstElementByLocalName(signature, 'CanonicalizationMethod') : null;
    const signatureMethod = signature ? findFirstElementByLocalName(signature, 'SignatureMethod') : null;
    const digestMethod = signature ? findFirstElementByLocalName(signature, 'DigestMethod') : null;
    const rootId = root?.getAttribute('Id') ?? root?.getAttribute('ID') ?? root?.getAttribute('id') ?? null;

    return {
      signedXmlRoot: root?.localName || root?.nodeName || null,
      signedXmlHasSignature: !!signature,
      signedXmlHasSignedInfo: !!signedInfo,
      signedXmlHasX509Certificate: !!x509Certificate,
      signedXmlHasIdAttributeOnRoot: !!root?.hasAttribute('Id') || !!root?.hasAttribute('ID') || !!root?.hasAttribute('id'),
      signatureReferenceUri: reference?.getAttribute('URI') ?? null,
      canonicalizationAlgorithm: canonicalizationMethod?.getAttribute('Algorithm') ?? null,
      signatureAlgorithm: signatureMethod?.getAttribute('Algorithm') ?? null,
      digestAlgorithm: digestMethod?.getAttribute('Algorithm') ?? null,
      signedXmlRootId: rootId,
    };
  }

  private prepareXmlForSigning(xml: string, options: { rootIdValue?: string }) {
    const normalizedXml = xml.replace(/^\uFEFF/, '');
    const document = new DOMParser().parseFromString(normalizedXml, 'text/xml');
    const root = document.documentElement;
    const rootName = root?.localName || root?.nodeName;
    if (!rootName) {
      throw new Error('No se pudo determinar el nodo raíz del XML a firmar');
    }
    if (rootName.toLowerCase().includes('parsererror')) {
      throw new Error('XML inválido: parsererror al intentar firmar');
    }

    if (options.rootIdValue && !root.hasAttribute('Id') && !root.hasAttribute('ID') && !root.hasAttribute('id')) {
      root.setAttribute('Id', options.rootIdValue);
    }

    return {
      xml: new XMLSerializer().serializeToString(document).replace(/^\uFEFF/, ''),
      rootName,
    };
  }

  private prepareDgiiSeedXmlForSigning(xml: string) {
    const normalizedXml = xml.replace(/^\uFEFF/, '');
    const document = new DOMParser().parseFromString(normalizedXml, 'text/xml');
    const root = document.documentElement;
    const rootName = root?.localName || root?.nodeName;
    if (!root || rootName !== 'SemillaModel') {
      throw new Error('La semilla DGII a firmar debe conservar raíz SemillaModel');
    }
    if (rootName.toLowerCase().includes('parsererror')) {
      throw new Error('XML inválido: parsererror al intentar firmar semilla DGII');
    }

    for (const attribute of ['Id', 'ID', 'id']) {
      if (root.hasAttribute(attribute)) {
        root.removeAttribute(attribute);
      }
    }

    return {
      xml: new XMLSerializer().serializeToString(document).replace(/^\uFEFF/, ''),
      rootName,
    };
  }

  private signDgiiSeedXmlInternal(
    xml: string,
    privateKeyPem: string,
    certPem: string,
    options: {
      signatureAlgorithm: string;
      canonicalizationAlgorithm: string;
      digestAlgorithm: string;
      keyInfoCertificates: string[];
    },
  ) {
    const prepared = this.prepareDgiiSeedXmlForSigning(xml);
    const rootXpath = "/*[local-name()='SemillaModel']";
    const signature = new SignedXml({
      privateKey: privateKeyPem,
      publicCert: certPem,
      signatureAlgorithm: options.signatureAlgorithm,
      canonicalizationAlgorithm: options.canonicalizationAlgorithm,
      getKeyInfoContent: () =>
        `<X509Data>${options.keyInfoCertificates
          .map((certificate) => `<X509Certificate>${certPemToBase64(certificate)}</X509Certificate>`)
          .join('')}</X509Data>`,
    });

    signature.addReference({
      xpath: rootXpath,
      transforms: [ENVELOPED_SIGNATURE_TRANSFORM, options.canonicalizationAlgorithm],
      digestAlgorithm: options.digestAlgorithm,
      isEmptyUri: true,
    });

    signature.computeSignature(prepared.xml, {
      location: {
        reference: rootXpath,
        action: 'append',
      },
    });

    return signature.getSignedXml();
  }

  private signXmlInternal(
    xml: string,
    privateKeyPem: string,
    certPem: string,
    options: {
      emptyReferenceUri: boolean;
      signatureAlgorithm?: string;
      canonicalizationAlgorithm?: string;
      digestAlgorithm?: string;
      keyInfoCertificates?: string[];
      rootIdValue?: string;
    },
  ) {
    const prepared = this.prepareXmlForSigning(xml, { rootIdValue: options.rootIdValue });
    const normalizedXml = prepared.xml;
    const rootName = prepared.rootName;

    const rootXpath = `/*[local-name()='${rootName.replace(/^.*:/, '')}']`;
    const signatureAlgorithm = options.signatureAlgorithm ?? SIGNATURE_ALGORITHM;
    const canonicalizationAlgorithm = options.canonicalizationAlgorithm ?? CANONICALIZATION_ALGORITHM;
    const digestAlgorithm = options.digestAlgorithm ?? DIGEST_ALGORITHM;
    const keyInfoCertificates = options.keyInfoCertificates ?? [certPem];
    const signature = new SignedXml({
      privateKey: privateKeyPem,
      publicCert: certPem,
      signatureAlgorithm,
      canonicalizationAlgorithm,
      getKeyInfoContent: () =>
        `<X509Data>${keyInfoCertificates
          .map((certificate) => `<X509Certificate>${certPemToBase64(certificate)}</X509Certificate>`)
          .join('')}</X509Data>`,
    });

    signature.addReference({
      xpath: rootXpath,
      transforms: [
        ENVELOPED_SIGNATURE_TRANSFORM,
        canonicalizationAlgorithm,
      ],
      digestAlgorithm,
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

    const transformNodes = Array.from(signatureNode.getElementsByTagName('Transform')) as any[];
    const hasCanonicalizationTransform = transformNodes.some((node) =>
      (node.getAttribute('Algorithm') ?? '').includes('xml-c14n') ||
      (node.getAttribute('Algorithm') ?? '').includes('REC-xml-c14n'),
    );
    const verifier = new SignedXml({
      implicitTransforms: hasCanonicalizationTransform ? [] : [CANONICALIZATION_ALGORITHM],
    });
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

import { create } from 'xmlbuilder2';
import { XMLParser } from 'fast-xml-parser';

const parser = new XMLParser({
  attributeNamePrefix: '',
  ignoreAttributes: false,
  ignoreDeclaration: true,
  parseTagValue: false,
  removeNSPrefix: true,
  trimValues: true,
});

function appendValue(node: ReturnType<typeof create>, value: unknown) {
  if (value == null) {
    return;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      const child = node.ele('Item');
      appendValue(child as ReturnType<typeof create>, item);
    }
    return;
  }

  if (typeof value === 'object') {
    for (const [key, nestedValue] of Object.entries(value as Record<string, unknown>)) {
      const child = node.ele(key);
      appendValue(child as ReturnType<typeof create>, nestedValue);
    }
    return;
  }

  node.txt(String(value));
}

export function buildXmlDocument(rootName: string, value: Record<string, unknown>) {
  const root = create({ version: '1.0', encoding: 'UTF-8' }).ele(rootName);
  appendValue(root as ReturnType<typeof create>, value);
  return root.end({ prettyPrint: false });
}

export function parseXml(xml: string) {
  return parser.parse(xml);
}

export function xmlEscape(value: string) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

export function firstString(...values: Array<unknown>) {
  for (const value of values) {
    if (typeof value === 'string' && value.trim().length > 0) {
      return value.trim();
    }
  }
  return undefined;
}

export function deepFindFirstString(payload: unknown, keys: string[]): string | undefined {
  if (payload == null) return undefined;

  if (typeof payload === 'object') {
    const asRecord = payload as Record<string, unknown>;
    for (const [key, value] of Object.entries(asRecord)) {
      if (keys.includes(key) && typeof value === 'string' && value.trim().length > 0) {
        return value.trim();
      }

      const nested = deepFindFirstString(value, keys);
      if (nested) return nested;
    }
  }

  if (Array.isArray(payload)) {
    for (const item of payload) {
      const nested = deepFindFirstString(item, keys);
      if (nested) return nested;
    }
  }

  return undefined;
}

export function deepFindFirstNumber(payload: unknown, keys: string[]): number | undefined {
  const value = deepFindFirstString(payload, keys);
  if (!value) return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

export function extractEmbeddedCertificate(xml: string) {
  const match = xml.match(/<X509Certificate>([\s\S]*?)<\/X509Certificate>/i);
  if (!match?.[1]) return null;
  const base64 = match[1].replace(/\s+/g, '');
  const lines = base64.match(/.{1,64}/g)?.join('\n') ?? base64;
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----`;
}
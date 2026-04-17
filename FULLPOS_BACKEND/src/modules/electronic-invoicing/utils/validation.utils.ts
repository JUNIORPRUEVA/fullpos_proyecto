import { SupportedDocumentTypeCode } from '../types/electronic-invoice.types';

const SUPPORTED_DOCUMENT_TYPES = new Set<SupportedDocumentTypeCode>([
  '31',
  '32',
  '33',
  '34',
  '41',
  '43',
  '44',
  '45',
]);

export function normalizeRnc(value?: string | null) {
  return (value ?? '').replace(/[^0-9]/g, '');
}

export function isRncLike(value?: string | null) {
  const normalized = normalizeRnc(value);
  return normalized.length === 9 || normalized.length === 11;
}

export function assertValidRnc(value: string | null | undefined, label: string) {
  if (!isRncLike(value)) {
    throw {
      status: 400,
      message: `${label} inválido`,
      errorCode: 'INVALID_RNC',
      details: { label },
    };
  }
}

export function isSupportedDocumentTypeCode(code: string): code is SupportedDocumentTypeCode {
  return SUPPORTED_DOCUMENT_TYPES.has(code as SupportedDocumentTypeCode);
}

export function assertSupportedDocumentTypeCode(code: string): SupportedDocumentTypeCode {
  if (!isSupportedDocumentTypeCode(code)) {
    throw {
      status: 400,
      message: `Tipo de documento electrónico no soportado: ${code}`,
      errorCode: 'UNSUPPORTED_DOCUMENT_TYPE',
    };
  }
  return code;
}

export function buildEcf(prefix: string, sequenceNumber: number) {
  return `${prefix}${sequenceNumber.toString().padStart(10, '0')}`;
}

export function assertValidEcf(ecf: string) {
  if (!/^E\d{12}$/.test(ecf)) {
    throw {
      status: 400,
      message: 'e-CF inválido',
      errorCode: 'INVALID_ECF',
      details: { ecf },
    };
  }
}

export function toPositiveMoney(value: number) {
  return Math.round(Math.abs(value) * 100) / 100;
}

export function formatMoney(value: number) {
  return toPositiveMoney(value).toFixed(2);
}
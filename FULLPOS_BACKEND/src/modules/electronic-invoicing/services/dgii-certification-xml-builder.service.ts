import fs from 'fs';
import path from 'path';

type RawRow = Record<string, unknown>;

export type CertificationIssuerFallback = {
  rnc?: string | null;
  legalName?: string | null;
  businessName?: string | null;
  tradeName?: string | null;
  address?: string | null;
  municipality?: string | null;
  province?: string | null;
  email?: string | null;
  website?: string | null;
};

export type CertificationXmlBuildResult = {
  xml: string;
  warnings: string[];
  errors: string[];
  missingFields: string[];
  extractedFields: Record<string, string>;
  fallbackFieldsUsed: Record<string, string>;
  rawRowKeys: string[];
  humanReadableMessage: string | null;
  sourceFieldsUsed: Record<string, string>;
};

type FieldSpec = {
  tag: string;
  aliases: string[];
  transform?: (value: string) => string | null;
};

type DgiiLocationEntry = {
  code: string;
  label: string;
  normalizedLabel: string;
};

let locationCatalogCache: {
  entries: DgiiLocationEntry[];
  byCode: Set<string>;
  byLabel: Map<string, DgiiLocationEntry[]>;
} | null = null;

function normalizeHeader(value: unknown) {
  return String(value ?? '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');
}

function normalizeLocationLabel(value: unknown) {
  return String(value ?? '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toUpperCase()
    .replace(/\([^)]*\)/g, ' ')
    .replace(/\b(PROVINCIA|MUNICIPIO|DISTRITO|MUNICIPAL|DM|D M)\b/g, ' ')
    .replace(/[^A-Z0-9]+/g, ' ')
    .trim()
    .replace(/\s+/g, ' ');
}

function compactLocationLabel(value: unknown) {
  return normalizeLocationLabel(value).replace(/\s+/g, '');
}

function loadDgiiLocationCatalog() {
  if (locationCatalogCache) return locationCatalogCache;
  const byCode = new Set<string>();
  const byLabel = new Map<string, DgiiLocationEntry[]>();
  const entries: DgiiLocationEntry[] = [];
  const candidateFiles = [
    path.resolve(process.cwd(), 'resources', 'dgii', 'xsd', 'e-CF 32 v.1.0.xsd'),
    path.resolve(process.cwd(), 'resources', 'dgii', 'xsd', 'e-CF 31 v.1.0.xsd'),
  ];
  const xsdPath = candidateFiles.find((filePath) => fs.existsSync(filePath));
  if (!xsdPath) {
    locationCatalogCache = { entries, byCode, byLabel };
    return locationCatalogCache;
  }

  const xsd = fs.readFileSync(xsdPath, 'utf8');
  const regex = /<xs:enumeration\s+value\s*=\s*["']\s*(\d{6})\s*["'][^>]*\/?>\s*<!--([\s\S]*?)-->/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(xsd)) !== null) {
    const code = match[1];
    const rawLabel = match[2].replace(/\s+/g, ' ').trim();
    const normalizedLabel = normalizeLocationLabel(rawLabel);
    const compactLabel = compactLocationLabel(rawLabel);
    if (!normalizedLabel) continue;
    const entry = { code, label: rawLabel, normalizedLabel };
    entries.push(entry);
    byCode.add(code);
    for (const key of new Set([normalizedLabel, compactLabel])) {
      const list = byLabel.get(key) ?? [];
      list.push(entry);
      byLabel.set(key, list);
    }
  }

  locationCatalogCache = { entries, byCode, byLabel };
  return locationCatalogCache;
}

function preferLocationEntry(entries: DgiiLocationEntry[], tag: string) {
  if (entries.length === 0) return null;
  const upperTag = tag.toUpperCase();
  if (upperTag.includes('PROVINCIA')) {
    return entries.find((entry) => entry.code.endsWith('0000')) ?? entries[0];
  }
  if (upperTag.includes('MUNICIPIO')) {
    return entries.find((entry) => entry.label.toUpperCase().includes('MUNICIPIO')) ??
      entries.find((entry) => entry.code.endsWith('00') && !entry.code.endsWith('0000')) ??
      entries[0];
  }
  return entries[0];
}

function normalizeProvinciaMunicipioCode(value: string | null, tag: string) {
  const clean = cleanDgiiValue(value);
  if (!clean) return null;
  const catalog = loadDgiiLocationCatalog();
  const digits = clean.replace(/\D/g, '');
  if (/^\d{6}$/.test(digits) && (catalog.byCode.size === 0 || catalog.byCode.has(digits))) {
    return digits;
  }
  const normalized = normalizeLocationLabel(clean);
  const compact = compactLocationLabel(clean);
  const matches = [
    ...(catalog.byLabel.get(normalized) ?? []),
    ...(catalog.byLabel.get(compact) ?? []),
  ];
  const exact = preferLocationEntry(matches, tag);
  if (exact) return exact.code;
  const containsMatches = catalog.entries.filter((entry) =>
    entry.normalizedLabel === normalized ||
    entry.normalizedLabel.endsWith(` ${normalized}`) ||
    normalized.endsWith(` ${entry.normalizedLabel}`),
  );
  return preferLocationEntry(containsMatches, tag)?.code ?? null;
}

function normalizeValue(value: unknown) {
  return cleanDgiiValue(value);
}

function cleanDgiiValue(value: unknown) {
  if (value == null) return null;
  if (value instanceof Date) return value.toISOString();
  const text = String(value).trim();
  if (!text) return null;
  const normalized = text.toLowerCase();
  if (['#e', '#n/a', 'n/a', 'null', 'undefined'].includes(normalized)) return null;
  return text;
}

function xmlEscape(value: unknown) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function caseRow(input: { rawRowJson: unknown }) {
  return input.rawRowJson && typeof input.rawRowJson === 'object' && !Array.isArray(input.rawRowJson)
    ? input.rawRowJson as RawRow
    : {};
}

class RowReader {
  private readonly normalizedEntries: Array<{ normalizedKey: string; originalKey: string; value: unknown }>;
  readonly sourceFieldsUsed: Record<string, string> = {};
  readonly extractedFields: Record<string, string> = {};
  readonly rawRowKeys: string[];

  constructor(row: RawRow) {
    this.rawRowKeys = Object.keys(row);
    this.normalizedEntries = Object.entries(row).map(([originalKey, value]) => ({
      normalizedKey: normalizeHeader(originalKey),
      originalKey,
      value,
    }));
  }

  get(canonicalName: string, aliases: string[]) {
    const normalizedAliases = aliases.map(normalizeHeader);
    const found = this.normalizedEntries.find((entry) => normalizedAliases.includes(entry.normalizedKey));
    if (!found) return null;
    const value = normalizeValue(found.value);
    if (value != null) {
      this.sourceFieldsUsed[canonicalName] = found.originalKey;
      this.extractedFields[canonicalName] = value;
    }
    return value;
  }
}

function normalizeRnc(value: string | null) {
  return value?.replace(/\D/g, '') || null;
}

function parseMoney(value: string | null) {
  if (value == null || value === '') return null;
  const parsed = Number(String(value).replace(/RD\$|\$|,/gi, '').trim());
  return Number.isFinite(parsed) ? Math.round(parsed * 100) / 100 : null;
}

function moneyText(value: string | null) {
  const parsed = parseMoney(value);
  return parsed == null ? null : parsed.toFixed(2);
}

function integerText(value: string | null) {
  const clean = cleanDgiiValue(value);
  if (!clean) return null;
  const parsed = Number(clean.replace(/,/g, ''));
  return Number.isInteger(parsed) ? String(parsed) : null;
}

function parsePositiveMoney(value: string | null) {
  const parsed = parseMoney(value);
  return parsed == null || parsed < 0 ? null : parsed;
}

function parseDate(value: string | null) {
  if (!value) return null;
  const text = value.trim();
  const dominicanMatch = text.match(/^(\d{1,2})[/-](\d{1,2})[/-](\d{4})$/);
  if (dominicanMatch) {
    return `${pad2(Number(dominicanMatch[1]))}-${pad2(Number(dominicanMatch[2]))}-${dominicanMatch[3]}`;
  }
  const normalized = text.replace(/^(\d{4})-(\d{2})-(\d{2}).*$/, '$1-$2-$3');
  const parsed = new Date(normalized);
  if (Number.isNaN(parsed.getTime())) return null;
  return `${pad2(parsed.getUTCDate())}-${pad2(parsed.getUTCMonth() + 1)}-${parsed.getUTCFullYear()}`;
}

function pad2(value: number) {
  return String(value).padStart(2, '0');
}

function dominicanTimestamp(value = new Date()) {
  const dominicanTime = new Date(value.getTime() - 4 * 60 * 60 * 1000);
  return `${pad2(dominicanTime.getUTCDate())}-${pad2(dominicanTime.getUTCMonth() + 1)}-${dominicanTime.getUTCFullYear()} ${pad2(dominicanTime.getUTCHours())}:${pad2(dominicanTime.getUTCMinutes())}:${pad2(dominicanTime.getUTCSeconds())}`;
}

function addTag(lines: string[], indent: string, tag: string, value: string | null | undefined) {
  if (value == null || value === '') return;
  lines.push(`${indent}<${tag}>${xmlEscape(value)}</${tag}>`);
}

function section(name: string, inner: string[], indent = '  ') {
  if (inner.length === 0) return [];
  return [`${indent}<${name}>`, ...inner, `${indent}</${name}>`];
}

function readField(reader: RowReader, canonicalName: string, aliases: string[], transform?: (value: string) => string | null) {
  const raw = reader.get(canonicalName, aliases);
  if (raw == null) return null;
  return transform ? transform(raw) : raw;
}

function readAny(reader: RowReader, canonicalName: string, aliases: string[]) {
  return readField(reader, canonicalName, aliases);
}

function readDate(reader: RowReader, canonicalName: string, aliases: string[]) {
  return readField(reader, canonicalName, aliases, parseDate);
}

function readMoney(reader: RowReader, canonicalName: string, aliases: string[]) {
  return readField(reader, canonicalName, aliases, moneyText);
}

function sourceFallback(reader: RowReader, canonicalName: string, value: string | null, source: string, fallbackFieldsUsed: Record<string, string>) {
  if (!value) return null;
  reader.sourceFieldsUsed[canonicalName] = source;
  reader.extractedFields[canonicalName] = value;
  fallbackFieldsUsed[canonicalName] = source;
  return value;
}

function pushValue(lines: string[], indent: string, tag: string, value: string | null | undefined, values: Record<string, string>) {
  if (value == null || value === '') return;
  values[tag] = value;
  addTag(lines, indent, tag, value);
}

function buildFields(
  reader: RowReader,
  specs: FieldSpec[],
  indent: string,
  fallbackValues?: Record<string, { value: string | null; source: string }>,
) {
  const lines: string[] = [];
  const values: Record<string, string> = {};
  const fallbackFieldsUsed: Record<string, string> = {};
  for (const spec of specs) {
    let value = readField(reader, spec.tag, spec.aliases, spec.transform);
    const fallback = fallbackValues?.[spec.tag];
    if (value == null && fallback?.value) {
      value = spec.transform ? spec.transform(fallback.value) : fallback.value;
      if (value) {
        reader.sourceFieldsUsed[spec.tag] = fallback.source;
        reader.extractedFields[spec.tag] = value;
        fallbackFieldsUsed[spec.tag] = fallback.source;
      }
    }
    if (value != null) values[spec.tag] = value;
    addTag(lines, indent, spec.tag, value);
  }
  return { lines, values, fallbackFieldsUsed };
}

function buildMissingMessage(missing: string[]) {
  return `Faltan campos obligatorios: ${missing.join(', ')}`;
}

function todayDominicanDate(value = new Date()) {
  const dominicanTime = new Date(value.getTime() - 4 * 60 * 60 * 1000);
  return `${pad2(dominicanTime.getUTCDate())}-${pad2(dominicanTime.getUTCMonth() + 1)}-${dominicanTime.getUTCFullYear()}`;
}

const ID_DOC_FIELDS: FieldSpec[] = [
  { tag: 'TipoeCF', aliases: ['tipoEcf', 'TipoCF', 'tipo e-CF', 'tipo comprobante', 'tipo'] },
  { tag: 'eNCF', aliases: ['encf', 'eNCF', 'E-NCF', 'NCF', 'comprobante', 'numeroComprobante'] },
  { tag: 'FechaVencimientoSecuencia', aliases: ['fechaVencimientoSecuencia', 'fecha vencimiento secuencia', 'vencimiento secuencia'], transform: parseDate },
  { tag: 'IndicadorMontoGravado', aliases: ['indicadorMontoGravado', 'indicador monto gravado'] },
  { tag: 'TipoIngresos', aliases: ['tipoIngresos', 'tipo ingresos'] },
  { tag: 'TipoPago', aliases: ['tipoPago', 'tipo pago'] },
  { tag: 'FechaLimitePago', aliases: ['fechaLimitePago', 'fecha limite pago'], transform: parseDate },
  { tag: 'TerminoPago', aliases: ['terminoPago', 'termino pago'] },
];

const EMISOR_FIELDS: FieldSpec[] = [
  { tag: 'RNCEmisor', aliases: ['rncEmisor', 'RNC Emisor', 'RNCEmisor'], transform: normalizeRnc },
  { tag: 'RazonSocialEmisor', aliases: ['razonSocialEmisor', 'Razon Social Emisor', 'Nombre Emisor', 'Emisor'] },
  { tag: 'NombreComercial', aliases: ['nombreComercial', 'nombre comercial'] },
  { tag: 'Sucursal', aliases: ['sucursal'] },
  { tag: 'DireccionEmisor', aliases: ['direccionEmisor', 'direccion emisor', 'direccion'] },
  { tag: 'Municipio', aliases: ['municipio', 'municipioEmisor'], transform: (value) => normalizeProvinciaMunicipioCode(value, 'Municipio') },
  { tag: 'Provincia', aliases: ['provincia', 'provinciaEmisor'], transform: (value) => normalizeProvinciaMunicipioCode(value, 'Provincia') },
  { tag: 'CorreoEmisor', aliases: ['correoEmisor', 'emailEmisor', 'correo emisor'] },
  { tag: 'WebSite', aliases: ['website', 'web site', 'sitio web'] },
  { tag: 'ActividadEconomica', aliases: ['actividadEconomica', 'actividad economica'] },
  { tag: 'FechaEmision', aliases: ['fechaEmision', 'Fecha Emision', 'FechaEmision', 'Fecha'], transform: parseDate },
];

const COMPRADOR_FIELDS: FieldSpec[] = [
  { tag: 'RNCComprador', aliases: ['rncComprador', 'RNC Comprador', 'RNCComprador'], transform: normalizeRnc },
  { tag: 'IdentificadorExtranjero', aliases: ['identificadorExtranjero', 'id extranjero', 'identificacion extranjero'] },
  { tag: 'RazonSocialComprador', aliases: ['razonSocialComprador', 'Razon Social Comprador', 'Nombre Comprador', 'Comprador'] },
  { tag: 'ContactoComprador', aliases: ['contactoComprador', 'contacto comprador'] },
  { tag: 'CorreoComprador', aliases: ['correoComprador', 'emailComprador', 'correo comprador'] },
  { tag: 'DireccionComprador', aliases: ['direccionComprador', 'direccion comprador'] },
  { tag: 'MunicipioComprador', aliases: ['municipioComprador', 'municipio comprador'], transform: (value) => normalizeProvinciaMunicipioCode(value, 'MunicipioComprador') },
  { tag: 'ProvinciaComprador', aliases: ['provinciaComprador', 'provincia comprador'], transform: (value) => normalizeProvinciaMunicipioCode(value, 'ProvinciaComprador') },
];

const TOTALES_FIELDS: FieldSpec[] = [
  { tag: 'MontoGravadoTotal', aliases: ['montoGravadoTotal', 'monto gravado total'], transform: moneyText },
  { tag: 'MontoGravadoI1', aliases: ['montoGravadoI1', 'monto gravado i1'], transform: moneyText },
  { tag: 'MontoGravadoI2', aliases: ['montoGravadoI2', 'monto gravado i2'], transform: moneyText },
  { tag: 'MontoGravadoI3', aliases: ['montoGravadoI3', 'monto gravado i3'], transform: moneyText },
  { tag: 'MontoExento', aliases: ['montoExento', 'monto exento'], transform: moneyText },
  { tag: 'ITBIS1', aliases: ['itbis1', 'ITBIS1'] },
  { tag: 'ITBIS2', aliases: ['itbis2', 'ITBIS2'] },
  { tag: 'ITBIS3', aliases: ['itbis3', 'ITBIS3'] },
  { tag: 'TotalITBIS', aliases: ['totalITBIS', 'Total ITBIS', 'itbisTotal'], transform: moneyText },
  { tag: 'TotalITBIS1', aliases: ['totalITBIS1', 'total itbis 1'], transform: moneyText },
  { tag: 'TotalITBIS2', aliases: ['totalITBIS2', 'total itbis 2'], transform: moneyText },
  { tag: 'TotalITBIS3', aliases: ['totalITBIS3', 'total itbis 3'], transform: moneyText },
  { tag: 'MontoTotal', aliases: ['montoTotal', 'Monto Total', 'Total', 'TotalFactura'], transform: moneyText },
  { tag: 'MontoPeriodo', aliases: ['montoPeriodo', 'monto periodo'], transform: moneyText },
  { tag: 'SaldoAnterior', aliases: ['saldoAnterior', 'saldo anterior'], transform: moneyText },
  { tag: 'MontoAvancePago', aliases: ['montoAvancePago', 'monto avance pago'], transform: moneyText },
  { tag: 'ValorPagar', aliases: ['valorPagar', 'valor pagar'], transform: moneyText },
  { tag: 'TotalITBISRetenido', aliases: ['totalITBISRetenido', 'total itbis retenido'], transform: moneyText },
  { tag: 'TotalISRRetencion', aliases: ['totalISRRetencion', 'total isr retencion'], transform: moneyText },
];

const ITEM_FIELDS: FieldSpec[] = [
  { tag: 'NumeroLinea', aliases: ['numeroLinea', 'numero linea', 'linea'] },
  { tag: 'IndicadorFacturacion', aliases: ['indicadorFacturacion', 'indicador facturacion'] },
  { tag: 'NombreItem', aliases: ['nombreItem', 'Nombre Item', 'descripcion', 'Descripcion', 'Item', 'Concepto'] },
  { tag: 'IndicadorBienoServicio', aliases: ['indicadorBienoServicio', 'indicador bien servicio', 'bienoservicio'] },
  { tag: 'CantidadItem', aliases: ['cantidadItem', 'cantidad', 'qty'] },
  { tag: 'UnidadMedida', aliases: ['unidadMedida', 'unidad medida', 'unidad'] },
  { tag: 'PrecioUnitarioItem', aliases: ['precioUnitarioItem', 'precio unitario', 'precio'], transform: moneyText },
  { tag: 'DescuentoMonto', aliases: ['descuentoMonto', 'descuento monto', 'descuento'], transform: moneyText },
  { tag: 'MontoItem', aliases: ['montoItem', 'monto item', 'totalLinea', 'total linea'], transform: moneyText },
];

const GENERATION_MINIMUM_FIELDS = ['TipoeCF', 'eNCF', 'RNCEmisor', 'RazonSocialEmisor', 'FechaEmision', 'MontoTotal'];
const BUYER_REQUIRED_BY_TYPE = new Set(['31', '34']);
const ECF_XSD_ROOT_ELEMENT = 'ECF';
const ECF_VERSION = '1.0';

export class DgiiCertificationXmlBuilderService {
  buildEcfXmlFromCertificationCase(input: { rawRowJson: unknown; issuerFallback?: CertificationIssuerFallback | null }): CertificationXmlBuildResult {
    const row = caseRow(input);
    const reader = new RowReader(row);
    const warnings: string[] = [];
    const errors: string[] = [];
    const issuerFallback = input.issuerFallback ?? null;
    const emisorFallbacks: Record<string, { value: string | null; source: string }> = {
      RNCEmisor: { value: issuerFallback?.rnc ?? null, source: 'company.rnc' },
      RazonSocialEmisor: { value: issuerFallback?.legalName ?? issuerFallback?.businessName ?? null, source: 'company.name' },
      NombreComercial: { value: issuerFallback?.tradeName ?? null, source: 'company.tradeName' },
      DireccionEmisor: { value: issuerFallback?.address ?? null, source: 'company.config.address' },
      Municipio: { value: issuerFallback?.municipality ?? null, source: 'company.config.city' },
      Provincia: { value: issuerFallback?.province ?? null, source: 'company.config.province' },
      CorreoEmisor: { value: issuerFallback?.email ?? null, source: 'company.config.email' },
      WebSite: { value: issuerFallback?.website ?? null, source: 'company.config.website' },
      FechaEmision: { value: todayDominicanDate(), source: 'certification.currentDate' },
    };

    const fallbackFieldsUsed: Record<string, string> = {};
    const idDocLines: string[] = [];
    const idDocValues: Record<string, string> = {};
    const emisor = buildFields(reader, EMISOR_FIELDS, '      ', emisorFallbacks);
    Object.assign(fallbackFieldsUsed, emisor.fallbackFieldsUsed);
    const comprador = buildFields(reader, COMPRADOR_FIELDS, '      ');
    const totalesLines: string[] = [];
    const totalesValues: Record<string, string> = {};
    const itemLines: string[] = [];
    const itemValues: Record<string, string> = {};

    if (fallbackFieldsUsed.FechaEmision === 'certification.currentDate') {
      warnings.push('FechaEmision fallback used for certification because workbook row does not include issue date.');
    }

    const tipoEcf = readAny(reader, 'TipoeCF', ['tipoEcf', 'TipoCF', 'tipo e-CF', 'tipo comprobante', 'tipo']);
    const encf = readAny(reader, 'eNCF', ['encf', 'eNCF', 'E-NCF', 'NCF', 'comprobante', 'numeroComprobante']);
    const fechaVencimiento = readDate(reader, 'FechaVencimientoSecuencia', ['fechaVencimientoSecuencia', 'fecha vencimiento secuencia', 'vencimiento secuencia']);
    const indicadorMontoGravado = readAny(reader, 'IndicadorMontoGravado', ['indicadorMontoGravado', 'indicador monto gravado']);
    const tipoIngresosRaw = readAny(reader, 'TipoIngresos', ['tipoIngresos', 'tipo ingresos']);
    let tipoIngresos = tipoIngresosRaw ? integerText(tipoIngresosRaw)?.padStart(2, '0') ?? null : null;
    if (!tipoIngresos) {
      tipoIngresos = sourceFallback(reader, 'TipoIngresos', '01', 'certification.defaultTipoIngresos', fallbackFieldsUsed);
      warnings.push('TipoIngresos default 01 used for certification because workbook row does not include a valid value.');
    }
    const tipoPago = integerText(readAny(reader, 'TipoPago', ['tipoPago', 'tipo pago']));
    const fechaLimitePago = readDate(reader, 'FechaLimitePago', ['fechaLimitePago', 'fecha limite pago']);
    const terminoPagoRaw = readAny(reader, 'TerminoPago', ['terminoPago', 'termino pago']);
    const terminoPago = terminoPagoRaw && terminoPagoRaw.length <= 15 ? terminoPagoRaw : null;
    if (terminoPagoRaw && !terminoPago) warnings.push('TerminoPago omitted because it is longer than 15 characters or invalid.');

    pushValue(idDocLines, '      ', 'TipoeCF', tipoEcf, idDocValues);
    pushValue(idDocLines, '      ', 'eNCF', encf, idDocValues);
    pushValue(idDocLines, '      ', 'FechaVencimientoSecuencia', fechaVencimiento, idDocValues);
    if (indicadorMontoGravado === '0' || indicadorMontoGravado === '1') {
      pushValue(idDocLines, '      ', 'IndicadorMontoGravado', indicadorMontoGravado, idDocValues);
    } else if (indicadorMontoGravado) {
      warnings.push(`IndicadorMontoGravado omitted because value "${indicadorMontoGravado}" is not 0 or 1.`);
    }
    pushValue(idDocLines, '      ', 'TipoIngresos', tipoIngresos, idDocValues);
    if (tipoPago === '1' || tipoPago === '2' || tipoPago === '3') {
      pushValue(idDocLines, '      ', 'TipoPago', tipoPago, idDocValues);
    } else if (tipoPago) {
      warnings.push(`TipoPago omitted because value "${tipoPago}" is not 1, 2 or 3.`);
    }
    pushValue(idDocLines, '      ', 'FechaLimitePago', fechaLimitePago, idDocValues);
    pushValue(idDocLines, '      ', 'TerminoPago', terminoPago, idDocValues);

    const montoTotalText = readMoney(reader, 'MontoTotal', ['montoTotal', 'Monto Total', 'Total', 'TotalFactura']);
    const totalItbisText = readMoney(reader, 'TotalITBIS', ['totalITBIS', 'Total ITBIS', 'itbisTotal']);
    const totalItbis = parseMoney(totalItbisText) ?? 0;
    const montoExentoText = readMoney(reader, 'MontoExento', ['montoExento', 'monto exento']);
    const montoGravadoTotalText = readMoney(reader, 'MontoGravadoTotal', ['montoGravadoTotal', 'monto gravado total']);
    const montoGravadoI1Text = readMoney(reader, 'MontoGravadoI1', ['montoGravadoI1', 'monto gravado i1']);
    const montoGravadoI2Text = readMoney(reader, 'MontoGravadoI2', ['montoGravadoI2', 'monto gravado i2']);
    const montoGravadoI3Text = readMoney(reader, 'MontoGravadoI3', ['montoGravadoI3', 'monto gravado i3']);
    const itemIndicatorRaw = integerText(readAny(reader, 'IndicadorFacturacion', ['indicadorFacturacion', 'indicador facturacion']));
    const nombreItemRaw = readAny(reader, 'NombreItem', ['nombreItem', 'Nombre Item', 'descripcion', 'Descripcion', 'Item', 'Concepto']);
    const explicitMontoItem = readMoney(reader, 'MontoItem', ['montoItem', 'monto item', 'totalLinea', 'total linea']);
    const explicitPrecioUnitario = readMoney(reader, 'PrecioUnitarioItem', ['precioUnitarioItem', 'precio unitario', 'precio']);
    const explicitCantidad = readMoney(reader, 'CantidadItem', ['cantidadItem', 'cantidad', 'qty']);
    const descuentoMonto = readMoney(reader, 'DescuentoMonto', ['descuentoMonto', 'descuento monto', 'descuento']);
    const indicadorBienServicioRaw = integerText(readAny(reader, 'IndicadorBienoServicio', ['indicadorBienoServicio', 'indicador bien servicio', 'bienoservicio']));
    const unitPriceBase = explicitPrecioUnitario ?? explicitMontoItem ?? montoTotalText;
    let indicadorFacturacion = ['0', '1', '2', '3', '4'].includes(itemIndicatorRaw ?? '') ? itemIndicatorRaw : null;
    let nombreItem = nombreItemRaw;
    let cantidadItem = explicitCantidad;
    let precioUnitarioItem = unitPriceBase;
    let montoItemText = explicitMontoItem ?? montoTotalText;
    let indicadorBienServicio = ['1', '2'].includes(indicadorBienServicioRaw ?? '') ? indicadorBienServicioRaw : null;

    if (!nombreItem && montoTotalText) {
      const taxableFallback = totalItbis > 0;
      indicadorFacturacion = taxableFallback ? '1' : '4';
      nombreItem = 'Servicio de prueba DGII';
      indicadorBienServicio = '2';
      cantidadItem = '1.00';
      precioUnitarioItem = montoTotalText;
      montoItemText = montoTotalText;
      sourceFallback(reader, 'IndicadorFacturacion', indicadorFacturacion, 'certification.itemFallback', fallbackFieldsUsed);
      sourceFallback(reader, 'NombreItem', nombreItem, 'certification.itemFallback', fallbackFieldsUsed);
      sourceFallback(reader, 'IndicadorBienoServicio', indicadorBienServicio, 'certification.itemFallback', fallbackFieldsUsed);
      sourceFallback(reader, 'CantidadItem', cantidadItem, 'certification.itemFallback', fallbackFieldsUsed);
      sourceFallback(reader, 'PrecioUnitarioItem', precioUnitarioItem, 'certification.itemFallback', fallbackFieldsUsed);
      sourceFallback(reader, 'MontoItem', montoItemText, 'certification.itemFallback', fallbackFieldsUsed);
      warnings.push('Certification item fallback used.');
    }

    const requiredFields = [
      ...GENERATION_MINIMUM_FIELDS,
      'TipoPago',
      'IndicadorFacturacion',
      'NombreItem',
      'IndicadorBienoServicio',
      'CantidadItem',
      'PrecioUnitarioItem',
      'MontoItem',
      ...(BUYER_REQUIRED_BY_TYPE.has(tipoEcf ?? '') ? ['RNCComprador', 'RazonSocialComprador'] : []),
      ...((tipoEcf === '33' || tipoEcf === '34') ? ['NCFModificado', 'FechaNCFModificado', 'CodigoModificacion'] : []),
    ];

    pushValue(totalesLines, '      ', 'MontoGravadoTotal', montoGravadoTotalText, totalesValues);
    pushValue(totalesLines, '      ', 'MontoGravadoI1', montoGravadoI1Text, totalesValues);
    pushValue(totalesLines, '      ', 'MontoGravadoI2', montoGravadoI2Text, totalesValues);
    pushValue(totalesLines, '      ', 'MontoGravadoI3', montoGravadoI3Text, totalesValues);
    if (indicadorFacturacion === '4' && montoTotalText && !montoExentoText) {
      sourceFallback(reader, 'MontoExento', montoTotalText, 'certification.exentoFromMontoTotal', fallbackFieldsUsed);
      pushValue(totalesLines, '      ', 'MontoExento', montoTotalText, totalesValues);
    } else {
      pushValue(totalesLines, '      ', 'MontoExento', montoExentoText, totalesValues);
    }
    if (indicadorFacturacion === '1') pushValue(totalesLines, '      ', 'ITBIS1', '18', totalesValues);
    if (indicadorFacturacion === '2') pushValue(totalesLines, '      ', 'ITBIS2', '16', totalesValues);
    if (indicadorFacturacion === '3') pushValue(totalesLines, '      ', 'ITBIS3', '0', totalesValues);
    pushValue(totalesLines, '      ', 'TotalITBIS', totalItbisText, totalesValues);
    pushValue(totalesLines, '      ', 'TotalITBIS1', readMoney(reader, 'TotalITBIS1', ['totalITBIS1', 'total itbis 1']), totalesValues);
    pushValue(totalesLines, '      ', 'TotalITBIS2', readMoney(reader, 'TotalITBIS2', ['totalITBIS2', 'total itbis 2']), totalesValues);
    pushValue(totalesLines, '      ', 'TotalITBIS3', readMoney(reader, 'TotalITBIS3', ['totalITBIS3', 'total itbis 3']), totalesValues);
    pushValue(totalesLines, '      ', 'MontoTotal', montoTotalText, totalesValues);
    pushValue(totalesLines, '      ', 'MontoPeriodo', readMoney(reader, 'MontoPeriodo', ['montoPeriodo', 'monto periodo']), totalesValues);
    pushValue(totalesLines, '      ', 'SaldoAnterior', readMoney(reader, 'SaldoAnterior', ['saldoAnterior', 'saldo anterior']), totalesValues);
    pushValue(totalesLines, '      ', 'MontoAvancePago', readMoney(reader, 'MontoAvancePago', ['montoAvancePago', 'monto avance pago']), totalesValues);
    pushValue(totalesLines, '      ', 'ValorPagar', readMoney(reader, 'ValorPagar', ['valorPagar', 'valor pagar']), totalesValues);
    pushValue(totalesLines, '      ', 'TotalITBISRetenido', readMoney(reader, 'TotalITBISRetenido', ['totalITBISRetenido', 'total itbis retenido']), totalesValues);
    pushValue(totalesLines, '      ', 'TotalISRRetencion', readMoney(reader, 'TotalISRRetencion', ['totalISRRetencion', 'total isr retencion']), totalesValues);

    pushValue(itemLines, '      ', 'NumeroLinea', integerText(readAny(reader, 'NumeroLinea', ['numeroLinea', 'numero linea', 'linea'])) ?? '1', itemValues);
    pushValue(itemLines, '      ', 'IndicadorFacturacion', indicadorFacturacion, itemValues);
    pushValue(itemLines, '      ', 'NombreItem', nombreItem, itemValues);
    pushValue(itemLines, '      ', 'IndicadorBienoServicio', indicadorBienServicio, itemValues);
    pushValue(itemLines, '      ', 'CantidadItem', cantidadItem, itemValues);
    pushValue(itemLines, '      ', 'UnidadMedida', integerText(readAny(reader, 'UnidadMedida', ['unidadMedida', 'unidad medida', 'unidad'])), itemValues);
    pushValue(itemLines, '      ', 'PrecioUnitarioItem', precioUnitarioItem, itemValues);
    pushValue(itemLines, '      ', 'DescuentoMonto', descuentoMonto, itemValues);
    pushValue(itemLines, '      ', 'MontoItem', montoItemText, itemValues);

    const informacionReferenciaLines: string[] = [];
    const informacionReferenciaValues: Record<string, string> = {};
    if (tipoEcf === '33' || tipoEcf === '34') {
      pushValue(informacionReferenciaLines, '    ', 'NCFModificado', readAny(reader, 'NCFModificado', ['ncfModificado', 'NCF Modificado', 'NCFModificado', 'eNCFModificado']), informacionReferenciaValues);
      pushValue(informacionReferenciaLines, '    ', 'FechaNCFModificado', readDate(reader, 'FechaNCFModificado', ['fechaNCFModificado', 'Fecha NCF Modificado', 'FechaNCFModificado']), informacionReferenciaValues);
      pushValue(informacionReferenciaLines, '    ', 'CodigoModificacion', integerText(readAny(reader, 'CodigoModificacion', ['codigoModificacion', 'Codigo Modificacion', 'CodigoModificacion'])), informacionReferenciaValues);
      pushValue(informacionReferenciaLines, '    ', 'RazonModificacion', readAny(reader, 'RazonModificacion', ['razonModificacion', 'Razon Modificacion', 'RazonModificacion']), informacionReferenciaValues);
    }

    const presentTags = new Set(
      [...idDocLines, ...emisor.lines, ...comprador.lines, ...totalesLines, ...itemLines, ...informacionReferenciaLines]
        .map((line) => line.match(/<([A-Za-z0-9]+)>/)?.[1])
        .filter((value): value is string => !!value),
    );
    const missing = requiredFields.filter((field) => !presentTags.has(field));
    if (missing.length > 0) {
      errors.push(buildMissingMessage(missing));
    }

    const montoTotal = parsePositiveMoney(montoTotalText);
    const montoItem = parsePositiveMoney(montoItemText);
    const descuento = parseMoney(descuentoMonto) ?? 0;
    if (montoTotal != null && montoItem != null) {
      const calculated = Math.round((montoItem + totalItbis - descuento) * 100) / 100;
      if (Math.abs(calculated - montoTotal) > 0.01) {
        warnings.push(`MontoTotal (${montoTotal.toFixed(2)}) no coincide con MontoItem + ITBIS - descuentos (${calculated.toFixed(2)})`);
      }
    }

    if (errors.length > 0) {
      return {
        xml: '',
        warnings,
        errors,
        missingFields: missing,
        extractedFields: reader.extractedFields,
        fallbackFieldsUsed,
        rawRowKeys: reader.rawRowKeys,
        humanReadableMessage: buildMissingMessage(missing),
        sourceFieldsUsed: reader.sourceFieldsUsed,
      };
    }

    const xmlLines = [
      '<?xml version="1.0" encoding="UTF-8"?>',
      `<${ECF_XSD_ROOT_ELEMENT}>`,
      '  <Encabezado>',
      `    <Version>${ECF_VERSION}</Version>`,
      ...section('IdDoc', idDocLines, '    '),
      ...section('Emisor', emisor.lines, '    '),
      '    <Comprador>',
      ...comprador.lines,
      '    </Comprador>',
      ...section('Totales', totalesLines, '    '),
      '  </Encabezado>',
      '  <DetallesItems>',
      '    <Item>',
      ...itemLines,
      '    </Item>',
      '  </DetallesItems>',
      ...section('InformacionReferencia', informacionReferenciaLines, '  '),
      `  <FechaHoraFirma>${xmlEscape(dominicanTimestamp())}</FechaHoraFirma>`,
      `</${ECF_XSD_ROOT_ELEMENT}>`,
    ];

    return {
      xml: xmlLines.join('\n'),
      warnings,
      errors,
      missingFields: [],
      extractedFields: reader.extractedFields,
      fallbackFieldsUsed,
      rawRowKeys: reader.rawRowKeys,
      humanReadableMessage: null,
      sourceFieldsUsed: reader.sourceFieldsUsed,
    };
  }

  buildRfceXmlFromCertificationCase(input: { rawRowJson: unknown }): CertificationXmlBuildResult {
    const row = caseRow(input);
    const reader = new RowReader(row);
    throw {
      status: 409,
      message: 'RFCE XML generation is not implemented in this phase.',
      errorCode: 'DGII_CERTIFICATION_RFCE_XML_NOT_MAPPED',
      details: {
        encf: readField(reader, 'eNCF', ['encf', 'eNCF', 'E-NCF', 'NCF', 'comprobante', 'numeroComprobante']),
        tipoEcf: readField(reader, 'TipoeCF', ['tipoEcf', 'TipoCF', 'tipo e-CF', 'tipo comprobante', 'tipo']),
        rawRowKeys: reader.rawRowKeys,
        extractedFields: reader.extractedFields,
      },
    };
  }
}

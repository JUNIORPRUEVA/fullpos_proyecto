import crypto from 'crypto';
import { CertificationXmlBuildResult } from './dgii-certification-xml-builder.service';

type RawRow = Record<string, unknown>;

type FieldSpec = {
  tag: string;
  aliases: string[];
  transform?: (value: string) => string | null;
};

function normalizeHeader(value: unknown) {
  return String(value ?? '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');
}

function normalizeValue(value: unknown) {
  if (value == null) return null;
  if (value instanceof Date) return value.toISOString();
  const text = String(value).trim();
  if (!text || ['#e', '#n/a', 'n/a', 'null', 'undefined'].includes(text.toLowerCase())) return null;
  return text.length > 0 ? text : null;
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
  private readonly entries: Array<{ normalizedKey: string; originalKey: string; value: unknown }>;
  readonly sourceFieldsUsed: Record<string, string> = {};
  readonly extractedFields: Record<string, string> = {};
  readonly rawRowKeys: string[];

  constructor(row: RawRow) {
    this.rawRowKeys = Object.keys(row);
    this.entries = Object.entries(row).map(([originalKey, value]) => ({
      normalizedKey: normalizeHeader(originalKey),
      originalKey,
      value,
    }));
  }

  get(canonicalName: string, aliases: string[]) {
    const normalizedAliases = aliases.map(normalizeHeader);
    const found = this.entries.find((entry) => normalizedAliases.includes(entry.normalizedKey)) ??
      this.entries.find((entry) => normalizedAliases.some((alias) => entry.normalizedKey === `${alias}1`));
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

function parseDate(value: string | null) {
  if (!value) return null;
  const text = value.trim();
  const dominican = text.match(/^(\d{1,2})[/-](\d{1,2})[/-](\d{4})$/);
  if (dominican) return `${pad2(Number(dominican[1]))}-${pad2(Number(dominican[2]))}-${dominican[3]}`;
  const parsed = new Date(text.replace(/^(\d{4})-(\d{2})-(\d{2}).*$/, '$1-$2-$3'));
  if (Number.isNaN(parsed.getTime())) return null;
  return `${pad2(parsed.getUTCDate())}-${pad2(parsed.getUTCMonth() + 1)}-${parsed.getUTCFullYear()}`;
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

function buildFields(reader: RowReader, specs: FieldSpec[], indent: string) {
  const lines: string[] = [];
  for (const spec of specs) {
    addTag(lines, indent, spec.tag, readField(reader, spec.tag, spec.aliases, spec.transform));
  }
  return lines;
}

function certificationSecurityCode(reader: RowReader) {
  const seedParts = [
    readField(reader, 'CasoPrueba', ['casoPrueba', 'caso prueba']),
    readField(reader, 'eNCF', ['encf', 'eNCF', 'E-NCF', 'NCF', 'comprobante', 'numeroComprobante']),
    readField(reader, 'RNCEmisor', ['rncEmisor', 'RNC Emisor', 'RNCEmisor'], normalizeRnc),
    readField(reader, 'MontoTotal', ['montoTotal', 'Monto Total', 'Total', 'TotalFactura'], moneyText),
  ].filter((value): value is string => !!value);
  if (seedParts.length === 0) return null;
  return crypto.createHash('sha256').update(seedParts.join('|')).digest('hex').slice(0, 6).toUpperCase();
}

const RFCE_ID_DOC_FIELDS: FieldSpec[] = [
  { tag: 'TipoeCF', aliases: ['tipoEcf', 'TipoCF', 'tipo e-CF', 'tipo comprobante', 'tipo'] },
  { tag: 'eNCF', aliases: ['encf', 'eNCF', 'E-NCF', 'NCF', 'comprobante', 'numeroComprobante'] },
  { tag: 'TipoIngresos', aliases: ['tipoIngresos', 'tipo ingresos'] },
  { tag: 'TipoPago', aliases: ['tipoPago', 'tipo pago', 'condicion pago', 'condicionPago', 'forma pago', 'Forma Pago'] },
  { tag: 'Periodo', aliases: ['periodo', 'Periodo'] },
  { tag: 'FechaDesde', aliases: ['fechaDesde', 'fecha desde', 'desde'], transform: parseDate },
  { tag: 'FechaHasta', aliases: ['fechaHasta', 'fecha hasta', 'hasta'], transform: parseDate },
];

const RFCE_EMISOR_FIELDS: FieldSpec[] = [
  { tag: 'RNCEmisor', aliases: ['rncEmisor', 'RNC Emisor', 'RNCEmisor'], transform: normalizeRnc },
  { tag: 'RazonSocialEmisor', aliases: ['razonSocialEmisor', 'Razon Social Emisor', 'Nombre Emisor', 'Emisor'] },
  { tag: 'NombreComercial', aliases: ['nombreComercial', 'nombre comercial'] },
  { tag: 'Sucursal', aliases: ['sucursal'] },
  { tag: 'DireccionEmisor', aliases: ['direccionEmisor', 'direccion emisor', 'direccion'] },
  { tag: 'FechaEmision', aliases: ['fechaEmision', 'Fecha Emision', 'FechaEmision', 'Fecha'], transform: parseDate },
];

const RFCE_COMPRADOR_FIELDS: FieldSpec[] = [
  { tag: 'RNCComprador', aliases: ['rncComprador', 'RNC Comprador', 'RNCComprador'], transform: normalizeRnc },
  { tag: 'IdentificadorExtranjero', aliases: ['identificadorExtranjero', 'id extranjero', 'identificacion extranjero'] },
  { tag: 'RazonSocialComprador', aliases: ['razonSocialComprador', 'Razon Social Comprador', 'Nombre Comprador', 'Comprador'] },
];

const RFCE_TOTALES_FIELDS: FieldSpec[] = [
  { tag: 'MontoGravadoTotal', aliases: ['montoGravadoTotal', 'monto gravado total'], transform: moneyText },
  { tag: 'MontoGravadoI1', aliases: ['montoGravadoI1', 'monto gravado i1'], transform: moneyText },
  { tag: 'MontoGravadoI2', aliases: ['montoGravadoI2', 'monto gravado i2'], transform: moneyText },
  { tag: 'MontoGravadoI3', aliases: ['montoGravadoI3', 'monto gravado i3'], transform: moneyText },
  { tag: 'MontoExento', aliases: ['montoExento', 'monto exento'], transform: moneyText },
  { tag: 'TotalITBIS', aliases: ['totalITBIS', 'Total ITBIS', 'itbisTotal'], transform: moneyText },
  { tag: 'TotalITBIS1', aliases: ['totalITBIS1', 'total itbis 1'], transform: moneyText },
  { tag: 'TotalITBIS2', aliases: ['totalITBIS2', 'total itbis 2'], transform: moneyText },
  { tag: 'TotalITBIS3', aliases: ['totalITBIS3', 'total itbis 3'], transform: moneyText },
  { tag: 'MontoImpuestoAdicional', aliases: ['montoImpuestoAdicional', 'monto impuesto adicional'], transform: moneyText },
  { tag: 'MontoTotal', aliases: ['montoTotal', 'Monto Total', 'Total', 'TotalFactura'], transform: moneyText },
  { tag: 'MontoNoFacturable', aliases: ['montoNoFacturable', 'monto no facturable'], transform: moneyText },
  { tag: 'MontoPeriodo', aliases: ['montoPeriodo', 'monto periodo'], transform: moneyText },
];

const RFCE_AFTER_TOTALES_FIELDS: FieldSpec[] = [
  { tag: 'CodigoSeguridadeCF', aliases: ['codigoSeguridadeCF', 'codigo seguridad ecf', 'codigo seguridad eCF', 'codigo seguridad'] },
];

const RFCE_RESUMEN_FIELDS: FieldSpec[] = [
  { tag: 'CantidadComprobantes', aliases: ['cantidadComprobantes', 'cantidad comprobantes', 'cantidad', 'totalComprobantes'] },
  { tag: 'SecuenciaDesde', aliases: ['secuenciaDesde', 'secuencia desde', 'ncfDesde', 'eNCFDesde'] },
  { tag: 'SecuenciaHasta', aliases: ['secuenciaHasta', 'secuencia hasta', 'ncfHasta', 'eNCFHasta'] },
  { tag: 'TotalMontoGravado', aliases: ['totalMontoGravado', 'total monto gravado'], transform: moneyText },
  { tag: 'TotalMontoExento', aliases: ['totalMontoExento', 'total monto exento'], transform: moneyText },
  { tag: 'TotalMontoFacturado', aliases: ['totalMontoFacturado', 'total monto facturado'], transform: moneyText },
  { tag: 'TotalITBIS', aliases: ['totalITBIS', 'Total ITBIS', 'itbisTotal'], transform: moneyText },
];

const RFCE_REQUIRED_FIELDS = [
  'TipoeCF',
  'eNCF',
  'TipoIngresos',
  'TipoPago',
  'RNCEmisor',
  'RazonSocialEmisor',
  'FechaEmision',
  'MontoTotal',
];

export class DgiiCertificationRfceXmlBuilderService {
  buildXmlFromCertificationCase(input: { rawRowJson: unknown }): CertificationXmlBuildResult {
    const reader = new RowReader(caseRow(input));
    const warnings: string[] = [];

    const idDocLines = buildFields(reader, RFCE_ID_DOC_FIELDS, '      ');
    const emisorLines = buildFields(reader, RFCE_EMISOR_FIELDS, '      ');
    const compradorLines = buildFields(reader, RFCE_COMPRADOR_FIELDS, '      ');
    const totalesLines = buildFields(reader, RFCE_TOTALES_FIELDS, '      ');
    const afterTotalesLines = buildFields(reader, RFCE_AFTER_TOTALES_FIELDS, '    ');
    const resumenLines = buildFields(reader, RFCE_RESUMEN_FIELDS, '    ');
    const fechaFirmaFromRow = readField(reader, 'FechaHoraFirma', [
      'fechaFirma',
      'Fecha Firma',
      'fechaHoraFirma',
      'FechaHoraFirma',
      'Fecha Firma Digital',
    ]);
    const fechaFirma = fechaFirmaFromRow ?? dominicanTimestamp();
    const fallbackFieldsUsed: Record<string, string> = {};
    if (!fechaFirmaFromRow) {
      reader.extractedFields.FechaHoraFirma = fechaFirma;
      fallbackFieldsUsed.FechaHoraFirma = 'certification.currentDominicanTimestamp';
      warnings.push('FechaHoraFirma generated automatically for RFCE certification using Dominican Republic timezone.');
    }
    if (!afterTotalesLines.some((line) => line.includes('<CodigoSeguridadeCF>'))) {
      const generatedSecurityCode = certificationSecurityCode(reader);
      if (generatedSecurityCode) {
        addTag(afterTotalesLines, '    ', 'CodigoSeguridadeCF', generatedSecurityCode);
        reader.extractedFields.CodigoSeguridadeCF = generatedSecurityCode;
        fallbackFieldsUsed.CodigoSeguridadeCF = 'certification.sha256(CasoPrueba|eNCF|RNCEmisor|MontoTotal).first6';
        warnings.push('CodigoSeguridadeCF generated for RFCE certification because workbook row does not include the original consumer invoice security code.');
      }
    }

    const presentTags = new Set(
      [...idDocLines, ...emisorLines, ...compradorLines, ...totalesLines, ...afterTotalesLines, ...resumenLines]
        .map((line) => line.match(/<([A-Za-z0-9]+)>/)?.[1])
        .filter((value): value is string => !!value),
    );
    if (fechaFirma) presentTags.add('FechaHoraFirma');
    const missing = RFCE_REQUIRED_FIELDS.filter((field) => !presentTags.has(field));
    if (missing.length > 0) {
      return {
        xml: '',
        warnings,
        errors: [`Faltan campos obligatorios RFCE: ${missing.join(', ')}`],
        missingFields: missing,
        extractedFields: reader.extractedFields,
        fallbackFieldsUsed,
        rawRowKeys: reader.rawRowKeys,
        humanReadableMessage: `Faltan campos obligatorios RFCE: ${missing.join(', ')}`,
        sourceFieldsUsed: reader.sourceFieldsUsed,
      };
    }

    if (resumenLines.length === 0) {
      warnings.push('RFCE resumen fields were not found; generated XML includes only mapped header and totals.');
    }

    const rfcePayloadLines = [...resumenLines];
    addTag(rfcePayloadLines, '    ', 'FechaHoraFirma', fechaFirma);

    const xmlLines = [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<RFCE>',
      '  <Encabezado>',
      '    <Version>1.0</Version>',
      ...section('IdDoc', idDocLines, '    '),
      ...section('Emisor', emisorLines, '    '),
      ...section('Comprador', compradorLines, '    '),
      ...section('Totales', totalesLines, '    '),
      ...afterTotalesLines,
      '  </Encabezado>',
      ...section('ResumenFacturaConsumo', rfcePayloadLines, '  '),
      '</RFCE>',
    ];

    return {
      xml: xmlLines.join('\n'),
      warnings,
      errors: [],
      missingFields: [],
      extractedFields: reader.extractedFields,
      fallbackFieldsUsed,
      rawRowKeys: reader.rawRowKeys,
      humanReadableMessage: null,
      sourceFieldsUsed: reader.sourceFieldsUsed,
    };
  }
}

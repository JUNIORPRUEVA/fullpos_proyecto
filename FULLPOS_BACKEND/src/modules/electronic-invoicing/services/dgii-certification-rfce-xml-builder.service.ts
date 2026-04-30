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

  constructor(row: RawRow) {
    this.entries = Object.entries(row).map(([originalKey, value]) => ({
      normalizedKey: normalizeHeader(originalKey),
      originalKey,
      value,
    }));
  }

  get(canonicalName: string, aliases: string[]) {
    const normalizedAliases = aliases.map(normalizeHeader);
    const found = this.entries.find((entry) => normalizedAliases.includes(entry.normalizedKey));
    if (!found) return null;
    const value = normalizeValue(found.value);
    if (value != null) this.sourceFieldsUsed[canonicalName] = found.originalKey;
    return value;
  }
}

function normalizeRnc(value: string | null) {
  return value?.replace(/\D/g, '') || null;
}

function parseDate(value: string | null) {
  if (!value) return null;
  const normalized = value
    .trim()
    .replace(/^(\d{2})\/(\d{2})\/(\d{4})$/, '$3-$2-$1')
    .replace(/^(\d{2})-(\d{2})-(\d{4})$/, '$3-$2-$1');
  const parsed = new Date(normalized);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString().slice(0, 10);
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

const RFCE_ID_DOC_FIELDS: FieldSpec[] = [
  { tag: 'TipoeCF', aliases: ['tipoEcf', 'TipoCF', 'tipo e-CF', 'tipo comprobante', 'tipo'] },
  { tag: 'eNCF', aliases: ['encf', 'eNCF', 'E-NCF', 'NCF', 'comprobante', 'numeroComprobante'] },
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

const RFCE_TOTALES_FIELDS: FieldSpec[] = [
  { tag: 'MontoGravadoTotal', aliases: ['montoGravadoTotal', 'monto gravado total'], transform: moneyText },
  { tag: 'MontoExento', aliases: ['montoExento', 'monto exento'], transform: moneyText },
  { tag: 'TotalITBIS', aliases: ['totalITBIS', 'Total ITBIS', 'itbisTotal'], transform: moneyText },
  { tag: 'MontoTotal', aliases: ['montoTotal', 'Monto Total', 'Total', 'TotalFactura'], transform: moneyText },
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
  'RNCEmisor',
  'RazonSocialEmisor',
  'FechaEmision',
  'FechaHoraFirma',
  'MontoTotal',
];

export class DgiiCertificationRfceXmlBuilderService {
  buildXmlFromCertificationCase(input: { rawRowJson: unknown }): CertificationXmlBuildResult {
    const reader = new RowReader(caseRow(input));
    const warnings: string[] = [];

    const idDocLines = buildFields(reader, RFCE_ID_DOC_FIELDS, '      ');
    const emisorLines = buildFields(reader, RFCE_EMISOR_FIELDS, '      ');
    const totalesLines = buildFields(reader, RFCE_TOTALES_FIELDS, '      ');
    const resumenLines = buildFields(reader, RFCE_RESUMEN_FIELDS, '    ');
    const fechaFirma = readField(reader, 'FechaHoraFirma', [
      'fechaFirma',
      'Fecha Firma',
      'fechaHoraFirma',
      'FechaHoraFirma',
      'Fecha Firma Digital',
    ]);

    const presentTags = new Set(
      [...idDocLines, ...emisorLines, ...totalesLines, ...resumenLines]
        .map((line) => line.match(/<([A-Za-z0-9]+)>/)?.[1])
        .filter((value): value is string => !!value),
    );
    if (fechaFirma) presentTags.add('FechaHoraFirma');
    const missing = RFCE_REQUIRED_FIELDS.filter((field) => !presentTags.has(field));
    if (missing.length > 0) {
      return {
        xml: '',
        warnings,
        errors: [`Missing required DGII RFCE fields: ${missing.join(', ')}`],
        sourceFieldsUsed: reader.sourceFieldsUsed,
      };
    }

    if (resumenLines.length === 0) {
      warnings.push('RFCE resumen fields were not found; generated XML includes only mapped header and totals.');
    }

    const xmlLines = [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<RFCE>',
      '  <Encabezado>',
      ...section('IdDoc', idDocLines, '    '),
      ...section('Emisor', emisorLines, '    '),
      ...section('Totales', totalesLines, '    '),
      '  </Encabezado>',
      ...section('ResumenFacturaConsumo', resumenLines, '  '),
      `  <FechaHoraFirma>${xmlEscape(fechaFirma)}</FechaHoraFirma>`,
      '</RFCE>',
    ];

    return {
      xml: xmlLines.join('\n'),
      warnings,
      errors: [],
      sourceFieldsUsed: reader.sourceFieldsUsed,
    };
  }
}

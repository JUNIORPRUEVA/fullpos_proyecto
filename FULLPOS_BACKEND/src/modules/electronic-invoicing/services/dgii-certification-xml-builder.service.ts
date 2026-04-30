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
  { tag: 'Municipio', aliases: ['municipio', 'municipioEmisor'] },
  { tag: 'Provincia', aliases: ['provincia', 'provinciaEmisor'] },
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
  { tag: 'MunicipioComprador', aliases: ['municipioComprador', 'municipio comprador'] },
  { tag: 'ProvinciaComprador', aliases: ['provinciaComprador', 'provincia comprador'] },
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

    const idDoc = buildFields(reader, ID_DOC_FIELDS, '      ');
    const emisor = buildFields(reader, EMISOR_FIELDS, '      ', emisorFallbacks);
    const comprador = buildFields(reader, COMPRADOR_FIELDS, '      ');
    const totales = buildFields(reader, TOTALES_FIELDS, '      ');
    const item = buildFields(reader, ITEM_FIELDS, '      ');

    const fallbackFieldsUsed = {
      ...idDoc.fallbackFieldsUsed,
      ...emisor.fallbackFieldsUsed,
      ...comprador.fallbackFieldsUsed,
      ...totales.fallbackFieldsUsed,
      ...item.fallbackFieldsUsed,
    };
    if (fallbackFieldsUsed.FechaEmision === 'certification.currentDate') {
      warnings.push('FechaEmision fallback used for certification because workbook row does not include issue date.');
    }

    const itemLines = [...item.lines];
    const montoTotalText = totales.values.MontoTotal ?? readField(reader, 'MontoTotal', ['montoTotal', 'Monto Total', 'Total', 'TotalFactura'], moneyText);
    if (!itemLines.some((line) => line.includes('<NumeroLinea>'))) {
      itemLines.unshift('      <NumeroLinea>1</NumeroLinea>');
    }
    if (!item.values.NombreItem && montoTotalText) {
      itemLines.push('      <NombreItem>Servicio de prueba DGII</NombreItem>');
      itemLines.push('      <CantidadItem>1</CantidadItem>');
      itemLines.push(`      <PrecioUnitarioItem>${xmlEscape(montoTotalText)}</PrecioUnitarioItem>`);
      itemLines.push(`      <MontoItem>${xmlEscape(montoTotalText)}</MontoItem>`);
      reader.extractedFields.NombreItem = 'Servicio de prueba DGII';
      reader.extractedFields.CantidadItem = '1';
      reader.extractedFields.PrecioUnitarioItem = montoTotalText;
      reader.extractedFields.MontoItem = montoTotalText;
      fallbackFieldsUsed.NombreItem = 'certification.itemFallback';
      fallbackFieldsUsed.CantidadItem = 'certification.itemFallback';
      fallbackFieldsUsed.PrecioUnitarioItem = 'certification.itemFallback';
      fallbackFieldsUsed.MontoItem = 'certification.itemFallback';
      warnings.push('Item fallback used for certification because workbook row does not include item detail.');
    }

    const tipoEcf = idDoc.values.TipoeCF ?? readField(reader, 'TipoeCF', ['tipoEcf', 'TipoCF', 'tipo e-CF', 'tipo comprobante', 'tipo']);
    const requiredFields = [
      ...GENERATION_MINIMUM_FIELDS,
      ...(BUYER_REQUIRED_BY_TYPE.has(tipoEcf ?? '') ? ['RNCComprador', 'RazonSocialComprador'] : []),
    ];
    const presentTags = new Set(
      [...idDoc.lines, ...emisor.lines, ...comprador.lines, ...totales.lines, ...itemLines]
        .map((line) => line.match(/<([A-Za-z0-9]+)>/)?.[1])
        .filter((value): value is string => !!value),
    );
    const missing = requiredFields.filter((field) => !presentTags.has(field));
    if (missing.length > 0) {
      errors.push(buildMissingMessage(missing));
    }

    const montoTotal = parsePositiveMoney(montoTotalText);
    const montoItem = parsePositiveMoney(reader.extractedFields.MontoItem ?? item.values.MontoItem ?? readField(reader, 'MontoItem', ['montoItem', 'monto item', 'totalLinea', 'total linea']));
    const totalItbis = parseMoney(totales.values.TotalITBIS ?? readField(reader, 'TotalITBIS', ['totalITBIS', 'Total ITBIS', 'itbisTotal'])) ?? 0;
    const descuento = parseMoney(item.values.DescuentoMonto ?? readField(reader, 'DescuentoMonto', ['descuentoMonto', 'descuento monto', 'descuento'])) ?? 0;
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
      ...section('IdDoc', idDoc.lines, '    '),
      ...section('Emisor', emisor.lines, '    '),
      ...section('Comprador', comprador.lines, '    '),
      ...section('Totales', totales.lines, '    '),
      '  </Encabezado>',
      '  <DetallesItems>',
      '    <Item>',
      ...itemLines,
      '    </Item>',
      '  </DetallesItems>',
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

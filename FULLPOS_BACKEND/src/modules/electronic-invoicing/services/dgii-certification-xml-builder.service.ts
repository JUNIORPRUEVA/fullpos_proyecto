type RawRow = Record<string, unknown>;

export type CertificationXmlBuildResult = {
  xml: string;
  warnings: string[];
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

function findRaw(row: RawRow, aliases: string[]) {
  const normalizedAliases = aliases.map(normalizeHeader);
  for (const [key, value] of Object.entries(row)) {
    if (normalizedAliases.includes(normalizeHeader(key))) {
      return normalizeValue(value);
    }
  }
  return null;
}

function normalizeRnc(value: string | null) {
  return value?.replace(/\D/g, '') || null;
}

function parseMoney(value: string | number | null) {
  if (value == null || value === '') return null;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  const parsed = Number(String(value).replace(/RD\$|\$|,/gi, '').trim());
  return Number.isFinite(parsed) ? parsed : null;
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

function formatMoney(value: number) {
  return value.toFixed(2);
}

function pad2(value: number) {
  return String(value).padStart(2, '0');
}

function signatureTimestamp(value = new Date()) {
  const dominicanTime = new Date(value.getTime() - 4 * 60 * 60 * 1000);
  return `${pad2(dominicanTime.getUTCDate())}-${pad2(dominicanTime.getUTCMonth() + 1)}-${dominicanTime.getUTCFullYear()} ${pad2(dominicanTime.getUTCHours())}:${pad2(dominicanTime.getUTCMinutes())}:${pad2(dominicanTime.getUTCSeconds())}`;
}

function first(row: RawRow, aliases: string[]) {
  return findRaw(row, aliases);
}

function caseRow(input: { rawRowJson: unknown }) {
  return input.rawRowJson && typeof input.rawRowJson === 'object' && !Array.isArray(input.rawRowJson)
    ? input.rawRowJson as RawRow
    : {};
}

function collectCommon(row: RawRow) {
  const warnings: string[] = [];
  const encf = first(row, ['encf', 'eNCF', 'E-NCF', 'NCF', 'comprobante', 'numeroComprobante']);
  const tipoEcf = first(row, ['tipoEcf', 'TipoCF', 'tipo e-CF', 'tipo comprobante', 'tipo']);
  const rncEmisor = normalizeRnc(first(row, ['rncEmisor', 'RNC Emisor', 'RNCEmisor']));
  const rncComprador = normalizeRnc(first(row, ['rncComprador', 'RNC Comprador', 'RNCComprador']));
  const razonSocialEmisor = first(row, ['razonSocialEmisor', 'Razon Social Emisor', 'Nombre Emisor', 'Emisor']) ?? 'EMISOR CERTIFICACION DGII';
  const razonSocialComprador = first(row, ['razonSocialComprador', 'Razon Social Comprador', 'Nombre Comprador', 'Comprador']);
  const fechaRaw = first(row, ['fechaEmision', 'Fecha Emision', 'FechaEmisión', 'Fecha']);
  const fechaEmision = parseDate(fechaRaw);
  const montoRaw = first(row, ['montoTotal', 'Monto Total', 'Total', 'TotalFactura']);
  const montoTotal = parseMoney(montoRaw);
  const descripcion = first(row, ['descripcion', 'Descripcion', 'NombreItem', 'Item', 'Concepto']) ?? 'Caso certificacion DGII';

  if (!encf) warnings.push('No se detecto eNCF');
  if (!tipoEcf) warnings.push('No se detecto tipo e-CF');
  if (!rncEmisor) warnings.push('No se detecto RNC emisor');
  if (!fechaEmision) warnings.push('No se detecto fecha de emision valida');
  if (montoTotal == null) warnings.push('No se detecto monto total valido');

  return {
    encf,
    tipoEcf,
    rncEmisor,
    rncComprador,
    razonSocialEmisor,
    razonSocialComprador,
    fechaEmision,
    montoTotal,
    descripcion,
    warnings,
  };
}

function assertRequired(
  values: Record<string, unknown>,
  message = 'Faltan campos obligatorios para generar XML',
) {
  const missing = Object.entries(values)
    .filter(([, value]) => value == null || value === '')
    .map(([key]) => key);
  if (missing.length > 0) {
    throw {
      status: 409,
      message,
      errorCode: 'DGII_CERTIFICATION_XML_REQUIRED_FIELDS_MISSING',
      details: { missing },
    };
  }
}

export class DgiiCertificationXmlBuilderService {
  buildEcfXmlFromCertificationCase(input: { rawRowJson: unknown }): CertificationXmlBuildResult {
    const row = caseRow(input);
    const mapped = collectCommon(row);
    assertRequired({
      encf: mapped.encf,
      tipoEcf: mapped.tipoEcf,
      rncEmisor: mapped.rncEmisor,
      fechaEmision: mapped.fechaEmision,
      montoTotal: mapped.montoTotal,
    });

    const montoTotal = mapped.montoTotal!;
    // TODO: Confirm full DGII Step 2 XSD mapping against official DGII workbook columns.
    const comprador = mapped.rncComprador || mapped.razonSocialComprador
      ? `
    <Comprador>${mapped.rncComprador ? `
      <RNCComprador>${xmlEscape(mapped.rncComprador)}</RNCComprador>` : ''}
      <RazonSocialComprador>${xmlEscape(mapped.razonSocialComprador ?? 'CONSUMIDOR FINAL')}</RazonSocialComprador>
    </Comprador>`
      : '';

    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<eCF>
  <Encabezado>
    <IdDoc>
      <eNCF>${xmlEscape(mapped.encf)}</eNCF>
      <TipoeCF>${xmlEscape(mapped.tipoEcf)}</TipoeCF>
      <FechaEmision>${xmlEscape(mapped.fechaEmision)}</FechaEmision>
    </IdDoc>
    <Emisor>
      <RNCEmisor>${xmlEscape(mapped.rncEmisor)}</RNCEmisor>
      <RazonSocialEmisor>${xmlEscape(mapped.razonSocialEmisor)}</RazonSocialEmisor>
    </Emisor>${comprador}
    <Totales>
      <MontoTotal>${xmlEscape(formatMoney(montoTotal))}</MontoTotal>
    </Totales>
  </Encabezado>
  <DetallesItems>
    <Item>
      <NumeroLinea>1</NumeroLinea>
      <NombreItem>${xmlEscape(mapped.descripcion)}</NombreItem>
      <CantidadItem>1.00</CantidadItem>
      <PrecioUnitarioItem>${xmlEscape(formatMoney(montoTotal))}</PrecioUnitarioItem>
      <MontoItem>${xmlEscape(formatMoney(montoTotal))}</MontoItem>
    </Item>
  </DetallesItems>
  <FechaHoraFirma>${xmlEscape(signatureTimestamp())}</FechaHoraFirma>
</eCF>`;

    return { xml, warnings: mapped.warnings };
  }

  buildRfceXmlFromCertificationCase(input: { rawRowJson: unknown }): CertificationXmlBuildResult {
    const row = caseRow(input);
    const mapped = collectCommon(row);
    // TODO: Complete RFCE structure after confirming official DGII RecepcionFC workbook/XSD mapping.
    throw {
      status: 409,
      message: 'RFCE XML generation is not fully mapped yet.',
      errorCode: 'DGII_CERTIFICATION_RFCE_XML_NOT_MAPPED',
      details: {
        encf: mapped.encf,
        tipoEcf: mapped.tipoEcf,
        warnings: mapped.warnings,
      },
    };
  }
}

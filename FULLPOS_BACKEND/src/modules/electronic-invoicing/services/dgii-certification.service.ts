import * as path from 'path';
import * as XLSX from 'xlsx';
import { Prisma, PrismaClient } from '@prisma/client';
import env, { normalizeDgiiEnvironmentAlias } from '../../../config/env';
import { ElectronicInvoicingMapperService } from './electronic-invoicing-mapper.service';
import { normalizeRnc } from '../utils/validation.utils';
import { DgiiCertificationXmlBuilderService } from './dgii-certification-xml-builder.service';
import { DgiiCertificationRfceXmlBuilderService } from './dgii-certification-rfce-xml-builder.service';
import { DgiiSignatureService } from './dgii-signature.service';
import { DgiiSubmissionService } from './dgii-submission.service';
import { DgiiResultService } from './dgii-result.service';
import { DgiiDirectoryService } from './dgii-directory.service';
import { DgiiCertificationXmlValidationService } from './dgii-certification-xml-validation.service';
import { DgiiEnvironment } from '../types/dgii.types';
import {
  analyzeCertificateForDgii,
  assertCertificateIsCurrentlyValid,
  loadPkcs12Certificate,
  loadPkcs12CertificateFromBuffer,
  resolveCertificateFilePath,
} from '../utils/certificate.utils';
import {
  decryptBinarySecret,
  decryptSecret,
  INLINE_CERTIFICATE_PREFIX,
  isInlineCertificateReference,
} from '../utils/credential-crypto.utils';
import { deepFindFirstString } from '../utils/xml.utils';
import { parseXml } from '../utils/xml.utils';

type CertificationSheetName = 'ECF' | 'RFCE';

type ImportWarnings = Array<{
  sheetName: CertificationSheetName;
  rowNumber?: number;
  message: string;
}>;

type CertificationCaseFilters = {
  sheetName?: string;
  status?: string;
  tipoEcf?: string;
  search?: string;
};

const REQUIRED_SHEETS: CertificationSheetName[] = ['ECF', 'RFCE'];
const FINAL_CERTIFICATION_STATUSES = new Set(['ACCEPTED', 'ACCEPTED_CONDITIONAL', 'REJECTED']);
const DGII_AUDIT_TOTAL_FIELDS = [
  'MontoGravadoTotal',
  'MontoGravadoI1',
  'MontoGravadoI2',
  'MontoGravadoI3',
  'MontoExento',
  'ITBIS1',
  'ITBIS2',
  'ITBIS3',
  'TotalITBIS',
  'TotalITBIS1',
  'TotalITBIS2',
  'TotalITBIS3',
  'MontoTotal',
  'ValorPagar',
] as const;
const CERTIFICATION_DB_FIELDS = [
  'xmlGenerated',
  'xmlSigned',
  'signedAt',
  'sentAt',
  'resultCheckedAt',
  'dgiiStatusCode',
  'dgiiStatusMessage',
  'rejectionCode',
  'rejectionMessage',
  'xmlValidationStatus',
  'xmlValidationJson',
  'xmlValidatedAt',
  'xsdValidated',
  'xsdValid',
  'xsdError',
];

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

function isEmptyRow(row: Record<string, unknown>) {
  return Object.entries(row)
    .filter(([key]) => !key.startsWith('__'))
    .every(([, value]) => normalizeValue(value) == null);
}

function findField(row: Record<string, unknown>, aliases: string[]) {
  const normalizedAliases = aliases.map(normalizeHeader);
  for (const [key, value] of Object.entries(row)) {
    const normalizedKey = normalizeHeader(key);
    if (normalizedAliases.includes(normalizedKey)) {
      return normalizeValue(value);
    }
  }
  return null;
}

function extractCertificationReferenceEcf(rawRowJson: unknown) {
  const row = rawRowJson && typeof rawRowJson === 'object' && !Array.isArray(rawRowJson)
    ? rawRowJson as Record<string, unknown>
    : {};
  return findField(row, ['ncfModificado', 'NCF Modificado', 'NCFModificado', 'eNCFModificado']);
}

function parseDateValue(value: unknown) {
  if (value == null || value === '') return null;
  if (value instanceof Date && !Number.isNaN(value.getTime())) return value;
  if (typeof value === 'number') {
    const parsed = XLSX.SSF.parse_date_code(value);
    if (parsed) {
      return new Date(Date.UTC(parsed.y, parsed.m - 1, parsed.d));
    }
  }
  const text = String(value).trim();
  if (!text) return null;
  const normalized = text.replace(/^(\d{2})\/(\d{2})\/(\d{4})$/, '$3-$2-$1');
  const parsed = new Date(normalized);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function parseMoney(value: unknown) {
  if (value == null || value === '') return null;
  if (typeof value === 'number' && Number.isFinite(value)) return Math.round(value * 100) / 100;
  const text = String(value)
    .trim()
    .replace(/RD\$|\$|,/gi, '');
  const parsed = Number(text);
  return Number.isFinite(parsed) ? Math.round(parsed * 100) / 100 : null;
}

function serializeCase(item: any) {
  const validation = item.xmlValidationJson && typeof item.xmlValidationJson === 'object' && !Array.isArray(item.xmlValidationJson)
    ? item.xmlValidationJson as Record<string, unknown>
    : {};
  const validationErrors = Array.isArray(validation.errors)
    ? validation.errors.map((value) => String(value))
    : [];
  const validationWarnings = Array.isArray(validation.warnings)
    ? validation.warnings.map((value) => String(value))
    : [];
  const xsdError = typeof validation.xsdError === 'string'
    ? validation.xsdError
    : validationErrors.join('\n');
  return {
    ...item,
    montoTotal: item.montoTotal == null ? null : Number(item.montoTotal),
    xsdFileUsed: typeof validation.xsdFileUsed === 'string' ? validation.xsdFileUsed : null,
    rawXmllintOutput: typeof validation.rawXmllintOutput === 'string'
      ? validation.rawXmllintOutput
      : (xsdError.trim().length > 0 ? xsdError : null),
    validationErrors,
    validationWarnings,
  };
}

function maskUrl(value?: string | null) {
  if (!value) return null;
  try {
    const url = new URL(value);
    const pathParts = url.pathname.split('/').filter(Boolean);
    const visiblePath = pathParts.length > 0 ? `/${pathParts[pathParts.length - 1]}` : '';
    return `${url.protocol}//${url.host}/...${visiblePath}`;
  } catch {
    return value.length <= 18 ? '***' : `${value.slice(0, 12)}...${value.slice(-6)}`;
  }
}

export class DgiiCertificationService {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly mapper: ElectronicInvoicingMapperService,
    private readonly xmlBuilder: DgiiCertificationXmlBuilderService,
    private readonly signatureService: DgiiSignatureService,
    private readonly submissionService: DgiiSubmissionService,
    private readonly resultService: DgiiResultService,
    private readonly directory: DgiiDirectoryService,
    private readonly xmlValidationService: DgiiCertificationXmlValidationService,
    private readonly rfceXmlBuilder: DgiiCertificationRfceXmlBuilderService,
  ) {}

  async resolveCompany(companyRnc?: string | null, companyCloudId?: string | null, requestId?: string) {
    return this.mapper.resolveCompanyOrThrow(companyRnc ?? null, companyCloudId ?? null, {
      preferCloudOnConflict: true,
      requestId,
      source: 'dgii_certification',
    });
  }

  private parseWorkbook(buffer: Buffer) {
    const workbook = XLSX.read(buffer, {
      type: 'buffer',
      cellDates: true,
      raw: false,
    });
    const warnings: ImportWarnings = [];
    const missingSheets = REQUIRED_SHEETS.filter((name) => !workbook.SheetNames.includes(name));
    if (missingSheets.length > 0) {
      throw {
        status: 400,
        message: `El archivo debe contener las hojas ${REQUIRED_SHEETS.join(' y ')}`,
        errorCode: 'DGII_CERTIFICATION_SHEETS_MISSING',
        details: { missingSheets, foundSheets: workbook.SheetNames },
      };
    }

    const cases: Array<{
      sheetName: CertificationSheetName;
      rowNumber: number;
      encf: string | null;
      tipoEcf: string | null;
      rncEmisor: string | null;
      rncComprador: string | null;
      fechaEmision: Date | null;
      montoTotal: number | null;
      rawRowJson: Record<string, unknown>;
    }> = [];
    const sheetStats: Record<CertificationSheetName, { found: number; imported: number; skipped: number }> = {
      ECF: { found: 0, imported: 0, skipped: 0 },
      RFCE: { found: 0, imported: 0, skipped: 0 },
    };

    for (const sheetName of REQUIRED_SHEETS) {
      const worksheet = workbook.Sheets[sheetName];
      const matrix = XLSX.utils.sheet_to_json<Array<unknown>>(worksheet, {
        header: 1,
        defval: null,
        raw: false,
      });
      const headerRow = (matrix[0] ?? []) as Array<unknown>;
      const headers = headerRow.map((value, index) => {
        const base = normalizeValue(value) ?? `Column_${index + 1}`;
        return base;
      });
      const rows = matrix.slice(1);
      sheetStats[sheetName].found = rows.length;

      rows.forEach((rowCells, index) => {
        const rowNumber = index + 2;
        const rawRow: Record<string, unknown> = {};
        const normalizedRow: Record<string, unknown> = {};
        const headerUsage = new Map<string, number>();
        headers.forEach((header, headerIndex) => {
          const usage = (headerUsage.get(header) ?? 0) + 1;
          headerUsage.set(header, usage);
          const uniqueHeader = usage > 1 ? `${header}__${usage}` : header;
          const cellValue = (rowCells as Array<unknown>)[headerIndex] ?? null;
          rawRow[uniqueHeader] = cellValue;
          normalizedRow[normalizeHeader(uniqueHeader)] = cellValue;
        });
        rawRow.__sheetName = sheetName;
        rawRow.__rowNumber = rowNumber;
        rawRow.__headers = headers;
        rawRow.__cells = rowCells as Array<unknown>;
        rawRow.__normalized = normalizedRow;
        if (isEmptyRow(rawRow)) {
          sheetStats[sheetName].skipped += 1;
          return;
        }

        const encf = findField(rawRow, ['encf', 'eNCF', 'NCF', 'comprobante']);
        const tipoEcf = findField(rawRow, ['tipoEcf', 'TipoCF', 'tipo comprobante', 'tipo eCF', 'tipo']);
        const rncEmisor = normalizeRnc(findField(rawRow, ['rncEmisor', 'RNC Emisor', 'RNC del Emisor']));
        const rncComprador = normalizeRnc(findField(rawRow, ['rncComprador', 'RNC Comprador', 'RNC del Comprador']));
        const fechaRaw = findField(rawRow, ['fechaEmision', 'Fecha Emision', 'Fecha de Emision', 'Fecha']);
        const montoRaw = findField(rawRow, ['montoTotal', 'Monto Total', 'Total', 'Monto']);
        const fechaEmision = parseDateValue(fechaRaw);
        const montoTotal = parseMoney(montoRaw);

        if (!encf) warnings.push({ sheetName, rowNumber, message: 'No se detecto eNCF/NCF/comprobante' });
        if (!tipoEcf) warnings.push({ sheetName, rowNumber, message: 'No se detecto tipo de e-CF' });
        if (!fechaEmision && fechaRaw) warnings.push({ sheetName, rowNumber, message: 'Fecha de emision no parseable' });
        if (montoTotal == null && montoRaw) warnings.push({ sheetName, rowNumber, message: 'Monto total no parseable' });

        cases.push({
          sheetName,
          rowNumber,
          encf,
          tipoEcf,
          rncEmisor,
          rncComprador,
          fechaEmision,
          montoTotal,
          rawRowJson: rawRow,
        });
        sheetStats[sheetName].imported += 1;
      });
    }

    return { cases, sheetStats, warnings };
  }

  async importExcel(input: {
    companyId: number;
    companyRnc?: string | null;
    fileName: string;
    buffer: Buffer;
    requestId?: string;
  }) {
    const extension = path.extname(input.fileName).toLowerCase();
    if (extension !== '.xlsx') {
      throw {
        status: 400,
        message: 'El archivo de certificacion DGII debe ser .xlsx',
        errorCode: 'DGII_CERTIFICATION_INVALID_FILE',
      };
    }

    const parsed = this.parseWorkbook(input.buffer);
    if (parsed.cases.length === 0) {
      throw {
        status: 400,
        message: 'No se detectaron casos ECF/RFCE en el archivo',
        errorCode: 'DGII_CERTIFICATION_NO_CASES',
        details: { sheetStats: parsed.sheetStats, warnings: parsed.warnings },
      };
    }

    const batch = await this.prisma.$transaction(async (tx) => {
      const createdBatch = await tx.dgiiCertificationBatch.create({
        data: {
          companyId: input.companyId,
          rnc: normalizeRnc(input.companyRnc),
          fileName: input.fileName,
          status: 'IMPORTED',
          totalCases: parsed.cases.length,
          ecfCases: parsed.sheetStats.ECF.imported,
          rfceCases: parsed.sheetStats.RFCE.imported,
          rawMetadataJson: {
            originalFileName: input.fileName,
            sheetStats: parsed.sheetStats,
            warnings: parsed.warnings,
          },
        },
      });

      await tx.dgiiCertificationCase.createMany({
        data: parsed.cases.map((item) => ({
          batchId: createdBatch.id,
          companyId: input.companyId,
          sheetName: item.sheetName,
          rowNumber: item.rowNumber,
          encf: item.encf,
          tipoEcf: item.tipoEcf,
          rncEmisor: item.rncEmisor,
          rncComprador: item.rncComprador,
          fechaEmision: item.fechaEmision,
          montoTotal: item.montoTotal,
          rawRowJson: item.rawRowJson as Prisma.InputJsonObject,
          status: 'IMPORTED',
        })),
      });

      return createdBatch;
    });

    console.info('[electronic-invoicing.certification] excel.imported', {
      requestId: input.requestId ?? null,
      companyId: input.companyId,
      rnc: normalizeRnc(input.companyRnc),
      fileName: input.fileName,
      rowsFoundEcf: parsed.sheetStats.ECF.found,
      rowsFoundRfce: parsed.sheetStats.RFCE.found,
      rowsImported: parsed.cases.length,
      rowsSkipped: parsed.sheetStats.ECF.skipped + parsed.sheetStats.RFCE.skipped,
      warnings: parsed.warnings,
    });

    return {
      batch,
      imported: parsed.cases.length,
      warnings: parsed.warnings,
    };
  }

  async listBatches(companyId: number) {
    return this.prisma.dgiiCertificationBatch.findMany({
      where: { companyId },
      orderBy: { uploadedAt: 'desc' },
    });
  }

  async getBatch(companyId: number, id: number) {
    const batch = await this.prisma.dgiiCertificationBatch.findFirst({
      where: { id, companyId },
    });
    if (!batch) {
      throw { status: 404, message: 'Lote de certificacion no encontrado', errorCode: 'DGII_CERTIFICATION_BATCH_NOT_FOUND' };
    }
    return batch;
  }

  async listCases(companyId: number, batchId: number, filters: CertificationCaseFilters) {
    await this.getBatch(companyId, batchId);
    const cases = await this.prisma.dgiiCertificationCase.findMany({
      where: {
        companyId,
        batchId,
        ...(filters.sheetName ? { sheetName: filters.sheetName.toUpperCase() } : {}),
        ...(filters.status ? { status: filters.status.toUpperCase() } : {}),
        ...(filters.tipoEcf ? { tipoEcf: filters.tipoEcf } : {}),
        ...(filters.search ? { encf: { contains: filters.search, mode: 'insensitive' } } : {}),
      },
      orderBy: [{ sheetName: 'asc' }, { rowNumber: 'asc' }],
    });
    return cases.map(serializeCase);
  }

  async getCase(companyId: number, id: number) {
    const item = await this.prisma.dgiiCertificationCase.findFirst({
      where: { id, companyId },
    });
    if (!item) {
      throw { status: 404, message: 'Caso de certificacion no encontrado', errorCode: 'DGII_CERTIFICATION_CASE_NOT_FOUND' };
    }
    return serializeCase(item);
  }

  private async getEnvironment(companyId: number): Promise<DgiiEnvironment> {
    const config = await this.prisma.electronicInboundEndpointConfig.findFirst({
      where: { companyId },
      orderBy: [{ branchId: 'asc' }, { updatedAt: 'desc' }],
      select: { environment: true },
    });
    return normalizeDgiiEnvironmentAlias(config?.environment ?? env.DGII_DEFAULT_ENVIRONMENT) as DgiiEnvironment;
  }

  async getCompanyDgiiEnvironment(companyId: number): Promise<DgiiEnvironment> {
    return this.getEnvironment(companyId);
  }

  private async loadActiveCertificate(companyId: number) {
    const certificate = await this.prisma.electronicCertificate.findFirst({
      where: { companyId, status: 'ACTIVE' },
      orderBy: { updatedAt: 'desc' },
    });
    if (!certificate) {
      throw {
        status: 409,
        message: 'La compania no tiene un certificado electronico activo',
        errorCode: 'DGII_CERTIFICATION_CERTIFICATE_NOT_FOUND',
      };
    }

    const password = decryptSecret(certificate.passwordEncrypted);
    const loaded = isInlineCertificateReference(certificate.secretReference)
      ? loadPkcs12CertificateFromBuffer(
          decryptBinarySecret(certificate.secretReference!.slice(INLINE_CERTIFICATE_PREFIX.length)),
          password,
        )
      : loadPkcs12Certificate(resolveCertificateFilePath(certificate.filePath, certificate.secretReference), password);
    assertCertificateIsCurrentlyValid(loaded.validFrom, loaded.validTo);
    return { certificate, loaded };
  }

  private assertMutableStatus(item: { status: string }) {
    if (FINAL_CERTIFICATION_STATUSES.has(item.status)) {
      throw {
        status: 409,
        message: 'Este caso ya tiene resultado final DGII. Regenerar/reiniciar debe hacerse explicitamente.',
        errorCode: 'DGII_CERTIFICATION_FINAL_CASE_LOCKED',
      };
    }
  }

  private validationStatus(validation: ReturnType<DgiiCertificationXmlValidationService['validate']>) {
    if (!validation.wellFormed) return 'XML_INVALID';
    if (validation.xsdValidated && validation.valid) return 'XSD_VALID';
    if (validation.xsdValidated && !validation.valid) return 'XSD_INVALID';
    return 'XSD_NOT_AVAILABLE';
  }

  private validationPersistenceData(validation: ReturnType<DgiiCertificationXmlValidationService['validate']>) {
    return {
      xmlValidationStatus: this.validationStatus(validation),
      xmlValidationJson: validation as unknown as Prisma.InputJsonObject,
      xmlValidatedAt: new Date(),
      xsdValidated: validation.xsdValidated,
      xsdValid: validation.xsdValidated && validation.valid,
      xsdError: validation.xsdError ?? (validation.xsdValidated && !validation.valid ? validation.errors.join('\n') : null),
    };
  }

  private buildIssuerFallback(item: any) {
    const companyConfig = item.company?.config ?? null;
    return {
      rnc: item.company?.rnc ?? null,
      legalName: item.company?.name ?? null,
      businessName: item.company?.name ?? null,
      tradeName: null,
      address: companyConfig?.address ?? null,
      municipality: companyConfig?.city ?? null,
      province: null,
      email: companyConfig?.email ?? null,
      website: companyConfig?.website ?? null,
    };
  }

  private buildXmlGenerationFailureDetails(item: any, details: any) {
    const missingFields = Array.isArray(details?.missingFields)
      ? details.missingFields.map((value: unknown) => String(value))
      : [];
    const humanReadableMessage = details?.humanReadableMessage?.toString() ??
      (missingFields.length > 0
        ? `Faltan campos obligatorios: ${missingFields.join(', ')}`
        : (details?.message?.toString() ?? 'No se pudo generar XML para el caso de certificacion'));
    const rawRowJson = item.rawRowJson && typeof item.rawRowJson === 'object' && !Array.isArray(item.rawRowJson)
      ? item.rawRowJson as Record<string, unknown>
      : {};
    return {
      type: 'XML_GENERATION_REQUIRED_FIELDS',
      caseId: item.id,
      eNCF: item.encf ?? null,
      tipoEcf: item.tipoEcf ?? null,
      sheetName: item.sheetName ?? null,
      missingFields,
      extractedFields: details?.extractedFields ?? {},
      fallbackFieldsUsed: details?.fallbackFieldsUsed ?? {},
      rawRowKeys: Array.isArray(details?.rawRowKeys) ? details.rawRowKeys : Object.keys(rawRowJson),
      rawRowJsonSummary: Object.fromEntries(Object.entries(rawRowJson).slice(0, 25)),
      warnings: Array.isArray(details?.warnings) ? details.warnings : [],
      errors: Array.isArray(details?.errors) ? details.errors : [],
      sourceFieldsUsed: details?.sourceFieldsUsed ?? {},
      humanReadableMessage,
    };
  }

  private sourceRow(item: { rawRowJson: unknown }) {
    return item.rawRowJson && typeof item.rawRowJson === 'object' && !Array.isArray(item.rawRowJson)
      ? item.rawRowJson as Record<string, unknown>
      : {};
  }

  private certificationFileName(encf: string | null | undefined) {
    const clean = String(encf ?? '').trim().replace(/[^A-Za-z0-9]/g, '');
    return clean ? `${clean}.xml` : null;
  }

  private fileNameIsValid(fileName: string | null) {
    return !!fileName && fileName.length <= 30 && /^[A-Za-z0-9]+\.xml$/.test(fileName);
  }

  private certificationPlaceholderFound(payload: unknown): boolean {
    if (payload == null) return false;
    if (typeof payload === 'string') {
      const normalized = payload.trim().toLowerCase();
      return ['#e', '#n/a', 'n/a', 'null', 'undefined', ''].includes(normalized);
    }
    if (Array.isArray(payload)) return payload.some((item) => this.certificationPlaceholderFound(item));
    if (typeof payload === 'object') return Object.values(payload as Record<string, unknown>).some((item) => this.certificationPlaceholderFound(item));
    return false;
  }

  private auditValueText(value: unknown) {
    if (value == null) return null;
    const text = String(value).trim();
    return text.length > 0 ? text : null;
  }

  private auditMoneyText(value: unknown) {
    const parsed = parseMoney(value);
    return parsed == null ? null : parsed.toFixed(2);
  }

  private auditNodeText(record: Record<string, unknown>, ...keys: string[]) {
    for (const key of keys) {
      const value = record[key];
      const text = this.auditValueText(value);
      if (text != null) return text;
    }
    return null;
  }

  private calculateTotalsFromParsedItems(items: Array<Record<string, unknown>>) {
    let montoGravadoI1 = 0;
    let montoGravadoI2 = 0;
    let montoGravadoI3 = 0;
    let montoExento = 0;
    for (const item of items) {
      const indicador = this.auditValueText(item.IndicadorFacturacion);
      const monto = parseMoney(item.MontoItem);
      if (monto == null) continue;
      if (indicador === '1') montoGravadoI1 += monto;
      else if (indicador === '2') montoGravadoI2 += monto;
      else if (indicador === '3') montoGravadoI3 += monto;
      else if (indicador === '4') montoExento += monto;
    }
    const totalItbis1 = Math.round(montoGravadoI1 * 0.18 * 100) / 100;
    const totalItbis2 = Math.round(montoGravadoI2 * 0.16 * 100) / 100;
    const totalItbis3 = 0;
    const totalItbis = Math.round((totalItbis1 + totalItbis2 + totalItbis3) * 100) / 100;
    const montoGravadoTotal = Math.round((montoGravadoI1 + montoGravadoI2 + montoGravadoI3) * 100) / 100;
    const montoTotal = Math.round((montoGravadoTotal + montoExento + totalItbis) * 100) / 100;
    return {
      MontoGravadoTotal: montoGravadoTotal.toFixed(2),
      MontoGravadoI1: montoGravadoI1.toFixed(2),
      MontoGravadoI2: montoGravadoI2.toFixed(2),
      MontoGravadoI3: montoGravadoI3.toFixed(2),
      MontoExento: montoExento.toFixed(2),
      ITBIS1: montoGravadoI1 > 0 ? '18' : null,
      ITBIS2: montoGravadoI2 > 0 ? '16' : null,
      ITBIS3: montoGravadoI3 > 0 ? '0' : null,
      TotalITBIS: totalItbis.toFixed(2),
      TotalITBIS1: totalItbis1.toFixed(2),
      TotalITBIS2: totalItbis2.toFixed(2),
      TotalITBIS3: totalItbis3.toFixed(2),
      MontoTotal: montoTotal.toFixed(2),
      ValorPagar: montoTotal.toFixed(2),
    } satisfies Record<string, string | null>;
  }

  private auditSourceTotals(rawRowJson: unknown) {
    const row = this.sourceRow({ rawRowJson });
    const totals: Record<string, string | null> = {};
    const aliases: Record<string, string[]> = {
      MontoGravadoTotal: ['montoGravadoTotal', 'monto gravado total'],
      MontoGravadoI1: ['montoGravadoI1', 'monto gravado i1'],
      MontoGravadoI2: ['montoGravadoI2', 'monto gravado i2'],
      MontoGravadoI3: ['montoGravadoI3', 'monto gravado i3'],
      MontoExento: ['montoExento', 'monto exento'],
      ITBIS1: ['ITBIS1', 'itbis1'],
      ITBIS2: ['ITBIS2', 'itbis2'],
      ITBIS3: ['ITBIS3', 'itbis3'],
      TotalITBIS: ['totalITBIS', 'Total ITBIS', 'itbisTotal'],
      TotalITBIS1: ['totalITBIS1', 'total itbis 1'],
      TotalITBIS2: ['totalITBIS2', 'total itbis 2'],
      TotalITBIS3: ['totalITBIS3', 'total itbis 3'],
      MontoTotal: ['montoTotal', 'Monto Total', 'Total', 'TotalFactura'],
      ValorPagar: ['valorPagar', 'valor pagar'],
    };
    for (const field of DGII_AUDIT_TOTAL_FIELDS) {
      const raw = findField(row, aliases[field] ?? [field]);
      totals[field] = field.startsWith('ITBIS') && field.length === 6
        ? this.auditValueText(raw)
        : this.auditMoneyText(raw);
    }
    return totals;
  }

  private parseXmlTotals(xml: string) {
    const parsed = parseXml(xml) as Record<string, unknown>;
    const root = (parsed.ECF ?? parsed.eCF ?? parsed.RFCE ?? parsed) as Record<string, unknown>;
    const encabezado = (root.Encabezado ?? {}) as Record<string, unknown>;
    const totales = (encabezado.Totales ?? {}) as Record<string, unknown>;
    const detalles = (root.DetallesItems ?? {}) as Record<string, unknown>;
    const rawItems = (detalles.Item ?? []) as unknown;
    const items = Array.isArray(rawItems)
      ? rawItems.filter((item): item is Record<string, unknown> => !!item && typeof item === 'object')
      : rawItems && typeof rawItems === 'object'
        ? [rawItems as Record<string, unknown>]
        : [];
    const xmlTotals: Record<string, string | null> = {};
    for (const field of DGII_AUDIT_TOTAL_FIELDS) {
      xmlTotals[field] = field.startsWith('ITBIS') && field.length === 6
        ? this.auditNodeText(totales, field)
        : this.auditMoneyText(totales[field]);
    }
    return {
      parsed,
      items,
      xmlTotals,
      calculatedTotals: this.calculateTotalsFromParsedItems(items),
    };
  }

  private summarizeAuditStatus(aptoParaEnviar: boolean, errors: string[], warnings: string[]) {
    if (aptoParaEnviar) return { status: 'APTO PARA ENVIAR', summary: 'La auditoría técnica no detectó bloqueos para DGII.' };
    if (errors.length > 0) return { status: 'NO APTO PARA ENVIAR', summary: errors[0] };
    if (warnings.length > 0) return { status: 'REQUIERE CORRECCIÓN', summary: warnings[0] };
    return { status: 'NO APTO PARA ENVIAR', summary: 'La auditoría detectó inconsistencias.' };
  }

  private async runDeterministicAudit(item: {
    id: number;
    companyId: number;
    encf: string | null;
    tipoEcf: string | null;
    xmlGenerated: string | null;
    xmlSigned: string | null;
    rawRowJson: unknown;
    xmlValidationJson: unknown;
  }) {
    const warnings: string[] = [];
    const errors: string[] = [];
    const mismatches: Array<{
      field: string;
      excelExpected: string | null;
      xmlGenerated: string | null;
      calculatedFromItems: string | null;
      difference: string | null;
      severity: 'ERROR' | 'WARNING';
    }> = [];

    const filename = this.certificationFileName(item.encf);
    const filenameValid = this.fileNameIsValid(filename);
    if (!filenameValid) {
      errors.push('El nombre de archivo DGII no es válido.');
    }

    if (!item.xmlGenerated?.trim()) {
      errors.push('El caso aún no tiene XML generado.');
    }

    const excelValues = this.auditSourceTotals(item.rawRowJson);
    let xmlValues: Record<string, string | null> = {};
    let calculatedValues: Record<string, string | null> = {};
    let parsedXml: Record<string, unknown> = {};
    let items: Array<Record<string, unknown>> = [];

    let xsdValid = false;
    if (item.xmlGenerated?.trim()) {
      const validation = this.xmlValidationService.validate(item.xmlGenerated);
      xsdValid = validation.xsdValidated && validation.valid;
      if (!xsdValid) {
        errors.push('El XML generado no valida contra el XSD DGII.');
      }
      const parsed = this.parseXmlTotals(item.xmlGenerated);
      parsedXml = parsed.parsed;
      items = parsed.items;
      xmlValues = parsed.xmlTotals;
      calculatedValues = parsed.calculatedTotals;
    }

    for (const field of DGII_AUDIT_TOTAL_FIELDS) {
      const excelExpected = excelValues[field] ?? null;
      const xmlGenerated = xmlValues[field] ?? null;
      const calculatedFromItems = calculatedValues[field] ?? null;
      const diff = excelExpected && calculatedFromItems
        ? (() => {
            const left = parseMoney(excelExpected);
            const right = parseMoney(calculatedFromItems);
            if (left == null || right == null) return excelExpected === calculatedFromItems ? null : `${excelExpected} vs ${calculatedFromItems}`;
            const delta = Math.round((left - right) * 100) / 100;
            return Math.abs(delta) > 0.0001 ? delta.toFixed(2) : null;
          })()
        : excelExpected === calculatedFromItems ? null : null;
      if (excelExpected && xmlGenerated && excelExpected !== xmlGenerated) {
        mismatches.push({ field, excelExpected, xmlGenerated, calculatedFromItems, difference: diff, severity: 'ERROR' });
      }
      if (excelExpected && calculatedFromItems && excelExpected !== calculatedFromItems) {
        mismatches.push({ field, excelExpected, xmlGenerated, calculatedFromItems, difference: diff, severity: 'ERROR' });
      }
    }

    if (mismatches.length > 0) {
      errors.push('Los totales del XML no coinciden exactamente con los valores esperados del Excel.');
    }

    const requiredFieldsPresent = !this.certificationPlaceholderFound((item.xmlValidationJson as any)?.missingFields ?? null);
    const noPlaceholders = !this.certificationPlaceholderFound(item.rawRowJson) && !this.certificationPlaceholderFound(item.xmlGenerated);
    if (!noPlaceholders) {
      errors.push('Se detectaron placeholders inválidos (#e, null, N/A, etc.).');
    }

    const totalsMatchExcel = mismatches.every((item) => item.severity !== 'ERROR');
    const totalsMatchItems = mismatches.every((item) => item.field.startsWith('ITBIS') ? true : item.severity !== 'ERROR');
    const aptoParaEnviar = filenameValid && xsdValid && requiredFieldsPresent && noPlaceholders && totalsMatchExcel && totalsMatchItems;
    const summaryStatus = this.summarizeAuditStatus(aptoParaEnviar, errors, warnings);

    return {
      caseId: item.id,
      eNCF: item.encf,
      tipoEcf: item.tipoEcf,
      filename,
      filenameValid,
      xsdValid,
      requiredFieldsPresent,
      noPlaceholders,
      totalsMatchExcel,
      totalsMatchItems,
      aptoParaEnviar,
      status: summaryStatus.status,
      summary: summaryStatus.summary,
      warnings,
      errors,
      mismatches,
      excelValues,
      xmlValues,
      calculatedValues,
      raw: {
        parsedXml,
        itemCount: items.length,
        xmlValidationJson: item.xmlValidationJson ?? null,
      },
      signatureStatus: item.xmlSigned?.trim() ? 'SIGNED' : 'UNSIGNED',
    };
  }

  private async maybeExplainAuditWithAi(
    audit: Record<string, unknown>,
    aiApiKey?: string | null,
    aiModel?: string | null,
  ) {
    const key = aiApiKey?.trim();
    if (!key) {
      return {
        providerConfigured: false,
        message: 'IA no configurada, se mostró auditoría técnica.',
      };
    }
    try {
      const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${key}`,
        },
        body: JSON.stringify({
          model: aiModel?.trim() || 'gpt-4.1-mini',
          response_format: { type: 'json_object' },
          messages: [
            {
              role: 'system',
              content: 'Eres un auditor técnico de DGII e-CF. Responde JSON con: resumen, erroresCriticos, diferenciasExcelVsXml, diferenciasTotalesVsItems, camposFaltantes, riesgoDgii, recomendacionExacta, aptoParaEnviar.',
            },
            {
              role: 'user',
              content: JSON.stringify(audit),
            },
          ],
        }),
      });
      const decoded = await response.json() as any;
      const content = decoded?.choices?.[0]?.message?.content;
      const parsed = typeof content === 'string' ? JSON.parse(content) : {};
      return {
        providerConfigured: true,
        ...parsed,
      };
    } catch (error) {
      return {
        providerConfigured: true,
        message: 'IA configurada, pero no se pudo generar la explicación. Se mostró auditoría técnica.',
        providerError: error instanceof Error ? error.message : String(error),
      };
    }
  }

  private async detectCertificationDbFields() {
    const tableName = 'DgiiCertificationCase';
    const prismaModel = Prisma.dmmf.datamodel.models.find((model) => model.name === 'DgiiCertificationCase');
    const prismaFieldNames = new Set((prismaModel?.fields ?? []).map((field) => field.name));
    const prismaClientHasNewFields = CERTIFICATION_DB_FIELDS.every((field) => prismaFieldNames.has(field));
    let databaseHasNewFields: boolean | null = null;
    let databaseCheckError: string | null = null;
    let dbColumnsFound: string[] = [];
    let missingDbColumns: string[] = [...CERTIFICATION_DB_FIELDS];
    try {
      const rows = await this.prisma.$queryRawUnsafe<Array<{ table_schema: string; column_name: string }>>(
        `SELECT table_schema, column_name
           FROM information_schema.columns
          WHERE table_name = $1
          ORDER BY table_schema, ordinal_position`,
        tableName,
      );
      dbColumnsFound = [...new Set(rows.map((row) => row.column_name))];
      const dbFields = new Set(dbColumnsFound);
      missingDbColumns = CERTIFICATION_DB_FIELDS.filter((field) => !dbFields.has(field));
      databaseHasNewFields = CERTIFICATION_DB_FIELDS.every((field) => dbFields.has(field));
      console.info('[electronic-invoicing.certification] database.migration_column_check', {
        tableNameChecked: tableName,
        tableSchemasFound: [...new Set(rows.map((row) => row.table_schema))],
        columnsFound: dbColumnsFound,
        requiredColumns: CERTIFICATION_DB_FIELDS,
        missingColumns: missingDbColumns,
        databaseHasNewFields,
      });
    } catch (error) {
      databaseCheckError = error instanceof Error ? error.message : 'No se pudo verificar la base de datos real';
      console.warn('[electronic-invoicing.certification] database.migration_column_check_failed', {
        tableNameChecked: tableName,
        requiredColumns: CERTIFICATION_DB_FIELDS,
        error: databaseCheckError,
      });
    }
    return { prismaClientHasNewFields, databaseHasNewFields, databaseCheckError, dbColumnsFound, missingDbColumns };
  }

  private async hasActiveCertificationCertificate(companyId?: number) {
    try {
      const certificate = await this.prisma.electronicCertificate.findFirst({
        where: { status: 'ACTIVE', ...(companyId ? { companyId } : {}) },
        orderBy: { updatedAt: 'desc' },
        select: { id: true, validFrom: true, validTo: true },
      });
      const now = Date.now();
      return !!certificate && certificate.validFrom.getTime() <= now && certificate.validTo.getTime() >= now;
    } catch {
      return false;
    }
  }

  private dgiiSubmitConfigDiagnostics(environment: DgiiEnvironment) {
    const production = environment === 'production';
    const submitBlockers: string[] = [];
    const configured = production
      ? {
          allowProduction: env.DGII_ALLOW_PRODUCTION === true,
          ecfEndpoint: !!(env.DGII_PRODUCTION_RECEPCION_ECF_URL?.trim() || env.DGII_PRODUCTION_SUBMIT_URL?.trim()),
          fcEndpoint: !!env.DGII_PRODUCTION_RECEPCION_FC_URL?.trim(),
          resultEndpoint: !!env.DGII_PRODUCTION_RESULT_URL_TEMPLATE?.trim(),
          authSeed: !!env.DGII_PRODUCTION_AUTH_SEED_URL?.trim(),
          authValidate: !!env.DGII_PRODUCTION_AUTH_VALIDATE_URL?.trim(),
          bearerToken: !!env.DGII_PRODUCTION_BEARER_TOKEN?.trim(),
        }
      : {
          allowProduction: true,
          ecfEndpoint: !!(env.DGII_PRECERT_RECEPCION_ECF_URL?.trim() || env.DGII_PRECERT_SUBMIT_URL?.trim()),
          fcEndpoint: !!env.DGII_PRECERT_RECEPCION_FC_URL?.trim(),
          resultEndpoint: !!env.DGII_PRECERT_RESULT_URL_TEMPLATE?.trim(),
          authSeed: !!env.DGII_PRECERT_AUTH_SEED_URL?.trim(),
          authValidate: !!env.DGII_PRECERT_AUTH_VALIDATE_URL?.trim(),
          bearerToken: !!env.DGII_PRECERT_BEARER_TOKEN?.trim(),
        };
    const keys = production
      ? {
          allowProduction: 'DGII_ALLOW_PRODUCTION',
          ecfEndpoint: 'DGII_PRODUCTION_RECEPCION_ECF_URL or DGII_PRODUCTION_SUBMIT_URL',
          fcEndpoint: 'DGII_PRODUCTION_RECEPCION_FC_URL',
          resultEndpoint: 'DGII_PRODUCTION_RESULT_URL_TEMPLATE',
          authSeed: 'DGII_PRODUCTION_AUTH_SEED_URL',
          authValidate: 'DGII_PRODUCTION_AUTH_VALIDATE_URL',
          bearerToken: 'DGII_PRODUCTION_BEARER_TOKEN',
        }
      : {
          allowProduction: 'DGII_ALLOW_PRODUCTION',
          ecfEndpoint: 'DGII_PRECERT_RECEPCION_ECF_URL or DGII_PRECERT_SUBMIT_URL',
          fcEndpoint: 'DGII_PRECERT_RECEPCION_FC_URL',
          resultEndpoint: 'DGII_PRECERT_RESULT_URL_TEMPLATE',
          authSeed: 'DGII_PRECERT_AUTH_SEED_URL',
          authValidate: 'DGII_PRECERT_AUTH_VALIDATE_URL',
          bearerToken: 'DGII_PRECERT_BEARER_TOKEN',
        };
    if (!configured.allowProduction) submitBlockers.push(`PRODUCTION_DISABLED:${keys.allowProduction}`);
    if (!configured.ecfEndpoint) submitBlockers.push(`ECF_ENDPOINT_MISSING:${keys.ecfEndpoint}`);
    if (!configured.fcEndpoint) submitBlockers.push(`RFCE_ENDPOINT_MISSING:${keys.fcEndpoint}`);
    if (!configured.resultEndpoint) submitBlockers.push(`RESULT_ENDPOINT_MISSING:${keys.resultEndpoint}`);
    const dgiiAuthConfigExists = configured.bearerToken || (configured.authSeed && configured.authValidate);
    if (!dgiiAuthConfigExists) {
      submitBlockers.push(`DGII_AUTH_CONFIG_MISSING:${keys.authSeed}, ${keys.authValidate} or ${keys.bearerToken}`);
    }
    return {
      dgiiEndpointConfigExists: configured.allowProduction && configured.ecfEndpoint && configured.fcEndpoint && configured.resultEndpoint,
      dgiiAuthConfigExists,
      submitBlockers,
      requiredEndpointConfigKeys: [keys.ecfEndpoint, keys.fcEndpoint, keys.resultEndpoint],
      requiredAuthConfigKeys: [`${keys.authSeed} + ${keys.authValidate}`, keys.bearerToken],
    };
  }

  private async dgiiAuthCacheDiagnostics(companyId: number | undefined, environment: DgiiEnvironment) {
    if (!companyId) {
      return {
        dgiiAuthTokenValid: false,
        dgiiAuthLastErrorCode: null as string | null,
        dgiiAuthLastErrorMessage: null as string | null,
        dgiiAuthLastErrorAt: null as Date | null,
        dgiiAuthTokenExpiresAt: null as Date | null,
      };
    }
    const cache = await this.prisma.electronicDgiiTokenCache.findUnique({
      where: { companyId_environment: { companyId, environment } },
      select: {
        expiresAt: true,
        updatedAt: true,
        lastErrorCode: true,
        lastErrorMessage: true,
      },
    }).catch(() => null);
    const expiresAt = cache?.expiresAt ?? null;
    const hasLiveToken = !!expiresAt && expiresAt.getTime() > Date.now() + 60_000;
    const hasAuthError = !!cache?.lastErrorCode || !!cache?.lastErrorMessage;
    return {
      dgiiAuthTokenValid: hasLiveToken && !hasAuthError,
      dgiiAuthLastErrorCode: cache?.lastErrorCode ?? null,
      dgiiAuthLastErrorMessage: cache?.lastErrorMessage ?? null,
      dgiiAuthLastErrorAt: hasAuthError ? cache?.updatedAt ?? null : null,
      dgiiAuthTokenExpiresAt: expiresAt,
    };
  }

  async buildDiagnostics(companyId?: number) {
    const migrationWarning = 'La migración de certificación DGII no está aplicada en la base de datos real.';
    const db = await this.detectCertificationDbFields();

    const xsd = this.xmlValidationService.diagnostics();
    const rfceGenerationAvailable = true;
    const ecfGenerationAvailable = true;
    const pendingMigrationWarning = db.databaseHasNewFields === false ? migrationWarning : null;
    const environment = companyId
      ? await this.getEnvironment(companyId)
      : normalizeDgiiEnvironmentAlias(env.DGII_DEFAULT_ENVIRONMENT) as DgiiEnvironment;
    const submitConfig = this.dgiiSubmitConfigDiagnostics(environment);
    const authCache = await this.dgiiAuthCacheDiagnostics(companyId, environment);
    const activeCertificateExists = await this.hasActiveCertificationCertificate(companyId);
    const caseWhere = companyId ? { companyId } : {};
    const [totalCasesCount, signedCasesCount, signableCasesCount, lastSigningErrorCase] = await Promise.all([
      this.prisma.dgiiCertificationCase.count({ where: caseWhere }).catch(() => 0),
      this.prisma.dgiiCertificationCase.count({
        where: {
          ...caseWhere,
          OR: [
            { status: 'SIGNED' },
            { xmlSigned: { not: null } },
            { signedAt: { not: null } },
          ],
        },
      }).catch(() => 0),
      this.prisma.dgiiCertificationCase.count({
        where: {
          ...caseWhere,
          xmlGenerated: { not: null },
          xmlSigned: null,
          xmlValidationStatus: 'XSD_VALID',
        },
      }).catch(() => 0),
      this.prisma.dgiiCertificationCase.findFirst({
        where: { ...caseWhere, status: 'ERROR', errorMessage: { not: null } },
        orderBy: { updatedAt: 'desc' },
        select: { errorMessage: true, encf: true, updatedAt: true },
      }).catch(() => null),
    ]);
    const signingEngineAvailable = typeof this.signatureService.signXml === 'function';
    const certificateConfigured = activeCertificateExists;
    const canSignCertification = signingEngineAvailable && certificateConfigured && (signedCasesCount > 0 || signableCasesCount > 0);
    const submitBlockers = [...submitConfig.submitBlockers];
    if (db.databaseHasNewFields !== true) submitBlockers.push('DB_MIGRATION_NOT_APPLIED');
    if (xsd.xsdFilesFound <= 0) submitBlockers.push('XSD_FILES_MISSING:resources/dgii/xsd/*.xsd');
    if (!xsd.xsdValidationEngineAvailable) submitBlockers.push('XSD_ENGINE_MISSING:xmllint');
    if (!certificateConfigured) submitBlockers.push('CERTIFICATE_MISSING:active electronic certificate');
    if (signedCasesCount <= 0) submitBlockers.push('SIGNED_CASES_MISSING');
    if (authCache.dgiiAuthLastErrorCode || authCache.dgiiAuthLastErrorMessage) {
      submitBlockers.push(`DGII_AUTH_VALIDATION_FAILED:${authCache.dgiiAuthLastErrorCode ?? 'DGII_AUTH_LAST_ERROR'}`);
    }
    const canSubmitToDgii = db.databaseHasNewFields === true &&
      xsd.xsdFilesFound > 0 &&
      xsd.xsdValidationEngineAvailable &&
      ecfGenerationAvailable &&
      rfceGenerationAvailable &&
      submitConfig.dgiiEndpointConfigExists &&
      submitConfig.dgiiAuthConfigExists &&
      !authCache.dgiiAuthLastErrorCode &&
      !authCache.dgiiAuthLastErrorMessage &&
      certificateConfigured &&
      signedCasesCount > 0;

    return {
      prismaClientHasNewFields: db.prismaClientHasNewFields,
      databaseHasNewFields: db.databaseHasNewFields,
      pendingMigrationWarning,
      migrationWarning: pendingMigrationWarning,
      databaseCheckError: db.databaseCheckError,
      databaseColumnsFound: db.dbColumnsFound,
      missingDatabaseColumns: db.missingDbColumns,
      xsdDirectoryExists: xsd.xsdDirectoryExists,
      xsdFilesFound: xsd.xsdFilesFound,
      xsdFiles: xsd.xsdFiles,
      xsdValidationEngineAvailable: xsd.xsdValidationEngineAvailable,
      xsdValidationEngine: xsd.xsdValidationEngine,
      ecfGenerationAvailable,
      rfceGenerationAvailable,
      dgiiEndpointConfigExists: submitConfig.dgiiEndpointConfigExists,
      dgiiAuthConfigExists: submitConfig.dgiiAuthConfigExists,
      dgiiAuthTokenValid: authCache.dgiiAuthTokenValid,
      dgiiAuthLastErrorCode: authCache.dgiiAuthLastErrorCode,
      dgiiAuthLastErrorMessage: authCache.dgiiAuthLastErrorMessage,
      dgiiAuthLastErrorAt: authCache.dgiiAuthLastErrorAt,
      dgiiAuthTokenExpiresAt: authCache.dgiiAuthTokenExpiresAt,
      activeCertificateExists,
      signingEngineAvailable,
      certificateConfigured,
      signedCasesCount,
      totalCasesCount,
      lastSigningError: lastSigningErrorCase
        ? {
            encf: lastSigningErrorCase.encf,
            message: lastSigningErrorCase.errorMessage,
            updatedAt: lastSigningErrorCase.updatedAt,
          }
        : null,
      canSignCertification,
      canSubmitToDgii,
      submitBlockers,
      requiredEndpointConfigKeys: submitConfig.requiredEndpointConfigKeys,
      requiredAuthConfigKeys: submitConfig.requiredAuthConfigKeys,
    };
  }

  private certificationStatusFromSubmit(result: Awaited<ReturnType<DgiiSubmissionService['submit']>>) {
    if (result.normalizedStatus === 'rejected') return 'REJECTED';
    if (result.normalizedStatus === 'accepted') return 'SENT';
    if (result.normalizedStatus === 'accepted_conditional') return 'SENT';
    if (result.trackId || result.normalizedStatus === 'pending') return 'SENT';
    return 'ERROR';
  }

  private certificationStatusFromResult(result: Awaited<ReturnType<DgiiResultService['query']>>) {
    if (result.normalizedStatus === 'accepted') return 'ACCEPTED';
    if (result.normalizedStatus === 'accepted_conditional') return 'ACCEPTED_CONDITIONAL';
    if (result.normalizedStatus === 'rejected') return 'REJECTED';
    if (result.normalizedStatus === 'pending') return 'EN_PROCESO';
    return 'ERROR';
  }

  private buildRawResponse(result: {
    httpStatus: number;
    ok: boolean;
    normalizedStatus: string;
    code?: string;
    message?: string;
    dgiiEndpoint?: string;
    responseContentType?: string;
    responseHeaders?: Record<string, string>;
    rawText?: string;
    raw: unknown;
  }): Prisma.InputJsonObject {
    return {
      httpStatus: result.httpStatus,
      ok: result.ok,
      normalizedStatus: result.normalizedStatus,
      code: result.code ?? null,
      message: result.message ?? null,
      dgiiEndpoint: result.dgiiEndpoint ?? null,
      responseContentType: result.responseContentType ?? null,
      responseHeaders: result.responseHeaders ?? null,
      rawText: result.rawText ?? null,
      raw: result.raw as Prisma.InputJsonValue,
    };
  }

  private extractRejectionCode(raw: unknown, fallback?: string) {
    return deepFindFirstString(raw, ['Codigo', 'codigo', 'Code', 'code', 'CodigoError', 'codigoError']) ?? fallback ?? null;
  }

  private extractRejectionMessage(raw: unknown, fallback?: string) {
    return deepFindFirstString(raw, ['Mensaje', 'mensaje', 'Descripcion', 'descripcion', 'Message', 'message', 'Detalle', 'detalle']) ?? fallback ?? null;
  }

  private submissionErrorMessage(result: Awaited<ReturnType<DgiiSubmissionService['submit']>>) {
    if (result.message?.trim()) return result.message.trim();
    if (result.rawText?.trim()) {
      const text = result.rawText.trim().replace(/\s+/g, ' ');
      return text.length > 240 ? `${text.slice(0, 240)}...` : text;
    }
    return 'DGII no devolvio TrackId ni respuesta valida';
  }

  async generateXmlForCase(companyId: number, id: number, requestId?: string) {
    const item = await this.prisma.dgiiCertificationCase.findFirst({
      where: { id, companyId },
      include: { company: { include: { config: true } } },
    });
    if (!item) {
      throw { status: 404, message: 'Caso de certificacion no encontrado', errorCode: 'DGII_CERTIFICATION_CASE_NOT_FOUND' };
    }
    this.assertMutableStatus(item);

    try {
      const result = item.sheetName === 'RFCE'
        ? this.rfceXmlBuilder.buildXmlFromCertificationCase(item)
        : this.xmlBuilder.buildEcfXmlFromCertificationCase({
            rawRowJson: item.rawRowJson,
            issuerFallback: this.buildIssuerFallback(item),
          });
      if (result.errors.length > 0) {
        const details = this.buildXmlGenerationFailureDetails(item, result);
        throw {
          status: 409,
          message: details.humanReadableMessage,
          errorCode: 'DGII_CERTIFICATION_XML_REQUIRED_FIELDS_MISSING',
          details,
        };
      }
      const validation = this.xmlValidationService.validate(result.xml);
      if (!validation.wellFormed) {
        throw {
          status: 409,
          message: 'XML generado no esta bien formado',
          errorCode: 'DGII_CERTIFICATION_XML_NOT_WELL_FORMED',
          details: validation,
        };
      }
      const validationErrorMessage = validation.xsdValidated && !validation.valid
        ? `XSD error: ${validation.xsdError ?? validation.errors[0] ?? 'XSD validation failed'}`
        : null;
      const warningMessage = [
        result.warnings.length > 0 ? `Warnings: ${result.warnings.join('; ')}` : null,
        validationErrorMessage,
      ].filter((value): value is string => !!value).join('; ') || null;
      const updated = await this.prisma.dgiiCertificationCase.update({
        where: { id: item.id },
        data: {
          xmlGenerated: result.xml,
          status: 'XML_GENERATED',
          ...this.validationPersistenceData(validation),
          errorMessage: warningMessage,
        },
      });

      console.info('[electronic-invoicing.certification] xml.generated', {
        requestId: requestId ?? null,
        companyId,
        batchId: item.batchId,
        caseId: item.id,
        sheetName: item.sheetName,
        encf: item.encf,
        tipoEcf: item.tipoEcf,
        xmlLength: result.xml.length,
        warnings: result.warnings,
        extractedFields: result.extractedFields,
        fallbackFieldsUsed: result.fallbackFieldsUsed,
        missingFields: result.missingFields,
        validation,
        sourceFieldsUsed: result.sourceFieldsUsed,
        audit: result.audit ?? null,
      });

      return {
        case: serializeCase(updated),
        xmlGenerated: result.xml,
        warnings: result.warnings,
        validation,
        sourceFieldsUsed: result.sourceFieldsUsed,
        extractedFields: result.extractedFields,
        fallbackFieldsUsed: result.fallbackFieldsUsed,
        rawRowKeys: result.rawRowKeys,
        audit: result.audit ?? null,
      };
    } catch (error) {
      const message = (error as any)?.message ?? 'No se pudo generar XML para el caso de certificacion';
      const errorCode = (error as any)?.errorCode ?? 'DGII_CERTIFICATION_XML_GENERATION_FAILED';
      const details = (error as any)?.details
        ? this.buildXmlGenerationFailureDetails(item, (error as any).details)
        : this.buildXmlGenerationFailureDetails(item, { humanReadableMessage: message });
      await this.prisma.dgiiCertificationCase.update({
        where: { id: item.id },
        data: {
          status: 'ERROR',
          errorMessage: details.humanReadableMessage,
          xmlValidationStatus: 'XML_INVALID',
          xmlValidationJson: details as unknown as Prisma.InputJsonObject,
          xmlValidatedAt: new Date(),
        },
      });
      console.error('[electronic-invoicing.certification] xml.generate_error', {
        requestId: requestId ?? null,
        companyId,
        batchId: item.batchId,
        caseId: item.id,
        sheetName: item.sheetName,
        encf: item.encf,
        tipoEcf: item.tipoEcf,
        errorCode,
        message: details.humanReadableMessage,
        extractedFields: details.extractedFields,
        fallbackFieldsUsed: details.fallbackFieldsUsed,
        missingFields: details.missingFields,
        rawRowKeys: details.rawRowKeys,
        details,
      });
      throw {
        status: (error as any)?.status ?? 409,
        message: details.humanReadableMessage,
        errorCode,
        details,
      };
    }
  }

  async validateCaseXml(companyId: number, id: number) {
    const item = await this.prisma.dgiiCertificationCase.findFirst({
      where: { id, companyId },
      select: { id: true, xmlGenerated: true },
    });
    if (!item) {
      throw { status: 404, message: 'Caso de certificacion no encontrado', errorCode: 'DGII_CERTIFICATION_CASE_NOT_FOUND' };
    }
    if (!item.xmlGenerated?.trim()) {
      throw { status: 409, message: 'Este caso aun no tiene XML generado', errorCode: 'DGII_CERTIFICATION_XML_NOT_FOUND' };
    }
    const validation = this.xmlValidationService.validate(item.xmlGenerated);
    await this.prisma.dgiiCertificationCase.update({
      where: { id: item.id },
      data: {
        ...this.validationPersistenceData(validation),
        errorMessage: validation.errors.length > 0 ? validation.errors.join('; ') : undefined,
      },
    });
    return validation;
  }

  async validateCaseXsd(companyId: number, id: number) {
    const validation = await this.validateCaseXml(companyId, id);
    return {
      xsdValidated: validation.xsdValidated,
      valid: validation.xsdValidated && validation.valid,
      xsdFileUsed: validation.xsdFileUsed ?? null,
      errors: validation.errors,
      xsdError: validation.xsdError ?? null,
      warnings: validation.xsdValidated
        ? validation.warnings
        : [...validation.warnings, 'XSD_NOT_AVAILABLE'],
    };
  }

  async auditCase(companyId: number, id: number) {
    const item = await this.prisma.dgiiCertificationCase.findFirst({
      where: { id, companyId },
      select: {
        id: true,
        companyId: true,
        encf: true,
        tipoEcf: true,
        xmlGenerated: true,
        xmlSigned: true,
        rawRowJson: true,
        xmlValidationJson: true,
      },
    });
    if (!item) {
      throw { status: 404, message: 'Caso de certificacion no encontrado', errorCode: 'DGII_CERTIFICATION_CASE_NOT_FOUND' };
    }
    const audit = await this.runDeterministicAudit(item);
    await this.prisma.dgiiCertificationCase.update({
      where: { id: item.id },
      data: {
        xmlValidationJson: {
          ...(item.xmlValidationJson && typeof item.xmlValidationJson === 'object' && !Array.isArray(item.xmlValidationJson)
            ? item.xmlValidationJson as Prisma.InputJsonObject
            : {}),
          audit,
        } as Prisma.InputJsonObject,
        errorMessage: audit.aptoParaEnviar ? null : audit.summary,
      },
    }).catch(() => undefined);
    return audit;
  }

  async aiAuditCase(companyId: number, id: number, aiApiKey?: string | null, aiModel?: string | null) {
    const audit = await this.auditCase(companyId, id);
    return {
      ...audit,
      ai: await this.maybeExplainAuditWithAi(audit as unknown as Record<string, unknown>, aiApiKey, aiModel),
    };
  }

  async auditBatch(companyId: number, batchId: number) {
    await this.getBatch(companyId, batchId);
    const cases = await this.prisma.dgiiCertificationCase.findMany({
      where: { companyId, batchId },
      select: {
        id: true,
        companyId: true,
        encf: true,
        tipoEcf: true,
        xmlGenerated: true,
        xmlSigned: true,
        rawRowJson: true,
        xmlValidationJson: true,
      },
      orderBy: [{ sheetName: 'asc' }, { rowNumber: 'asc' }],
    });
    const audits = [];
    for (const item of cases) {
      audits.push(await this.runDeterministicAudit(item));
    }
    return {
      batchId,
      total: audits.length,
      aptos: audits.filter((item) => item.aptoParaEnviar).length,
      noAptos: audits.filter((item) => !item.aptoParaEnviar).length,
      status: audits.every((item) => item.aptoParaEnviar) ? 'APTO PARA ENVIAR' : 'REQUIERE CORRECCIÓN',
      cases: audits,
    };
  }

  async aiAuditBatch(companyId: number, batchId: number, aiApiKey?: string | null, aiModel?: string | null) {
    const audit = await this.auditBatch(companyId, batchId);
    return {
      ...audit,
      ai: await this.maybeExplainAuditWithAi(audit as unknown as Record<string, unknown>, aiApiKey, aiModel),
    };
  }

  async getGeneratedXml(companyId: number, id: number) {
    const item = await this.prisma.dgiiCertificationCase.findFirst({
      where: { id, companyId },
      select: {
        id: true,
        companyId: true,
        xmlGenerated: true,
      },
    });
    if (!item) {
      throw { status: 404, message: 'Caso de certificacion no encontrado', errorCode: 'DGII_CERTIFICATION_CASE_NOT_FOUND' };
    }
    if (!item.xmlGenerated) {
      throw { status: 404, message: 'Este caso aun no tiene XML generado', errorCode: 'DGII_CERTIFICATION_XML_NOT_FOUND' };
    }
    return item.xmlGenerated;
  }

  async getSignedXml(companyId: number, id: number) {
    const item = await this.prisma.dgiiCertificationCase.findFirst({
      where: { id, companyId },
      select: { id: true, xmlSigned: true },
    });
    if (!item) {
      throw { status: 404, message: 'Caso de certificacion no encontrado', errorCode: 'DGII_CERTIFICATION_CASE_NOT_FOUND' };
    }
    if (!item.xmlSigned) {
      throw { status: 404, message: 'Este caso aun no tiene XML firmado', errorCode: 'DGII_CERTIFICATION_SIGNED_XML_NOT_FOUND' };
    }
    return item.xmlSigned;
  }

  async importManualSignedCaseXml(companyId: number, id: number, signedXml: string, fileName?: string, requestId?: string) {
    const item = await this.prisma.dgiiCertificationCase.findFirst({ where: { id, companyId } });
    if (!item) {
      throw { status: 404, message: 'Caso de certificacion no encontrado', errorCode: 'DGII_CERTIFICATION_CASE_NOT_FOUND' };
    }
    this.assertMutableStatus(item);
    if (!item.xmlGenerated?.trim()) {
      throw { status: 409, message: 'Primero genera el XML del caso antes de importar la firma manual', errorCode: 'DGII_CERTIFICATION_XML_NOT_FOUND' };
    }
    if (item.trackId?.trim()) {
      throw {
        status: 409,
        message: 'Este caso ya tiene TrackId. Limpia/reinicia el XML antes de importar una firma manual nueva.',
        errorCode: 'DGII_CERTIFICATION_TRACK_ID_ALREADY_EXISTS',
      };
    }
    const trimmedSignedXml = signedXml.trim();
    if (!trimmedSignedXml || !trimmedSignedXml.includes('<')) {
      throw { status: 400, message: 'El archivo XML firmado esta vacio o no parece XML', errorCode: 'DGII_CERTIFICATION_SIGNED_XML_INVALID_FILE' };
    }

    const validation = this.xmlValidationService.validate(trimmedSignedXml);
    const diagnostics = this.signatureService.inspectSignedXml(trimmedSignedXml);
    const localVerification = this.signatureService.verifySignedXml(trimmedSignedXml);
    const requiredSignatureNodesPresent =
      diagnostics.signedXmlHasSignature &&
      diagnostics.signedXmlHasSignedInfo &&
      diagnostics.signedXmlHasX509Certificate;

    if (!validation.wellFormed || !requiredSignatureNodesPresent || (validation.xsdValidated && !validation.valid)) {
      throw {
        status: 409,
        message: !requiredSignatureNodesPresent
          ? 'El XML importado no contiene una firma XMLDSig completa'
          : validation.xsdValidated && !validation.valid
            ? 'El XML firmado importado no valida contra el XSD DGII'
            : 'El XML firmado importado no esta bien formado',
        errorCode: 'DGII_CERTIFICATION_IMPORTED_SIGNED_XML_INVALID',
        details: { validation, diagnostics, localVerification },
      };
    }

    const warnings = [
      'XML firmado importado manualmente para prueba controlada.',
      ...validation.warnings,
      ...(localVerification.valid ? [] : localVerification.errors.map((message) => `Verificacion criptografica local: ${message}`)),
    ];
    const updated = await this.prisma.dgiiCertificationCase.update({
      where: { id: item.id },
      data: {
        xmlSigned: trimmedSignedXml,
        status: 'SIGNED',
        signedAt: new Date(),
        ...this.validationPersistenceData(validation),
        errorMessage: warnings.length > 0 ? warnings.join('; ') : null,
      },
    });

    console.warn('[electronic-invoicing.certification] signed_xml.imported_manual', {
      requestId: requestId ?? null,
      companyId,
      batchId: item.batchId,
      caseId: item.id,
      encf: item.encf,
      fileName: fileName ?? null,
      signedXmlLength: trimmedSignedXml.length,
      xsdValidated: validation.xsdValidated,
      xsdValid: validation.xsdValidated ? validation.valid : null,
      localSignatureValid: localVerification.valid,
      diagnostics,
    });

    return { case: serializeCase(updated), warnings, diagnostics, localVerification };
  }

  async generateXmlForBatch(companyId: number, batchId: number, requestId?: string) {
    await this.getBatch(companyId, batchId);
    const cases = await this.prisma.dgiiCertificationCase.findMany({
      where: { companyId, batchId },
      orderBy: [{ sheetName: 'asc' }, { rowNumber: 'asc' }],
      select: { id: true },
    });
    const errors: Array<{
      caseId: number;
      eNCF?: string | null;
      tipoEcf?: string | null;
      sheetName?: string | null;
      message: string;
      errorCode: string;
      missingFields?: string[];
      extractedFields?: Record<string, unknown>;
      rawRowKeys?: string[];
      humanReadableMessage?: string;
    }> = [];
    let generated = 0;

    for (const item of cases) {
      try {
        await this.generateXmlForCase(companyId, item.id, requestId);
        generated += 1;
      } catch (error) {
        const details = (error as any)?.details ?? {};
        errors.push({
          caseId: item.id,
          eNCF: details.eNCF ?? null,
          tipoEcf: details.tipoEcf ?? null,
          sheetName: details.sheetName ?? null,
          message: details.humanReadableMessage ?? (error as any)?.message ?? 'No se pudo generar XML',
          errorCode: (error as any)?.errorCode ?? 'DGII_CERTIFICATION_XML_GENERATION_FAILED',
          missingFields: Array.isArray(details.missingFields) ? details.missingFields : [],
          extractedFields: details.extractedFields ?? {},
          rawRowKeys: Array.isArray(details.rawRowKeys) ? details.rawRowKeys : [],
          humanReadableMessage: details.humanReadableMessage ?? (error as any)?.message ?? 'No se pudo generar XML',
        });
      }
    }

    return {
      total: cases.length,
      generated,
      failed: errors.length,
      errors,
    };
  }

  async signCase(companyId: number, id: number, requestId?: string) {
    const item = await this.prisma.dgiiCertificationCase.findFirst({ where: { id, companyId } });
    if (!item) {
      throw { status: 404, message: 'Caso de certificacion no encontrado', errorCode: 'DGII_CERTIFICATION_CASE_NOT_FOUND' };
    }
    this.assertMutableStatus(item);
    if (!item.xmlGenerated?.trim()) {
      throw { status: 409, message: 'Este caso no tiene XML generado para firmar', errorCode: 'DGII_CERTIFICATION_XML_NOT_FOUND' };
    }
    const audit = await this.auditCase(companyId, id);
    if (!audit.aptoParaEnviar) {
      throw {
        status: 409,
        message: audit.summary,
        errorCode: 'DGII_CERTIFICATION_AUDIT_BLOCKED',
        details: audit,
      };
    }
    const xmlValidation = this.xmlValidationService.validate(item.xmlGenerated);
    if (!xmlValidation.canSign) {
      await this.prisma.dgiiCertificationCase.update({
        where: { id: item.id },
        data: {
          ...this.validationPersistenceData(xmlValidation),
          errorMessage: 'Este XML todavia no esta listo para firmarse. Corrige los campos requeridos o carga los XSD oficiales DGII.',
        },
      });
      throw {
        status: 409,
        message: 'Este XML todavia no esta listo para firmarse. Corrige los campos requeridos o carga los XSD oficiales DGII.',
        errorCode: 'DGII_CERTIFICATION_XML_NOT_SIGNABLE',
        details: xmlValidation,
      };
    }

    try {
      const { certificate, loaded } = await this.loadActiveCertificate(companyId);
      const signedXml = this.signatureService.signXml(item.xmlGenerated, loaded.privateKeyPem, loaded.certPem);
      const diagnostics = this.signatureService.inspectSignedXml(signedXml);
      const signedXmlValidation = this.xmlValidationService.validate(signedXml);
      const localVerification = this.signatureService.verifySignedXml(signedXml);
      const requiredSignatureNodesPresent =
        diagnostics.signedXmlHasSignature &&
        diagnostics.signedXmlHasSignedInfo &&
        diagnostics.signedXmlHasX509Certificate &&
        diagnostics.signatureReferenceUri === '' &&
        diagnostics.canonicalizationAlgorithm === 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315' &&
        diagnostics.signatureAlgorithm === 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' &&
        diagnostics.digestAlgorithm === 'http://www.w3.org/2001/04/xmlenc#sha256';
      const signedXmlXsdFailed = signedXmlValidation.xsdValidated && !signedXmlValidation.valid;
      if (!signedXmlValidation.wellFormed || signedXmlXsdFailed || !requiredSignatureNodesPresent || !localVerification.valid) {
        throw {
          status: 409,
          message: signedXmlXsdFailed
            ? 'El XML firmado no valida contra el XSD DGII'
            : 'La firma XML local no cumple la estructura DGII esperada',
          errorCode: 'DGII_CERTIFICATION_SIGNATURE_INVALID',
          details: {
            diagnostics,
            signedXmlValidation,
            localVerification,
          },
        };
      }
      const updated = await this.prisma.dgiiCertificationCase.update({
        where: { id: item.id },
        data: {
          xmlSigned: signedXml,
          status: 'SIGNED',
          signedAt: new Date(),
          ...this.validationPersistenceData(xmlValidation),
          errorMessage: null,
        },
      });

      console.info('[electronic-invoicing.certification] xml.signed', {
        requestId: requestId ?? null,
        companyId,
        batchId: item.batchId,
        caseId: item.id,
        encf: item.encf,
        certificateId: certificate.id,
        signedXmlLength: signedXml.length,
        diagnostics,
      });

      return { case: serializeCase(updated), signedXml, warnings: [], diagnostics, localVerification };
    } catch (error) {
      const message = (error as any)?.message ?? 'No se pudo firmar XML';
      await this.prisma.dgiiCertificationCase.update({
        where: { id: item.id },
        data: { status: 'ERROR', errorMessage: message },
      });
      console.error('[electronic-invoicing.certification] xml.sign_error', {
        requestId: requestId ?? null,
        companyId,
        batchId: item.batchId,
        caseId: item.id,
        encf: item.encf,
        errorCode: (error as any)?.errorCode ?? 'DGII_CERTIFICATION_SIGN_FAILED',
        message,
      });
      throw {
        status: (error as any)?.status ?? 409,
        message,
        errorCode: (error as any)?.errorCode ?? 'DGII_CERTIFICATION_SIGN_FAILED',
      };
    }
  }

  async signBatch(companyId: number, batchId: number, requestId?: string) {
    await this.getBatch(companyId, batchId);
    const cases = await this.prisma.dgiiCertificationCase.findMany({
      where: { companyId, batchId, status: 'XML_GENERATED' },
      orderBy: [{ sheetName: 'asc' }, { rowNumber: 'asc' }],
      select: { id: true, xmlGenerated: true },
    });
    const errors: Array<{ caseId: number; message: string; errorCode: string }> = [];
    let signed = 0;
    let skipped = 0;

    for (const item of cases) {
      if (!item.xmlGenerated?.trim()) {
        skipped += 1;
        continue;
      }
      try {
        await this.signCase(companyId, item.id, requestId);
        signed += 1;
      } catch (error) {
        errors.push({
          caseId: item.id,
          message: (error as any)?.message ?? 'No se pudo firmar XML',
          errorCode: (error as any)?.errorCode ?? 'DGII_CERTIFICATION_SIGN_FAILED',
        });
      }
    }

    return { total: cases.length, signed, skipped, failed: errors.length, errors };
  }

  private resolveReceptionEndpoint(environment: DgiiEnvironment, sheetName: string) {
    const config = this.directory.getEnvironmentConfig(environment);
    if (sheetName.toUpperCase() === 'ECF') {
      return config.recepcionEcfUrl || config.submitUrl;
    }
    if (sheetName.toUpperCase() === 'RFCE') {
      if (!config.recepcionFcUrl) {
        throw {
          status: 500,
          message: 'RFCE sending is pending until RFCE XML generation is implemented.',
          errorCode: 'DGII_CERTIFICATION_RFCE_RECEPTION_FC_URL_MISSING',
        };
      }
      return config.recepcionFcUrl;
    }
    throw { status: 400, message: 'Hoja de certificacion no soportada', errorCode: 'DGII_CERTIFICATION_SHEET_UNSUPPORTED' };
  }

  async sendCase(companyId: number, id: number, requestId?: string) {
    const preflight = await this.preflightCase(companyId, id);
    if (!preflight.canSend) {
      throw {
        status: 409,
        message: 'El preflight DGII no permite enviar este caso.',
        errorCode: 'DGII_CERTIFICATION_PREFLIGHT_BLOCKED',
        details: preflight,
      };
    }
    const item = await this.prisma.dgiiCertificationCase.findFirst({ where: { id, companyId } });
    if (!item) {
      throw { status: 404, message: 'Caso de certificacion no encontrado', errorCode: 'DGII_CERTIFICATION_CASE_NOT_FOUND' };
    }
    this.assertMutableStatus(item);
    if (!item.xmlSigned?.trim()) {
      throw { status: 409, message: 'No se puede enviar XML sin firma', errorCode: 'DGII_CERTIFICATION_SIGNED_XML_NOT_FOUND' };
    }

    const environment = await this.getEnvironment(companyId);
    const endpoint = this.resolveReceptionEndpoint(environment, item.sheetName);
    const result = await this.submissionService.submit(companyId, environment, item.xmlSigned, requestId, undefined, {
      ecf: item.encf ?? undefined,
      endpointOverride: endpoint,
      maxRetriesOverride: 0,
    });
    const nextStatus = this.certificationStatusFromSubmit(result);
    const rejectionCode = nextStatus === 'REJECTED' ? this.extractRejectionCode(result.raw, result.code) : null;
    const rejectionMessage = nextStatus === 'REJECTED' ? this.extractRejectionMessage(result.raw, result.message) : null;

    const updated = await this.prisma.dgiiCertificationCase.update({
      where: { id: item.id },
      data: {
        status: nextStatus,
        trackId: result.trackId ?? item.trackId,
        sentAt: new Date(),
        dgiiRawResponseJson: this.buildRawResponse(result),
        dgiiStatusCode: result.code ?? null,
        dgiiStatusMessage: result.message ?? null,
        rejectionCode,
        rejectionMessage,
        errorMessage: nextStatus === 'ERROR' ? this.submissionErrorMessage(result) : null,
      },
    });

    console.info('[electronic-invoicing.certification] xml.sent', {
      requestId: requestId ?? null,
      companyId,
      batchId: item.batchId,
      caseId: item.id,
      encf: item.encf,
      environment,
      endpoint,
      status: nextStatus,
      trackId: result.trackId ?? item.trackId ?? null,
    });

    return { case: serializeCase(updated), dgii: result };
  }

  async sendBatch(companyId: number, batchId: number, requestId?: string) {
    await this.getBatch(companyId, batchId);
    const cases = await this.prisma.dgiiCertificationCase.findMany({
      where: {
        companyId,
        batchId,
        OR: [
          { status: 'SIGNED' },
          {
            status: 'ERROR',
            xmlSigned: { not: null },
            trackId: null,
          },
        ],
      },
      orderBy: [{ sheetName: 'asc' }, { rowNumber: 'asc' }],
      select: { id: true, xmlSigned: true, rowNumber: true, tipoEcf: true, encf: true, rawRowJson: true },
    });
    const orderedCases = this.sortCasesForCertificationSend(cases);
    const errors: Array<{ caseId: number; message: string; errorCode: string }> = [];
    const trackIds: Array<{ caseId: number; trackId: string }> = [];
    let sent = 0;
    let skipped = 0;

    for (const item of orderedCases) {
      if (!item.xmlSigned?.trim()) {
        skipped += 1;
        continue;
      }
      try {
        const result = await this.sendCase(companyId, item.id, requestId);
        if (['SENT', 'EN_PROCESO'].includes(result.case.status)) sent += 1;
        if (result.case.trackId) trackIds.push({ caseId: item.id, trackId: result.case.trackId });
      } catch (error) {
        errors.push({
          caseId: item.id,
          message: (error as any)?.message ?? 'No se pudo enviar XML',
          errorCode: (error as any)?.errorCode ?? 'DGII_CERTIFICATION_SEND_FAILED',
        });
      }
    }

    return { total: orderedCases.length, sent, skipped, failed: errors.length, trackIds, errors };
  }

  async reprocessAndSendBatch(companyId: number, batchId: number, requestId?: string) {
    await this.getBatch(companyId, batchId);

    const reset = await this.resetBatch(companyId, batchId, false, requestId);
    const generation = await this.generateXmlForBatch(companyId, batchId, requestId);
    const signing = await this.signBatch(companyId, batchId, requestId);
    const preflight = await this.preflightBatch(companyId, batchId);
    const send = await this.sendBatch(companyId, batchId, requestId);

    const blockedCases = preflight.cases
      .filter((item) => !item.canSend)
      .map((item) => ({
        caseId: item.caseId,
        encf: item.encf ?? null,
        blockers: item.blockers,
        warnings: item.warnings,
        referencedEcf: item.referencedEcf ?? null,
      }));

    return {
      batchId,
      total: preflight.total,
      reset: reset.reset,
      blockedFinal: reset.blockedFinal,
      generated: generation.generated,
      generationFailed: generation.failed,
      generationErrors: generation.errors,
      signed: signing.signed,
      signingSkipped: signing.skipped,
      signingFailed: signing.failed,
      signingErrors: signing.errors,
      readyToSend: preflight.readyToSend,
      blocked: preflight.blocked,
      preflightWarnings: preflight.warnings,
      blockedCases,
      sent: send.sent,
      sendSkipped: send.skipped,
      sendFailed: send.failed,
      trackIds: send.trackIds,
      sendErrors: send.errors,
    };
  }

  async queryCaseResult(companyId: number, id: number, requestId?: string) {
    const item = await this.prisma.dgiiCertificationCase.findFirst({ where: { id, companyId } });
    if (!item) {
      throw { status: 404, message: 'Caso de certificacion no encontrado', errorCode: 'DGII_CERTIFICATION_CASE_NOT_FOUND' };
    }
    if (!item.trackId?.trim()) {
      throw { status: 409, message: 'Este caso no tiene TrackId para consultar', errorCode: 'DGII_CERTIFICATION_TRACK_ID_NOT_FOUND' };
    }

    const environment = await this.getEnvironment(companyId);
    const result = await this.resultService.query(companyId, environment, item.trackId, requestId);
    const normalizedNextStatus = this.certificationStatusFromResult(result);
    const keepPriorStatus =
      FINAL_CERTIFICATION_STATUSES.has(item.status) ||
      (normalizedNextStatus === 'ERROR' && ['SENT', 'EN_PROCESO'].includes(item.status));
    const nextStatus = keepPriorStatus ? item.status : normalizedNextStatus;
    const rejectionCode = nextStatus === 'REJECTED' ? this.extractRejectionCode(result.raw, result.code) : item.rejectionCode;
    const rejectionMessage = nextStatus === 'REJECTED' ? this.extractRejectionMessage(result.raw, result.message) : item.rejectionMessage;

    const updated = await this.prisma.dgiiCertificationCase.update({
      where: { id: item.id },
      data: {
        status: nextStatus,
        trackId: item.trackId,
        resultCheckedAt: new Date(),
        dgiiRawResponseJson: this.buildRawResponse(result),
        dgiiStatusCode: result.code ?? null,
        dgiiStatusMessage: result.message ?? null,
        rejectionCode,
        rejectionMessage,
        errorMessage: normalizedNextStatus === 'ERROR' ? result.message ?? 'No se pudo consultar resultado DGII' : null,
      },
    });

    return { case: serializeCase(updated), dgii: result };
  }

  async queryBatchResults(companyId: number, batchId: number, requestId?: string) {
    await this.getBatch(companyId, batchId);
    const cases = await this.prisma.dgiiCertificationCase.findMany({
      where: { companyId, batchId, trackId: { not: null } },
      orderBy: [{ sheetName: 'asc' }, { rowNumber: 'asc' }],
      select: { id: true },
    });
    let queried = 0;
    let accepted = 0;
    let rejected = 0;
    let conditional = 0;
    let processing = 0;
    const errors: Array<{ caseId: number; message: string; errorCode: string }> = [];

    for (const item of cases) {
      try {
        const result = await this.queryCaseResult(companyId, item.id, requestId);
        queried += 1;
        if (result.case.status === 'ACCEPTED') accepted += 1;
        else if (result.case.status === 'ACCEPTED_CONDITIONAL') conditional += 1;
        else if (result.case.status === 'REJECTED') rejected += 1;
        else if (result.case.status === 'EN_PROCESO' || result.case.status === 'SENT') processing += 1;
      } catch (error) {
        errors.push({
          caseId: item.id,
          message: (error as any)?.message ?? 'No se pudo consultar resultado',
          errorCode: (error as any)?.errorCode ?? 'DGII_CERTIFICATION_RESULT_FAILED',
        });
      }
    }

    return { total: cases.length, queried, accepted, rejected, conditional, processing, failed: errors.length, errors };
  }

  private signatureStructureIsValid(xmlSigned: string) {
    const diagnostics = this.signatureService.inspectSignedXml(xmlSigned);
    const localVerification = this.signatureService.verifySignedXml(xmlSigned);
    const structureValid =
      diagnostics.signedXmlHasSignature &&
      diagnostics.signedXmlHasSignedInfo &&
      diagnostics.signedXmlHasX509Certificate &&
      diagnostics.signatureReferenceUri === '' &&
      diagnostics.canonicalizationAlgorithm === 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315' &&
      diagnostics.signatureAlgorithm === 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' &&
      diagnostics.digestAlgorithm === 'http://www.w3.org/2001/04/xmlenc#sha256';
    return {
      valid: structureValid,
      localVerificationValid: localVerification.valid,
      diagnostics,
      localVerification,
    };
  }

  private async resolveReferenceDependencyBlockers(item: {
    id: number;
    companyId: number;
    batchId: number;
    tipoEcf: string | null;
    rawRowJson: unknown;
  }) {
    const reference = extractCertificationReferenceEcf(item.rawRowJson)?.trim();
    if (!reference || !['33', '34'].includes(item.tipoEcf ?? '')) {
      return { blockers: [] as string[], referencedCaseId: null as number | null, referencedEcf: reference ?? null };
    }

    const referencedCase = await this.prisma.dgiiCertificationCase.findFirst({
      where: {
        companyId: item.companyId,
        batchId: item.batchId,
        encf: reference,
      },
      select: {
        id: true,
        status: true,
        trackId: true,
        sentAt: true,
      },
    });

    if (!referencedCase) {
      return { blockers: [] as string[], referencedCaseId: null as number | null, referencedEcf: reference };
    }

    const readyStatuses = new Set(['SENT', 'EN_PROCESO', 'ACCEPTED', 'ACCEPTED_CONDITIONAL']);
    const isReady = readyStatuses.has(referencedCase.status) || !!referencedCase.trackId?.trim() || !!referencedCase.sentAt;
    return {
      blockers: isReady ? [] : ['REFERENCED_ECF_NOT_READY'],
      referencedCaseId: referencedCase.id,
      referencedEcf: reference,
    };
  }

  private sortCasesForCertificationSend<T extends {
    id: number;
    rowNumber: number;
    tipoEcf: string | null;
    encf: string | null;
    rawRowJson: unknown;
  }>(cases: T[]) {
    const byEcf = new Map<string, T>();
    for (const item of cases) {
      if (item.encf?.trim()) byEcf.set(item.encf.trim(), item);
    }

    const visiting = new Set<number>();
    const visited = new Set<number>();
    const ordered: T[] = [];

    const visit = (item: T) => {
      if (visited.has(item.id)) return;
      if (visiting.has(item.id)) return;
      visiting.add(item.id);
      const reference = extractCertificationReferenceEcf(item.rawRowJson)?.trim();
      if (reference && ['33', '34'].includes(item.tipoEcf ?? '')) {
        const dependency = byEcf.get(reference);
        if (dependency) visit(dependency);
      }
      visiting.delete(item.id);
      visited.add(item.id);
      ordered.push(item);
    };

    [...cases]
      .sort((left, right) => left.rowNumber - right.rowNumber || left.id - right.id)
      .forEach(visit);
    return ordered;
  }

  async preflightCase(companyId: number, id: number) {
    const blockers: string[] = [];
    const warnings: string[] = [];
    const db = await this.detectCertificationDbFields();
    if (db.databaseHasNewFields !== true) blockers.push('DB_MIGRATION_NOT_APPLIED');

    const item = await this.prisma.dgiiCertificationCase.findFirst({
      where: { id, companyId },
      include: {
        company: {
          select: { id: true, rnc: true, name: true },
        },
      },
    });
    if (!item) {
      throw { status: 404, message: 'Caso de certificacion no encontrado', errorCode: 'DGII_CERTIFICATION_CASE_NOT_FOUND' };
    }

    if (FINAL_CERTIFICATION_STATUSES.has(item.status)) blockers.push('CASE_ALREADY_FINAL');
    if (!item.xmlGenerated?.trim()) blockers.push('XML_GENERATED_MISSING');
    const referenceDependency = await this.resolveReferenceDependencyBlockers(item);
    blockers.push(...referenceDependency.blockers);

    let xmlValidationStatus = item.xmlValidationStatus ?? 'NOT_VALIDATED';
    let validation: ReturnType<DgiiCertificationXmlValidationService['validate']> | null = null;
    if (item.xmlGenerated?.trim()) {
      validation = this.xmlValidationService.validate(item.xmlGenerated);
      xmlValidationStatus = this.validationStatus(validation);
      if (!validation.wellFormed) blockers.push('XML_NOT_WELL_FORMED');
      if (validation.xsdFiles.length === 0) blockers.push('XSD_FILES_MISSING');
      else if (!validation.xsdValidationEngineAvailable) blockers.push('XSD_ENGINE_MISSING');
      else if (!validation.xsdValidated || !validation.valid) blockers.push('XSD_VALIDATION_FAILED');
      warnings.push(...validation.warnings);
      await this.prisma.dgiiCertificationCase.update({
        where: { id: item.id },
        data: {
          ...this.validationPersistenceData(validation),
        },
      }).catch(() => undefined);
    }
    const deterministicAudit = await this.runDeterministicAudit(item);
    if (!deterministicAudit.aptoParaEnviar) {
      blockers.push('CERTIFICATION_AUDIT_FAILED');
      warnings.push(...deterministicAudit.warnings);
    }

    if (!item.xmlSigned?.trim()) blockers.push('SIGNED_XML_MISSING');
    let signatureStatus = 'MISSING';
    if (item.xmlSigned?.trim()) {
      const signature = this.signatureStructureIsValid(item.xmlSigned);
      signatureStatus = signature.valid ? 'VALID' : 'INVALID';
      if (!signature.valid) blockers.push('SIGNATURE_INVALID');
      if (!signature.localVerificationValid) {
        warnings.push('SIGNATURE_LOCAL_VERIFICATION_FAILED');
      }
      warnings.push(...signature.localVerification.errors);
    }

    const environment = await this.getEnvironment(companyId);
    let endpointType: 'Recepcion' | 'RecepcionFC' | null = null;
    let endpointUrl: string | null = null;
    let endpointUrlMasked: string | null = null;
    try {
      const config = this.directory.getEnvironmentConfig(environment);
      endpointType = item.sheetName.toUpperCase() === 'RFCE' ? 'RecepcionFC' : 'Recepcion';
      endpointUrl = endpointType === 'RecepcionFC' ? config.recepcionFcUrl ?? null : (config.recepcionEcfUrl || config.submitUrl);
      endpointUrlMasked = maskUrl(endpointUrl);
      if (!endpointUrl) blockers.push(endpointType === 'RecepcionFC' ? 'RFCE_ENDPOINT_MISSING' : 'ECF_ENDPOINT_MISSING');
      if (!config.authSeedUrl || !config.authValidateUrl) blockers.push('DGII_AUTH_CONFIG_MISSING');
    } catch (error) {
      blockers.push('DGII_ENDPOINT_CONFIG_MISSING');
      warnings.push((error as any)?.message ?? 'Configuracion DGII no disponible');
    }

    let certificateStatus = 'MISSING';
    try {
      const { loaded } = await this.loadActiveCertificate(companyId);
      const analysis = analyzeCertificateForDgii(
        loaded.subject,
        loaded.issuer,
        item.company.rnc ?? null,
        loaded.chainPems.length,
      );
      certificateStatus = 'VALID';
      if (!loaded.keyMatchesCertificate) {
        certificateStatus = 'INVALID';
        blockers.push('CERTIFICATE_KEY_MISMATCH');
      }
      if (analysis.rncInCertificate && !analysis.rncMatchesCompany) {
        blockers.push('CERTIFICATE_RNC_MISMATCH');
      }
      if (!analysis.rncInCertificate) warnings.push('CERTIFICATE_RNC_NOT_DETECTABLE');
    } catch (error) {
      certificateStatus = 'INVALID';
      blockers.push('ACTIVE_CERTIFICATE_MISSING_OR_INVALID');
      warnings.push((error as any)?.message ?? 'Certificado activo no disponible');
    }

    return {
      caseId: item.id,
      sheetName: item.sheetName,
      encf: item.encf,
      status: item.status,
      canSend: blockers.length === 0,
      blockers: [...new Set(blockers)],
      warnings: [...new Set(warnings)],
      endpointType,
      endpointUrlMasked,
      certificateStatus,
      xmlValidationStatus,
      signatureStatus,
      referencedCaseId: referenceDependency.referencedCaseId,
      referencedEcf: referenceDependency.referencedEcf,
      audit: deterministicAudit,
    };
  }

  async preflightBatch(companyId: number, batchId: number) {
    await this.getBatch(companyId, batchId);
    const cases = await this.prisma.dgiiCertificationCase.findMany({
      where: { companyId, batchId },
      orderBy: [{ sheetName: 'asc' }, { rowNumber: 'asc' }],
      select: { id: true },
    });
    const results = [];
    for (const item of cases) {
      results.push(await this.preflightCase(companyId, item.id));
    }
    return {
      total: results.length,
      readyToSend: results.filter((item) => item.canSend).length,
      blocked: results.filter((item) => !item.canSend).length,
      warnings: [...new Set(results.flatMap((item) => item.warnings))],
      cases: results,
    };
  }

  async getBatchSummary(companyId: number, batchId: number) {
    const batch = await this.getBatch(companyId, batchId);
    const cases = await this.prisma.dgiiCertificationCase.findMany({
      where: { companyId, batchId },
      select: { status: true, sheetName: true, xmlGenerated: true, xmlSigned: true, trackId: true, errorMessage: true },
    });
    const count = (statuses: string[]) => cases.filter((item) => statuses.includes(item.status)).length;
    const totalCases = cases.length;
    const accepted = count(['ACCEPTED']);
    const rejected = count(['REJECTED']);
    const acceptedConditional = count(['ACCEPTED_CONDITIONAL']);
    const processing = count(['EN_PROCESO', 'SENT']);
    const error = count(['ERROR']);
    const xmlGenerated = cases.filter((item) => !!item.xmlGenerated || item.status === 'XML_GENERATED').length;
    const signed = cases.filter((item) => !!item.xmlSigned || item.status === 'SIGNED').length;
    const sent = cases.filter((item) => !!item.trackId || ['SENT', 'EN_PROCESO', 'ACCEPTED', 'ACCEPTED_CONDITIONAL', 'REJECTED'].includes(item.status)).length;
    const done = accepted + rejected + acceptedConditional;
    const progressPercentage = totalCases === 0 ? 0 : Math.round((done / totalCases) * 100);
    const blockingIssues: string[] = [];
    if (totalCases === 0) blockingIssues.push('NO_CASES');
    if (cases.some((item) => item.status === 'IMPORTED')) blockingIssues.push('XML_PENDING');
    if (cases.some((item) => item.status === 'XML_GENERATED')) blockingIssues.push('SIGNATURE_PENDING');
    if (cases.some((item) => item.status === 'SIGNED')) blockingIssues.push('SEND_PENDING');
    if (cases.some((item) => ['SENT', 'EN_PROCESO'].includes(item.status))) blockingIssues.push('RESULT_PENDING');
    if (rejected > 0) blockingIssues.push('REJECTIONS_PRESENT');
    if (error > 0) blockingIssues.push('ERRORS_PRESENT');

    return {
      batch,
      totalCases,
      imported: count(['IMPORTED']),
      xmlGenerated,
      signed,
      sent,
      accepted,
      rejected,
      acceptedConditional,
      processing,
      error,
      ecfCases: cases.filter((item) => item.sheetName === 'ECF').length,
      rfceCases: cases.filter((item) => item.sheetName === 'RFCE').length,
      progressPercentage,
      isReadyForNextStep: blockingIssues.length > 0 && !blockingIssues.includes('ERRORS_PRESENT'),
      blockingIssues,
    };
  }

  async resetCase(companyId: number, id: number, force = false, requestId?: string) {
    const item = await this.prisma.dgiiCertificationCase.findFirst({
      where: { id, companyId },
    });
    if (!item) {
      throw { status: 404, message: 'Caso de certificacion no encontrado', errorCode: 'DGII_CERTIFICATION_CASE_NOT_FOUND' };
    }
    if (item.status === 'ACCEPTED' && !force) {
      throw {
        status: 409,
        message: 'No se puede reiniciar un caso aceptado sin force=true',
        errorCode: 'DGII_CERTIFICATION_ACCEPTED_RESET_REQUIRES_FORCE',
      };
    }
    if (['ACCEPTED_CONDITIONAL', 'REJECTED'].includes(item.status) && !force) {
      throw {
        status: 409,
        message: 'No se puede reiniciar un caso final sin force=true',
        errorCode: 'DGII_CERTIFICATION_FINAL_RESET_REQUIRES_FORCE',
      };
    }
    const resettable = ['IMPORTED', 'XML_GENERATED', 'SIGNED', 'SENT', 'EN_PROCESO', 'ERROR', 'ACCEPTED', 'ACCEPTED_CONDITIONAL', 'REJECTED'];
    if (!resettable.includes(item.status)) {
      throw {
        status: 409,
        message: `Estado no reiniciable: ${item.status}`,
        errorCode: 'DGII_CERTIFICATION_STATUS_NOT_RESETTABLE',
      };
    }
    const updated = await this.prisma.dgiiCertificationCase.update({
      where: { id: item.id },
      data: {
        status: 'IMPORTED',
        xmlGenerated: null,
        xmlSigned: null,
        trackId: null,
        dgiiRawResponseJson: Prisma.JsonNull,
        signedAt: null,
        sentAt: null,
        resultCheckedAt: null,
        dgiiStatusCode: null,
        dgiiStatusMessage: null,
        rejectionCode: null,
        rejectionMessage: null,
        xmlValidationStatus: 'NOT_VALIDATED',
        xmlValidationJson: Prisma.JsonNull,
        xmlValidatedAt: null,
        xsdValidated: false,
        xsdValid: false,
        xsdError: null,
        errorMessage: null,
      },
    });
    console.warn('[electronic-invoicing.certification] case.reset', {
      requestId: requestId ?? null,
      companyId,
      caseId: item.id,
      encf: item.encf,
      fromStatus: item.status,
      force,
    });
    return { case: serializeCase(updated), fromStatus: item.status, force };
  }

  async resetBatch(companyId: number, batchId: number, force = false, requestId?: string) {
    await this.getBatch(companyId, batchId);
    const finalStatuses = ['ACCEPTED', 'ACCEPTED_CONDITIONAL', 'REJECTED'];
    const cases = await this.prisma.dgiiCertificationCase.findMany({
      where: { companyId, batchId },
      select: { id: true, status: true },
    });
    const blockedFinal = force
      ? 0
      : cases.filter((item) => finalStatuses.includes(item.status)).length;
    const resettableIds = cases
      .filter((item) => force || !finalStatuses.includes(item.status))
      .map((item) => item.id);

    if (resettableIds.length === 0) {
      return {
        batchId,
        total: cases.length,
        reset: 0,
        blockedFinal,
        force,
      };
    }

    const updated = await this.prisma.dgiiCertificationCase.updateMany({
      where: {
        companyId,
        batchId,
        id: { in: resettableIds },
      },
      data: {
        status: 'IMPORTED',
        xmlGenerated: null,
        xmlSigned: null,
        trackId: null,
        dgiiRawResponseJson: Prisma.JsonNull,
        signedAt: null,
        sentAt: null,
        resultCheckedAt: null,
        dgiiStatusCode: null,
        dgiiStatusMessage: null,
        rejectionCode: null,
        rejectionMessage: null,
        xmlValidationStatus: 'NOT_VALIDATED',
        xmlValidationJson: Prisma.JsonNull,
        xmlValidatedAt: null,
        xsdValidated: false,
        xsdValid: false,
        xsdError: null,
        errorMessage: null,
      },
    });

    console.warn('[electronic-invoicing.certification] batch.reset', {
      requestId: requestId ?? null,
      companyId,
      batchId,
      total: cases.length,
      reset: updated.count,
      blockedFinal,
      force,
    });

    return {
      batchId,
      total: cases.length,
      reset: updated.count,
      blockedFinal,
      force,
    };
  }

  async deleteBatch(companyId: number, id: number) {
    await this.getBatch(companyId, id);
    await this.prisma.dgiiCertificationBatch.delete({ where: { id } });
    return { ok: true, deletedBatchId: id };
  }
}

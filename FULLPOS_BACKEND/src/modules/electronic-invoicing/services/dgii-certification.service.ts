import * as path from 'path';
import * as XLSX from 'xlsx';
import { Prisma, PrismaClient } from '@prisma/client';
import { ElectronicInvoicingMapperService } from './electronic-invoicing-mapper.service';
import { normalizeRnc } from '../utils/validation.utils';

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
  return Object.values(row).every((value) => normalizeValue(value) == null);
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
  return {
    ...item,
    montoTotal: item.montoTotal == null ? null : Number(item.montoTotal),
  };
}

export class DgiiCertificationService {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly mapper: ElectronicInvoicingMapperService,
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
      const rows = XLSX.utils.sheet_to_json<Record<string, unknown>>(worksheet, {
        defval: null,
        raw: false,
      });
      sheetStats[sheetName].found = rows.length;

      rows.forEach((rawRow, index) => {
        const rowNumber = index + 2;
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

  async deleteBatch(companyId: number, id: number) {
    await this.getBatch(companyId, id);
    await this.prisma.dgiiCertificationBatch.delete({ where: { id } });
    return { ok: true, deletedBatchId: id };
  }
}

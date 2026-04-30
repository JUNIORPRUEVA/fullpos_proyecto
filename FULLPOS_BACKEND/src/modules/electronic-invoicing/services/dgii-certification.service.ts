import * as path from 'path';
import * as XLSX from 'xlsx';
import { Prisma, PrismaClient } from '@prisma/client';
import env, { normalizeDgiiEnvironmentAlias } from '../../../config/env';
import { ElectronicInvoicingMapperService } from './electronic-invoicing-mapper.service';
import { normalizeRnc } from '../utils/validation.utils';
import { DgiiCertificationXmlBuilderService } from './dgii-certification-xml-builder.service';
import { DgiiSignatureService } from './dgii-signature.service';
import { DgiiSubmissionService } from './dgii-submission.service';
import { DgiiResultService } from './dgii-result.service';
import { DgiiDirectoryService } from './dgii-directory.service';
import { DgiiEnvironment } from '../types/dgii.types';
import {
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
    private readonly xmlBuilder: DgiiCertificationXmlBuilderService,
    private readonly signatureService: DgiiSignatureService,
    private readonly submissionService: DgiiSubmissionService,
    private readonly resultService: DgiiResultService,
    private readonly directory: DgiiDirectoryService,
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

  private async getEnvironment(companyId: number): Promise<DgiiEnvironment> {
    const config = await this.prisma.electronicInboundEndpointConfig.findFirst({
      where: { companyId },
      orderBy: [{ branchId: 'asc' }, { updatedAt: 'desc' }],
      select: { environment: true },
    });
    return normalizeDgiiEnvironmentAlias(config?.environment ?? env.DGII_DEFAULT_ENVIRONMENT) as DgiiEnvironment;
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
    if (['ACCEPTED', 'ACCEPTED_CONDITIONAL', 'REJECTED'].includes(item.status)) {
      throw {
        status: 409,
        message: 'Este caso ya tiene resultado final DGII. Regenerar/reiniciar debe hacerse explicitamente.',
        errorCode: 'DGII_CERTIFICATION_FINAL_CASE_LOCKED',
      };
    }
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

  async generateXmlForCase(companyId: number, id: number, requestId?: string) {
    const item = await this.prisma.dgiiCertificationCase.findFirst({
      where: { id, companyId },
    });
    if (!item) {
      throw { status: 404, message: 'Caso de certificacion no encontrado', errorCode: 'DGII_CERTIFICATION_CASE_NOT_FOUND' };
    }

    try {
      const result = item.sheetName === 'RFCE'
        ? this.xmlBuilder.buildRfceXmlFromCertificationCase(item)
        : this.xmlBuilder.buildEcfXmlFromCertificationCase(item);
      const warningMessage = result.warnings.length > 0 ? `Warnings: ${result.warnings.join('; ')}` : null;
      const updated = await this.prisma.dgiiCertificationCase.update({
        where: { id: item.id },
        data: {
          xmlGenerated: result.xml,
          status: 'XML_GENERATED',
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
      });

      return { case: serializeCase(updated), xmlGenerated: result.xml, warnings: result.warnings };
    } catch (error) {
      const message = (error as any)?.message ?? 'No se pudo generar XML para el caso de certificacion';
      const errorCode = (error as any)?.errorCode ?? 'DGII_CERTIFICATION_XML_GENERATION_FAILED';
      await this.prisma.dgiiCertificationCase.update({
        where: { id: item.id },
        data: {
          status: 'ERROR',
          errorMessage: message,
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
        message,
        details: (error as any)?.details ?? null,
      });
      throw {
        status: (error as any)?.status ?? 409,
        message,
        errorCode,
        details: (error as any)?.details ?? null,
      };
    }
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

  async generateXmlForBatch(companyId: number, batchId: number, requestId?: string) {
    await this.getBatch(companyId, batchId);
    const cases = await this.prisma.dgiiCertificationCase.findMany({
      where: { companyId, batchId },
      orderBy: [{ sheetName: 'asc' }, { rowNumber: 'asc' }],
      select: { id: true },
    });
    const errors: Array<{ caseId: number; message: string; errorCode: string }> = [];
    let generated = 0;

    for (const item of cases) {
      try {
        await this.generateXmlForCase(companyId, item.id, requestId);
        generated += 1;
      } catch (error) {
        errors.push({
          caseId: item.id,
          message: (error as any)?.message ?? 'No se pudo generar XML',
          errorCode: (error as any)?.errorCode ?? 'DGII_CERTIFICATION_XML_GENERATION_FAILED',
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

    try {
      const { certificate, loaded } = await this.loadActiveCertificate(companyId);
      const signedXml = this.signatureService.signXml(item.xmlGenerated, loaded.privateKeyPem, loaded.certPem);
      const diagnostics = this.signatureService.inspectSignedXml(signedXml);
      const updated = await this.prisma.dgiiCertificationCase.update({
        where: { id: item.id },
        data: {
          xmlSigned: signedXml,
          status: 'SIGNED',
          signedAt: new Date(),
          errorMessage: diagnostics.signedXmlHasSignature ? null : 'Advertencia: no se detecto nodo Signature en el XML firmado',
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

      return { case: serializeCase(updated), signedXml, warnings: diagnostics.signedXmlHasSignature ? [] : ['No se detecto nodo Signature'] };
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
        errorMessage: nextStatus === 'ERROR' ? result.message ?? 'DGII no devolvio TrackId ni respuesta valida' : null,
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
      where: { companyId, batchId, status: 'SIGNED' },
      orderBy: [{ sheetName: 'asc' }, { rowNumber: 'asc' }],
      select: { id: true, xmlSigned: true },
    });
    const errors: Array<{ caseId: number; message: string; errorCode: string }> = [];
    const trackIds: Array<{ caseId: number; trackId: string }> = [];
    let sent = 0;
    let skipped = 0;

    for (const item of cases) {
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

    return { total: cases.length, sent, skipped, failed: errors.length, trackIds, errors };
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
    const nextStatus = this.certificationStatusFromResult(result);
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
        errorMessage: nextStatus === 'ERROR' ? result.message ?? 'No se pudo consultar resultado DGII' : null,
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

  async deleteBatch(companyId: number, id: number) {
    await this.getBatch(companyId, id);
    await this.prisma.dgiiCertificationBatch.delete({ where: { id } });
    return { ok: true, deletedBatchId: id };
  }
}

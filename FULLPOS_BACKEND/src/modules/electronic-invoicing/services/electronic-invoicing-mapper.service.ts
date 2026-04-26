import { Prisma, PrismaClient } from '@prisma/client';
import {
  ElectronicInvoiceBuildInput,
  ElectronicInvoiceLineInput,
  ParsedInvoiceXmlMetadata,
  SupportedDocumentTypeCode,
} from '../types/electronic-invoice.types';
import {
  assertSupportedDocumentTypeCode,
  assertValidRnc,
  formatMoney,
  normalizeRnc,
  toPositiveMoney,
} from '../utils/validation.utils';
import { deepFindFirstNumber, deepFindFirstString, parseXml } from '../utils/xml.utils';

function toNumber(value: Prisma.Decimal | number | null | undefined) {
  if (value == null) return 0;
  return typeof value === 'number' ? value : value.toNumber();
}

function parseDate(value?: string) {
  if (!value) return undefined;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

function splitTaxAcrossLines(lines: Array<{ baseAmount: number }>, totalTax: number) {
  if (lines.length === 0) return [] as number[];
  if (totalTax <= 0) return lines.map(() => 0);

  const baseTotal = lines.reduce((sum, line) => sum + line.baseAmount, 0);
  if (baseTotal <= 0) {
    const equal = totalTax / lines.length;
    return lines.map((_, index) => (index === lines.length - 1 ? totalTax - equal * (lines.length - 1) : equal));
  }

  let assigned = 0;
  return lines.map((line, index) => {
    if (index === lines.length - 1) {
      return Math.round((totalTax - assigned) * 100) / 100;
    }
    const value = Math.round(((line.baseAmount / baseTotal) * totalTax) * 100) / 100;
    assigned += value;
    return value;
  });
}

export class ElectronicInvoicingMapperService {
  constructor(private readonly prisma: PrismaClient) {}

  async resolveCompanyOrThrow(companyRnc?: string | null, companyCloudId?: string | null) {
    const normalizedRnc = normalizeRnc(companyRnc);
    const cloudId = companyCloudId?.trim() ?? '';

    let company = null as Awaited<ReturnType<PrismaClient['company']['findFirst']>>;

    if (cloudId) {
      company = await this.prisma.company.findFirst({
        where: { cloudCompanyId: cloudId, isActive: true },
        include: { config: true },
      });
    }

    if (!company && normalizedRnc) {
      company = await this.prisma.company.findFirst({
        where: { rnc: normalizedRnc, isActive: true },
        include: { config: true },
      });
    }

    if (!company) {
      throw {
        status: 404,
        message: 'Compañía no encontrada',
        errorCode: 'COMPANY_NOT_FOUND',
      };
    }

    return company;
  }

  async mapSaleToOutbound(
    companyId: number,
    saleId: number,
    documentTypeCode: SupportedDocumentTypeCode,
    options?: {
      localCode?: string | null;
      companyCloudId?: string | null;
      companyRnc?: string | null;
    },
  ): Promise<ElectronicInvoiceBuildInput> {
    if (documentTypeCode !== '31' && documentTypeCode !== '32') {
      throw {
        status: 400,
        message: `La generación desde ventas solo soporta 31 y 32, no ${documentTypeCode}`,
        errorCode: 'DOCUMENT_TYPE_NOT_ELIGIBLE',
      };
    }

    const requestedLocalCode = options?.localCode?.trim() ?? '';
    const requestedCompanyCloudId = options?.companyCloudId?.trim() ?? '';
    const requestedCompanyRnc = normalizeRnc(options?.companyRnc);

    console.info('[electronic-invoicing.mapper] sale_lookup_start', {
      saleId,
      localCode: requestedLocalCode || null,
      companyId,
      companyCloudId: requestedCompanyCloudId || null,
      companyRnc: requestedCompanyRnc || null,
      documentTypeCode,
    });

    let sale = await this.prisma.sale.findFirst({
      where: { id: saleId, companyId },
      include: {
        items: true,
        company: { include: { config: true } },
      },
    });

    console.info('[electronic-invoicing.mapper] sale_lookup_by_id_result', {
      saleId,
      companyId,
      found: !!sale,
    });

    const triedCriteria: string[] = ['id+companyId'];

    if (!sale && requestedLocalCode) {
      triedCriteria.push('companyId+localCode');
      sale = await this.prisma.sale.findFirst({
        where: {
          companyId,
          localCode: requestedLocalCode,
        },
        include: {
          items: true,
          company: { include: { config: true } },
        },
      });

      console.info('[electronic-invoicing.mapper] sale_lookup_by_local_code_company_id_result', {
        saleId,
        localCode: requestedLocalCode,
        companyId,
        found: !!sale,
      });
    }

    if (!sale && requestedLocalCode && requestedCompanyCloudId) {
      triedCriteria.push('companyCloudId+localCode');
      sale = await this.prisma.sale.findFirst({
        where: {
          localCode: requestedLocalCode,
          company: {
            cloudCompanyId: requestedCompanyCloudId,
            isActive: true,
          },
        },
        include: {
          items: true,
          company: { include: { config: true } },
        },
      });

      console.info('[electronic-invoicing.mapper] sale_lookup_by_local_code_company_cloud_id_result', {
        saleId,
        localCode: requestedLocalCode,
        companyCloudId: requestedCompanyCloudId,
        found: !!sale,
      });
    }

    if (!sale && requestedLocalCode && requestedCompanyRnc) {
      triedCriteria.push('companyRnc+localCode');
      sale = await this.prisma.sale.findFirst({
        where: {
          localCode: requestedLocalCode,
          company: {
            rnc: requestedCompanyRnc,
            isActive: true,
          },
        },
        include: {
          items: true,
          company: { include: { config: true } },
        },
      });

      console.info('[electronic-invoicing.mapper] sale_lookup_by_local_code_company_rnc_result', {
        saleId,
        localCode: requestedLocalCode,
        companyRnc: requestedCompanyRnc,
        found: !!sale,
      });
    }

    if (!sale) {
      throw {
        status: 404,
        message: `Venta no encontrada. saleId=${saleId}, localCode=${requestedLocalCode || 'N/A'}, companyId=${companyId}, criterios=${triedCriteria.join(' -> ')}`,
        errorCode: 'SALE_NOT_FOUND',
      };
    }

    console.info('[electronic-invoicing.mapper] sale_lookup_found', {
      saleIdRequested: saleId,
      localCodeRequested: requestedLocalCode || null,
      companyIdRequested: companyId,
      sale: {
        id: sale.id,
        localCode: sale.localCode,
        companyId: sale.companyId,
      },
    });
    if (sale.deletedAt) {
      throw { status: 409, message: 'La venta está anulada o eliminada', errorCode: 'SALE_NOT_ACTIVE' };
    }
    if (sale.kind !== 'invoice' && sale.kind !== 'sale') {
      throw { status: 409, message: 'Solo las ventas facturables son elegibles', errorCode: 'SALE_KIND_NOT_ELIGIBLE' };
    }
    if (sale.status.toLowerCase() === 'cancelled' || sale.status.toUpperCase() === 'REFUNDED') {
      throw { status: 409, message: 'La venta no es elegible para e-CF', errorCode: 'SALE_STATUS_NOT_ELIGIBLE' };
    }

    if (!sale.company.rnc) {
      throw { status: 409, message: 'La compañía no tiene RNC configurado', errorCode: 'COMPANY_RNC_MISSING' };
    }
    assertValidRnc(sale.company.rnc, 'RNC del emisor');

    const issuerAddress = sale.company.config?.address?.trim();
    if (!issuerAddress) {
      throw { status: 409, message: 'La compañía no tiene dirección configurada', errorCode: 'COMPANY_ADDRESS_MISSING' };
    }

    if (documentTypeCode === '31') {
      assertValidRnc(sale.customerRncSnapshot, 'RNC del comprador');
      if (!(sale.customerNameSnapshot ?? '').trim()) {
        throw { status: 409, message: 'La venta 31 requiere nombre del comprador', errorCode: 'BUYER_NAME_MISSING' };
      }
    }

    if (sale.items.length === 0) {
      throw { status: 409, message: 'La venta no tiene items', errorCode: 'SALE_ITEMS_MISSING' };
    }

    const subtotalAmount = toPositiveMoney(toNumber(sale.subtotal));
    const taxAmount = toPositiveMoney(toNumber(sale.itbisAmount));
    const totalAmount = toPositiveMoney(toNumber(sale.total));

    if (totalAmount <= 0) {
      throw { status: 409, message: 'La venta debe tener un total mayor que cero', errorCode: 'INVALID_SALE_TOTAL' };
    }

    const taxShares = splitTaxAcrossLines(
      sale.items.map((item) => ({ baseAmount: toPositiveMoney(toNumber(item.totalLine)) })),
      taxAmount,
    );

    const lines: ElectronicInvoiceLineInput[] = sale.items.map((item, index) => ({
      lineNumber: index + 1,
      productCode: item.productCodeSnapshot,
      description: item.productNameSnapshot,
      quantity: toNumber(item.qty),
      unitPrice: toPositiveMoney(toNumber(item.unitPrice)),
      lineExtensionAmount: toPositiveMoney(toNumber(item.totalLine)),
      taxAmount: taxShares[index] ?? 0,
    }));

    return {
      ecf: '',
      documentTypeCode,
      issueDate: sale.createdAt,
      currencyCode: 'DOP',
      issuer: {
        rnc: normalizeRnc(sale.company.rnc),
        name: sale.company.name,
        address: issuerAddress,
        email: sale.company.config?.email,
        phone: sale.company.config?.phone,
      },
      buyer: {
        rnc: normalizeRnc(sale.customerRncSnapshot) || null,
        name: (sale.customerNameSnapshot ?? '').trim() || 'Consumidor Final',
        phone: sale.customerPhoneSnapshot,
      },
      lines,
      subtotalAmount,
      taxAmount,
      totalAmount,
    };
  }

  async mapCreditNoteToOutbound(companyId: number, originalInvoiceId: number, saleId: number, reason: string): Promise<ElectronicInvoiceBuildInput> {
    const [originalInvoice, sale] = await Promise.all([
      this.prisma.electronicInvoice.findFirst({ where: { id: originalInvoiceId, companyId, direction: 'outbound' } }),
      this.prisma.sale.findFirst({
        where: { id: saleId, companyId },
        include: { items: true, company: { include: { config: true } } },
      }),
    ]);

    if (!originalInvoice) {
      throw { status: 404, message: 'Factura original no encontrada', errorCode: 'ORIGINAL_INVOICE_NOT_FOUND' };
    }
    if (!sale) {
      throw { status: 404, message: 'Venta de corrección no encontrada', errorCode: 'CREDIT_SALE_NOT_FOUND' };
    }

    const taxAmount = toPositiveMoney(Math.abs(toNumber(sale.itbisAmount)));
    const baseAmounts = sale.items.map((item) => ({
      baseAmount: toPositiveMoney(Math.abs(toNumber(item.totalLine))),
    }));
    const taxShares = splitTaxAcrossLines(baseAmounts, taxAmount);
    const lines = sale.items.map((item, index) => ({
      lineNumber: index + 1,
      productCode: item.productCodeSnapshot,
      description: item.productNameSnapshot,
      quantity: Math.abs(toNumber(item.qty)),
      unitPrice: toPositiveMoney(toNumber(item.unitPrice)),
      lineExtensionAmount: toPositiveMoney(Math.abs(toNumber(item.totalLine))),
      taxAmount: taxShares[index] ?? 0,
    }));

    return {
      ecf: '',
      documentTypeCode: '34',
      issueDate: sale.createdAt,
      currencyCode: originalInvoice.currencyCode,
      issuer: {
        rnc: originalInvoice.issuerRnc,
        name: originalInvoice.issuerName,
        address: sale.company.config?.address,
        email: sale.company.config?.email,
        phone: sale.company.config?.phone,
      },
      buyer: {
        rnc: originalInvoice.buyerRnc,
        name: originalInvoice.buyerName ?? 'Comprador',
      },
      lines,
      subtotalAmount: toPositiveMoney(Math.abs(toNumber(sale.subtotal))),
      taxAmount,
      totalAmount: toPositiveMoney(Math.abs(toNumber(sale.total))),
      reference: {
        modifiedEcf: originalInvoice.ecf,
        modifiedDocumentTypeCode: originalInvoice.documentTypeCode,
        modifiedIssueDate: originalInvoice.issueDate,
        reason,
      },
    };
  }

  extractXmlMetadata(xml: string): ParsedInvoiceXmlMetadata {
    const parsed = parseXml(xml);
    const documentTypeCode = deepFindFirstString(parsed, ['TipoeCF', 'TipoDocumento']);
    const issueDate = parseDate(deepFindFirstString(parsed, ['FechaEmision', 'IssueDate', 'Fecha']));

    const result: ParsedInvoiceXmlMetadata = {
      ecf: deepFindFirstString(parsed, ['eNCF', 'eCF', 'NCF', 'ECF']),
      documentTypeCode,
      issuerRnc: normalizeRnc(deepFindFirstString(parsed, ['RNCEmisor', 'RncEmisor', 'EmisorRNC'])),
      issuerName: deepFindFirstString(parsed, ['RazonSocialEmisor', 'NombreEmisor', 'EmisorNombre']),
      buyerRnc: normalizeRnc(deepFindFirstString(parsed, ['RNCComprador', 'RncComprador', 'CompradorRNC'])),
      buyerName: deepFindFirstString(parsed, ['RazonSocialComprador', 'NombreComprador', 'CompradorNombre']),
      issueDate,
      totalAmount: deepFindFirstNumber(parsed, ['MontoTotal', 'TotalAmount', 'Total']),
      taxAmount: deepFindFirstNumber(parsed, ['ITBISTotal', 'TaxAmount', 'MontoITBIS']),
      currencyCode: deepFindFirstString(parsed, ['Moneda', 'CurrencyCode']),
    };

    if (documentTypeCode) {
      result.documentTypeCode = assertSupportedDocumentTypeCode(documentTypeCode);
    }

    return result;
  }
}
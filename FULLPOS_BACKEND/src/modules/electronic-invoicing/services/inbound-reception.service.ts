import { PrismaClient } from '@prisma/client';
import { DgiiAuthService } from './dgii-auth.service';
import { ElectronicInvoicingMapperService } from './electronic-invoicing-mapper.service';
import { ElectronicInvoicingAuditService } from './electronic-invoicing-audit.service';
import { sha256Hex } from '../utils/hash.utils';
import { normalizeRnc } from '../utils/validation.utils';

export class InboundReceptionService {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly auth: DgiiAuthService,
    private readonly mapper: ElectronicInvoicingMapperService,
    private readonly audit: ElectronicInvoicingAuditService,
  ) {}

  private toJsonValue(value: unknown) {
    return value == null ? null : JSON.parse(JSON.stringify(value));
  }

  async receive(xml: string, companyRnc: string | undefined, companyCloudId: string | undefined, authHeader: string | undefined, requestId?: string) {
    const metadata = this.mapper.extractXmlMetadata(xml);
    const company = await this.mapper.resolveCompanyOrThrow(companyRnc || metadata.buyerRnc, companyCloudId);

    await this.auth.assertInboundToken(company.id, 0, authHeader);

    if (company.rnc && metadata.buyerRnc && normalizeRnc(company.rnc) !== normalizeRnc(metadata.buyerRnc)) {
      throw {
        status: 409,
        message: 'El XML recibido no corresponde a esta compañía receptora',
        errorCode: 'INBOUND_COMPANY_MISMATCH',
      };
    }

    if (!metadata.ecf || !metadata.documentTypeCode || !metadata.issuerRnc || !metadata.issuerName) {
      throw {
        status: 400,
        message: 'No se pudo extraer la metadata mínima del XML entrante',
        errorCode: 'INBOUND_XML_METADATA_INVALID',
      };
    }

    const existing = await this.prisma.electronicInvoice.findFirst({
      where: { companyId: company.id, ecf: metadata.ecf },
    });

    const invoice = existing
      ? await this.prisma.electronicInvoice.update({
          where: { id: existing.id },
          data: {
            xmlSigned: xml,
            xmlHash: sha256Hex(xml),
            dgiiStatus: 'RECEIVED',
            internalStatus: existing.internalStatus,
            commercialStatus: existing.commercialStatus,
            dgiiRawResponseJson: { inboundUpdatedAt: new Date().toISOString() },
          },
        })
      : await this.prisma.electronicInvoice.create({
          data: {
            companyId: company.id,
            branchId: 0,
            direction: 'inbound',
            documentTypeCode: metadata.documentTypeCode,
            ecf: metadata.ecf,
            sequenceNumber: Number(metadata.ecf.slice(3)),
            issuerRnc: metadata.issuerRnc,
            issuerName: metadata.issuerName,
            buyerRnc: metadata.buyerRnc ?? normalizeRnc(company.rnc),
            buyerName: metadata.buyerName ?? company.name,
            issueDate: metadata.issueDate ?? new Date(),
            totalAmount: metadata.totalAmount ?? 0,
            taxAmount: metadata.taxAmount ?? 0,
            currencyCode: metadata.currencyCode ?? 'DOP',
            xmlSigned: xml,
            xmlHash: sha256Hex(xml),
            dgiiStatus: 'RECEIVED',
            commercialStatus: 'PENDING',
            internalStatus: 'GENERATED',
          },
        });

    await this.prisma.electronicInvoiceStatusHistory.create({
      data: {
        electronicInvoiceId: invoice.id,
        fromStatus: existing?.internalStatus ?? null,
        toStatus: invoice.internalStatus,
        note: existing ? 'XML inbound actualizado' : 'XML inbound recibido',
        rawPayloadJson: this.toJsonValue(metadata),
        createdBy: 'public-reception',
      },
    });

    await this.audit.log({
      companyId: company.id,
      invoiceId: invoice.id,
      eventType: 'inbound.received',
      eventSource: 'PUBLIC_API',
      message: `e-CF entrante ${invoice.ecf} recibido`,
      payload: metadata,
      requestId,
    });

    return {
      ok: true,
      acknowledged: true,
      invoiceId: invoice.id,
      ecf: invoice.ecf,
      receivedAt: new Date().toISOString(),
    };
  }
}
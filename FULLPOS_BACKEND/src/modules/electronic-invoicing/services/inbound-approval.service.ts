import { PrismaClient } from '@prisma/client';
import { DgiiAuthService } from './dgii-auth.service';
import { ElectronicInvoicingMapperService } from './electronic-invoicing-mapper.service';
import { ElectronicInvoicingAuditService } from './electronic-invoicing-audit.service';

export class InboundApprovalService {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly auth: DgiiAuthService,
    private readonly mapper: ElectronicInvoicingMapperService,
    private readonly audit: ElectronicInvoicingAuditService,
  ) {}

  async receiveApproval(
    companyRnc: string | undefined,
    companyCloudId: string | undefined,
    ecf: string | undefined,
    approved: boolean,
    reason: string | null | undefined,
    authHeader: string | undefined,
    xml?: string,
    requestId?: string,
  ) {
    const parsed = xml ? this.mapper.extractXmlMetadata(xml) : undefined;
    const company = await this.mapper.resolveCompanyOrThrow(companyRnc || parsed?.issuerRnc || parsed?.buyerRnc, companyCloudId);
    await this.auth.assertInboundToken(company.id, 0, authHeader);

    const resolvedEcf = ecf ?? parsed?.ecf;
    if (!resolvedEcf) {
      throw { status: 400, message: 'e-CF requerido para aprobación comercial', errorCode: 'APPROVAL_ECF_REQUIRED' };
    }

    const invoice = await this.prisma.electronicInvoice.findFirst({
      where: { companyId: company.id, ecf: resolvedEcf },
    });
    if (!invoice) {
      throw { status: 404, message: 'No se encontró el documento electrónico', errorCode: 'APPROVAL_INVOICE_NOT_FOUND' };
    }

    const internalStatus = approved ? 'COMMERCIAL_APPROVED' : 'COMMERCIAL_REJECTED';
    const commercialStatus = approved ? 'APPROVED' : 'REJECTED';
    const updated = await this.prisma.electronicInvoice.update({
      where: { id: invoice.id },
      data: {
        internalStatus,
        commercialStatus,
        rejectionMessage: approved ? null : reason ?? invoice.rejectionMessage,
      },
    });

    await this.prisma.electronicInvoiceStatusHistory.create({
      data: {
        electronicInvoiceId: invoice.id,
        fromStatus: invoice.internalStatus,
        toStatus: internalStatus,
        note: approved ? 'Aprobación comercial recibida' : `Rechazo comercial recibido: ${reason ?? 'sin detalle'}`,
        rawPayloadJson: xml ? { xml } : { approved, reason },
        createdBy: 'public-approval',
      },
    });

    await this.audit.log({
      companyId: company.id,
      invoiceId: invoice.id,
      eventType: approved ? 'commercial.approved' : 'commercial.rejected',
      eventSource: 'PUBLIC_API',
      message: approved
        ? `Se recibió aprobación comercial para ${resolvedEcf}`
        : `Se recibió rechazo comercial para ${resolvedEcf}`,
      payload: { reason, xml },
      requestId,
    });

    return {
      ok: true,
      invoiceId: updated.id,
      ecf: updated.ecf,
      commercialStatus: updated.commercialStatus,
      internalStatus: updated.internalStatus,
    };
  }
}
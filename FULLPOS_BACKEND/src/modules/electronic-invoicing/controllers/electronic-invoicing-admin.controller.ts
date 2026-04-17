import { Request, Response } from 'express';
import { z } from 'zod';
import { ElectronicInvoicingService } from '../services/electronic-invoicing.service';
import { createCertificateDtoSchema } from '../dto/certificate.dto';
import { upsertElectronicConfigDtoSchema } from '../dto/config.dto';
import { createSequenceDtoSchema } from '../dto/sequence.dto';
import { createEcfDtoSchema } from '../dto/create-ecf.dto';
import { sendEcfDtoSchema } from '../dto/send-ecf.dto';
import { createCreditNoteDtoSchema } from '../dto/credit-note.dto';

const listQuerySchema = z.object({
  documentTypeCode: z.string().trim().optional(),
  internalStatus: z.string().trim().optional(),
  dgiiStatus: z.string().trim().optional(),
  search: z.string().trim().optional(),
  fromDate: z.string().datetime().optional(),
  toDate: z.string().datetime().optional(),
});

export function createElectronicInvoicingAdminController(service: ElectronicInvoicingService) {
  return {
    getConfig: async (req: Request, res: Response) => {
      const branchId = Number(req.query.branchId ?? 0);
      const config = await service.getConfig(req.user!.companyId, Number.isFinite(branchId) ? branchId : 0);
      res.json(config);
    },

    upsertConfig: async (req: Request, res: Response) => {
      const dto = upsertElectronicConfigDtoSchema.parse(req.body);
      const config = await service.upsertConfig(req.user!.companyId, dto, req.user!.username, req.requestId);
      res.json(config);
    },

    createSequence: async (req: Request, res: Response) => {
      const dto = createSequenceDtoSchema.parse(req.body);
      const sequence = await service.upsertSequence(req.user!.companyId, dto, req.user!.username, req.requestId);
      res.status(201).json(sequence);
    },

    createCertificate: async (req: Request, res: Response) => {
      const dto = createCertificateDtoSchema.parse(req.body);
      const certificate = await service.registerCertificate(req.user!.companyId, dto, req.user!.username, req.requestId);
      res.status(201).json(certificate);
    },

    generateOutbound: async (req: Request, res: Response) => {
      const dto = createEcfDtoSchema.parse(req.body);
      const invoice = await service.generateOutbound(req.user!.companyId, dto, req.user!.username, req.requestId);
      res.status(201).json(invoice);
    },

    signOutbound: async (req: Request, res: Response) => {
      const dto = sendEcfDtoSchema.parse(req.body);
      const invoice = await service.signOutbound(req.user!.companyId, dto, req.user!.username, req.requestId);
      res.json(invoice);
    },

    listOutbound: async (req: Request, res: Response) => {
      const query = listQuerySchema.parse(req.query);
      const invoices = await service.listOutboundInvoices(req.user!.companyId, {
        ...query,
        fromDate: query.fromDate ? new Date(query.fromDate) : undefined,
        toDate: query.toDate ? new Date(query.toDate) : undefined,
      });
      res.json(invoices);
    },

    getOutbound: async (req: Request, res: Response) => {
      const invoiceId = Number(req.params.id);
      const invoice = await service.getOutboundInvoice(req.user!.companyId, invoiceId);
      res.json(invoice);
    },

    getXmlVariant: async (req: Request, res: Response) => {
      const invoiceId = Number(req.params.id);
      const variant = req.params.variant === 'signed' ? 'signed' : 'unsigned';
      const xml = await service.getXmlVariant(req.user!.companyId, invoiceId, variant);
      res.setHeader('content-type', 'application/xml; charset=utf-8');
      res.setHeader('content-disposition', `attachment; filename="${xml.filename}"`);
      res.send(xml.xml);
    },

    getAuditTimeline: async (req: Request, res: Response) => {
      const invoiceId = Number(req.params.invoiceId);
      const timeline = await service.getAuditTimeline(req.user!.companyId, invoiceId);
      res.json(timeline);
    },

    createCreditNote: async (req: Request, res: Response) => {
      const dto = createCreditNoteDtoSchema.parse(req.body);
      const invoice = await service.createCreditNote(req.user!.companyId, dto, req.user!.username, req.requestId);
      res.status(201).json(invoice);
    },
  };
}
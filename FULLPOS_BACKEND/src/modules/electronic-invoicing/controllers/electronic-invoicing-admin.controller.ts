import { Request, Response } from 'express';
import { z } from 'zod';
import { ElectronicInvoicingService } from '../services/electronic-invoicing.service';
import { createCertificateDtoSchema } from '../dto/certificate.dto';
import { upsertElectronicConfigDtoSchema } from '../dto/config.dto';
import { createSequenceDtoSchema } from '../dto/sequence.dto';
import { createEcfDtoSchema } from '../dto/create-ecf.dto';
import { sendEcfDtoSchema } from '../dto/send-ecf.dto';
import { createCreditNoteDtoSchema } from '../dto/credit-note.dto';

export const configQuerySchema = z.object({
  branchId: z.coerce.number().int().min(0).optional().default(0),
});

export const listQuerySchema = z.object({
  documentTypeCode: z.string().trim().optional(),
  internalStatus: z.string().trim().optional(),
  dgiiStatus: z.string().trim().optional(),
  search: z.string().trim().optional(),
  fromDate: z.string().datetime().optional(),
  toDate: z.string().datetime().optional(),
});

export const invoiceIdParamsSchema = z.object({
  id: z.coerce.number().int().positive(),
});

export const invoiceIdVariantParamsSchema = z.object({
  id: z.coerce.number().int().positive(),
  variant: z.string().trim().min(1),
});

export const auditTimelineParamsSchema = z.object({
  invoiceId: z.coerce.number().int().positive(),
});

export function createElectronicInvoicingAdminController(service: ElectronicInvoicingService) {
  return {
    getConfig: async (req: Request, res: Response) => {
      const query = req.query as unknown as typeof configQuerySchema['_output'];
      const config = await service.getConfig(req.user!.companyId, query.branchId);
      res.json(config);
    },

    upsertConfig: async (req: Request, res: Response) => {
      const dto = req.body as typeof upsertElectronicConfigDtoSchema['_output'];
      const config = await service.upsertConfig(req.user!.companyId, dto, req.user!.username, req.requestId);
      res.json(config);
    },

    createSequence: async (req: Request, res: Response) => {
      const dto = req.body as typeof createSequenceDtoSchema['_output'];
      const sequence = await service.upsertSequence(req.user!.companyId, dto, req.user!.username, req.requestId);
      res.status(201).json(sequence);
    },

    createCertificate: async (req: Request, res: Response) => {
      const dto = req.body as typeof createCertificateDtoSchema['_output'];
      const certificate = await service.registerCertificate(req.user!.companyId, dto, req.user!.username, req.requestId);
      res.status(201).json(certificate);
    },

    generateOutbound: async (req: Request, res: Response) => {
      const dto = req.body as typeof createEcfDtoSchema['_output'];
      const invoice = await service.generateOutbound(req.user!.companyId, dto, req.user!.username, req.requestId);
      res.status(201).json(invoice);
    },

    signOutbound: async (req: Request, res: Response) => {
      const dto = req.body as typeof sendEcfDtoSchema['_output'];
      const invoice = await service.signOutbound(req.user!.companyId, dto, req.user!.username, req.requestId);
      res.json(invoice);
    },

    listOutbound: async (req: Request, res: Response) => {
      const query = req.query as typeof listQuerySchema['_output'];
      const invoices = await service.listOutboundInvoices(req.user!.companyId, {
        ...query,
        fromDate: query.fromDate ? new Date(query.fromDate) : undefined,
        toDate: query.toDate ? new Date(query.toDate) : undefined,
      });
      res.json(invoices);
    },

    getOutbound: async (req: Request, res: Response) => {
      const params = req.params as unknown as typeof invoiceIdParamsSchema['_output'];
      const invoiceId = params.id;
      const invoice = await service.getOutboundInvoice(req.user!.companyId, invoiceId);
      res.json(invoice);
    },

    getXmlVariant: async (req: Request, res: Response) => {
      const params = req.params as unknown as typeof invoiceIdVariantParamsSchema['_output'];
      const invoiceId = params.id;
      const variant = params.variant === 'signed' ? 'signed' : 'unsigned';
      const xml = await service.getXmlVariant(req.user!.companyId, invoiceId, variant);
      res.setHeader('content-type', 'application/xml; charset=utf-8');
      res.setHeader('content-disposition', `attachment; filename="${xml.filename}"`);
      res.send(xml.xml);
    },

    getAuditTimeline: async (req: Request, res: Response) => {
      const params = req.params as unknown as typeof auditTimelineParamsSchema['_output'];
      const invoiceId = params.invoiceId;
      const timeline = await service.getAuditTimeline(req.user!.companyId, invoiceId);
      res.json(timeline);
    },

    createCreditNote: async (req: Request, res: Response) => {
      const dto = req.body as typeof createCreditNoteDtoSchema['_output'];
      const invoice = await service.createCreditNote(req.user!.companyId, dto, req.user!.username, req.requestId);
      res.status(201).json(invoice);
    },
  };
}
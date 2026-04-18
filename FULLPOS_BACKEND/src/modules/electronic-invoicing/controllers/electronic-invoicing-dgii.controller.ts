import { Request, Response } from 'express';
import { ElectronicInvoicingService } from '../services/electronic-invoicing.service';

export function createElectronicInvoicingDgiiController(service: ElectronicInvoicingService) {
  return {
    submitOutbound: async (req: Request, res: Response) => {
      const dto = req.body as { invoiceId: number; force: boolean };
      const invoice = await service.submitOutbound(req.user!.companyId, dto, req.user!.username, req.requestId);
      res.json(invoice);
    },

    queryTrackResult: async (req: Request, res: Response) => {
      const result = await service.queryOutboundResult(
        req.user!.companyId,
        req.params.trackId,
        req.user!.username,
        req.requestId,
      );
      res.json(result);
    },
  };
}
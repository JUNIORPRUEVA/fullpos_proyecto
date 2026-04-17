import { Request, Response } from 'express';
import { ElectronicInvoicingService } from '../services/electronic-invoicing.service';
import { sendEcfDtoSchema } from '../dto/send-ecf.dto';

export function createElectronicInvoicingDgiiController(service: ElectronicInvoicingService) {
  return {
    submitOutbound: async (req: Request, res: Response) => {
      const dto = sendEcfDtoSchema.parse(req.body);
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
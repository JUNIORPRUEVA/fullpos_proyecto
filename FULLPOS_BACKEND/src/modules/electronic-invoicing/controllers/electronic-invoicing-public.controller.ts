import { Request, Response } from 'express';
import { DgiiAuthService } from '../services/dgii-auth.service';
import { InboundReceptionService } from '../services/inbound-reception.service';
import { InboundApprovalService } from '../services/inbound-approval.service';
import { requestSeedDtoSchema, validateSeedDtoSchema } from '../dto/validate-seed.dto';
import { receiveEcfDtoSchema } from '../dto/receive-ecf.dto';
import { commercialApprovalDtoSchema } from '../dto/commercial-approval.dto';
import { deepFindFirstString, parseXml } from '../utils/xml.utils';

function resolveXmlPayload(req: Request) {
  if (typeof req.body === 'string') {
    return req.body;
  }
  return req.body?.xml;
}

export function createElectronicInvoicingPublicController(
  authService: DgiiAuthService,
  receptionService: InboundReceptionService,
  approvalService: InboundApprovalService,
) {
  const inferApprovalFromXml = (xml?: string) => {
    if (!xml) return undefined;
    try {
      const parsed = parseXml(xml);
      const raw = deepFindFirstString(parsed, [
        'EstadoAprobacion',
        'Aprobado',
        'Resultado',
        'Estado',
        'status',
      ])?.toLowerCase();

      if (!raw) return undefined;
      if (raw.includes('aprob') || raw === 'true' || raw === '1' || raw.includes('acept')) return true;
      if (raw.includes('rechaz') || raw === 'false' || raw === '0') return false;
      return undefined;
    } catch {
      return undefined;
    }
  };

  return {
    createSeed: async (req: Request, res: Response) => {
      const dto = requestSeedDtoSchema.parse(req.body);
      const seed = await authService.createSeed(dto.companyRnc, dto.companyCloudId, dto.branchId, req.requestId);
      res.status(201).json(seed);
    },

    validateSeed: async (req: Request, res: Response) => {
      const dto = validateSeedDtoSchema.parse(req.body);
      const token = await authService.validateSignedSeed(
        dto.companyRnc,
        dto.companyCloudId,
        dto.branchId,
        dto.signedSeedXml,
        req.requestId,
      );
      res.json(token);
    },

    receiveEcf: async (req: Request, res: Response) => {
      const xml = resolveXmlPayload(req);
      const dto = receiveEcfDtoSchema.parse({ ...(typeof req.body === 'object' ? req.body : {}), xml });
      const response = await receptionService.receive(
        dto.xml!,
        dto.companyRnc,
        dto.companyCloudId,
        req.header('authorization'),
        req.requestId,
      );
      res.status(201).json(response);
    },

    receiveCommercialApproval: async (req: Request, res: Response) => {
      const xml = resolveXmlPayload(req);
      const dto = commercialApprovalDtoSchema.parse({ ...(typeof req.body === 'object' ? req.body : {}), xml });
      const approved = dto.approved ?? inferApprovalFromXml(xml);
      if (approved == null) {
        res.status(400).json({ message: 'No se pudo determinar el estado de aprobación comercial' });
        return;
      }
      const response = await approvalService.receiveApproval(
        dto.companyRnc,
        dto.companyCloudId,
        dto.ecf,
        approved,
        dto.reason,
        req.header('authorization'),
        xml,
        req.requestId,
      );
      res.json(response);
    },
  };
}
import { NextFunction, Request, RequestHandler, Response } from 'express';
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

function validateResolvedBody<T>(resolver: (req: Request) => unknown, schema: { safeParse: (value: unknown) => any }): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    const parsed = schema.safeParse(resolver(req));
    if (!parsed.success) {
      return next(parsed.error);
    }

    req.body = parsed.data;
    next();
  };
}

export const validateReceiveEcfRequest = validateResolvedBody(
  (req) => ({ ...(typeof req.body === 'object' && req.body ? req.body : {}), xml: resolveXmlPayload(req) }),
  receiveEcfDtoSchema,
);

export const validateCommercialApprovalRequest = validateResolvedBody(
  (req) => ({ ...(typeof req.body === 'object' && req.body ? req.body : {}), xml: resolveXmlPayload(req) }),
  commercialApprovalDtoSchema,
);

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
      const dto = req.body as typeof requestSeedDtoSchema['_output'];
      const seed = await authService.createSeed(dto.companyRnc, dto.companyCloudId, dto.branchId, req.requestId);
      res.status(201).json(seed);
    },

    validateSeed: async (req: Request, res: Response) => {
      const dto = req.body as typeof validateSeedDtoSchema['_output'];
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
      const dto = req.body as typeof receiveEcfDtoSchema['_output'];
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
      const dto = req.body as typeof commercialApprovalDtoSchema['_output'];
      const approved = dto.approved ?? inferApprovalFromXml(dto.xml);
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
        dto.xml,
        req.requestId,
      );
      res.json(response);
    },
  };
}
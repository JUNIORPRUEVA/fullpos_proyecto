import path from 'path';
import multer from 'multer';
import { Request, RequestHandler, Response } from 'express';
import { z } from 'zod';
import { DgiiCertificationService } from '../services/dgii-certification.service';

const excelUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024 },
});

export const uploadDgiiCertificationExcel = excelUpload.single('file');

const certificationLocatorBaseSchema = z.object({
    companyRnc: z.string().trim().min(3).optional(),
    companyCloudId: z.string().trim().min(6).optional(),
  }).strict();

export const certificationLocatorSchema = certificationLocatorBaseSchema
  .refine((value) => !!value.companyRnc || !!value.companyCloudId, {
    message: 'RNC o ID interno requerido',
    path: ['companyRnc'],
  });

export const certificationBatchParamsSchema = z.object({
  id: z.coerce.number().int().positive(),
});

export const certificationCaseParamsSchema = z.object({
  id: z.coerce.number().int().positive(),
});

export const certificationCasesQuerySchema = certificationLocatorBaseSchema.extend({
  sheetName: z.preprocess(
    (value) => String(value ?? '').trim().toUpperCase() || undefined,
    z.enum(['ECF', 'RFCE']).optional(),
  ),
  status: z.string().trim().optional(),
  tipoEcf: z.string().trim().optional(),
  search: z.string().trim().optional(),
}).refine((value) => !!value.companyRnc || !!value.companyCloudId, {
  message: 'RNC o ID interno requerido',
  path: ['companyRnc'],
});

function requestFile(req: Request) {
  return (req as Request & {
    file?: {
      buffer: Buffer;
      originalname: string;
      mimetype: string;
      size: number;
    };
  }).file;
}

export const validateDgiiCertificationExcelUpload: RequestHandler = (req, res, next) => {
  const file = requestFile(req);
  if (!file) {
    return res.status(400).json({
      message: 'Archivo Excel DGII requerido',
      errorCode: 'DGII_CERTIFICATION_FILE_REQUIRED',
    });
  }

  if (path.extname(file.originalname).toLowerCase() !== '.xlsx') {
    return res.status(400).json({
      message: 'El archivo debe tener extension .xlsx',
      errorCode: 'DGII_CERTIFICATION_INVALID_FILE',
    });
  }

  const parsed = certificationLocatorSchema.safeParse(req.body);
  if (!parsed.success) return next(parsed.error);
  req.body = parsed.data;
  return next();
};

export function createElectronicInvoicingCertificationController(service: DgiiCertificationService) {
  const resolveCompany = (req: Request) => {
    const source = req.method === 'GET' || req.method === 'DELETE' ? req.query : req.body;
    const locators = source as { companyRnc?: string; companyCloudId?: string };
    return service.resolveCompany(locators.companyRnc, locators.companyCloudId, req.requestId);
  };

  return {
    importExcel: async (req: Request, res: Response) => {
      const file = requestFile(req)!;
      const locators = req.body as typeof certificationLocatorSchema['_output'];
      const company = await service.resolveCompany(locators.companyRnc, locators.companyCloudId, req.requestId);
      const result = await service.importExcel({
        companyId: company.id,
        companyRnc: company.rnc ?? locators.companyRnc,
        fileName: file.originalname,
        buffer: file.buffer,
        requestId: req.requestId,
      });
      res.status(201).json(result);
    },

    listBatches: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      res.json(await service.listBatches(company.id));
    },

    getBatch: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationBatchParamsSchema['_output'];
      res.json(await service.getBatch(company.id, params.id));
    },

    listCases: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationBatchParamsSchema['_output'];
      const query = req.query as unknown as typeof certificationCasesQuerySchema['_output'];
      res.json(await service.listCases(company.id, params.id, query));
    },

    getCase: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationCaseParamsSchema['_output'];
      res.json(await service.getCase(company.id, params.id));
    },

    deleteBatch: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationBatchParamsSchema['_output'];
      res.json(await service.deleteBatch(company.id, params.id));
    },
  };
}

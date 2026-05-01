import path from 'path';
import multer from 'multer';
import { Request, RequestHandler, Response } from 'express';
import { z } from 'zod';
import { DgiiCertificationService } from '../services/dgii-certification.service';
import { DgiiAuthService } from '../services/dgii-auth.service';

const excelUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024 },
});

export const uploadDgiiCertificationExcel = excelUpload.single('file');

const signedSeedUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 },
});

export const uploadDgiiSignedSeedXml = signedSeedUpload.single('file');

const signedCaseXmlUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 },
});

export const uploadDgiiCertificationSignedCaseXml = signedCaseXmlUpload.single('file');

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

export const certificationResetSchema = certificationLocatorBaseSchema.extend({
  force: z.coerce.boolean().optional().default(false),
}).strict().refine((value) => !!value.companyRnc || !!value.companyCloudId, {
  message: 'RNC o ID interno requerido',
  path: ['companyRnc'],
});

export const certificationAiAuditSchema = certificationLocatorBaseSchema.extend({
  aiApiKey: z.string().trim().optional(),
  aiModel: z.string().trim().optional(),
}).strict().refine((value) => !!value.companyRnc || !!value.companyCloudId, {
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

export const validateDgiiSignedSeedXmlUpload: RequestHandler = (req, res, next) => {
  const file = requestFile(req);
  if (!file) {
    return res.status(400).json({
      message: 'Archivo XML de semilla firmada requerido',
      errorCode: 'DGII_SIGNED_SEED_FILE_REQUIRED',
    });
  }

  if (path.extname(file.originalname).toLowerCase() !== '.xml') {
    return res.status(400).json({
      message: 'El archivo de semilla firmada debe tener extension .xml',
      errorCode: 'DGII_SIGNED_SEED_INVALID_FILE',
    });
  }

  const parsed = certificationLocatorSchema.safeParse(req.body);
  if (!parsed.success) return next(parsed.error);
  req.body = parsed.data;
  return next();
};

export const validateDgiiCertificationSignedCaseXmlUpload: RequestHandler = (req, res, next) => {
  const file = requestFile(req);
  if (!file) {
    return res.status(400).json({
      message: 'Archivo XML firmado requerido',
      errorCode: 'DGII_CERTIFICATION_SIGNED_XML_FILE_REQUIRED',
    });
  }

  if (path.extname(file.originalname).toLowerCase() !== '.xml') {
    return res.status(400).json({
      message: 'El archivo firmado debe tener extension .xml',
      errorCode: 'DGII_CERTIFICATION_SIGNED_XML_INVALID_FILE',
    });
  }

  const parsed = certificationLocatorSchema.safeParse(req.body);
  if (!parsed.success) return next(parsed.error);
  req.body = parsed.data;
  return next();
};

export function createElectronicInvoicingCertificationController(
  service: DgiiCertificationService,
  authService: DgiiAuthService,
) {
  const resolveCompany = (req: Request) => {
    const source = req.method === 'GET' || req.method === 'DELETE' ? req.query : req.body;
    const locators = source as { companyRnc?: string; companyCloudId?: string };
    return service.resolveCompany(locators.companyRnc, locators.companyCloudId, req.requestId);
  };

  return {
    diagnostics: async (req: Request, res: Response) => {
      const parsed = certificationLocatorBaseSchema.safeParse(req.query);
      let companyId: number | undefined;
      if (parsed.success && (parsed.data.companyRnc || parsed.data.companyCloudId)) {
        const company = await service.resolveCompany(parsed.data.companyRnc, parsed.data.companyCloudId, req.requestId);
        companyId = company.id;
      }
      res.json(await service.buildDiagnostics(companyId));
    },

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

    downloadManualSeed: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const environment = await service.getCompanyDgiiEnvironment(company.id);
      const result = await authService.requestManualSeedForSigning(company.id, environment, req.requestId);
      const safeRnc = String(company.rnc ?? 'dgii').replace(/[^0-9A-Za-z_-]/g, '');
      const fileName = `dgii-semilla-${safeRnc || 'empresa'}.xml`;
      res
        .status(200)
        .type('application/xml')
        .set('Content-Disposition', `attachment; filename="${fileName}"`)
        .set('X-DGII-Seed-Root', result.meta.rootElement ?? '')
        .send(result.seedXml);
    },

    uploadManualSignedSeed: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const file = requestFile(req)!;
      const environment = await service.getCompanyDgiiEnvironment(company.id);
      const signedSeedXml = file.buffer.toString('utf8');
      const result = await authService.validateManualSignedSeed(
        company.id,
        environment,
        signedSeedXml,
        req.requestId,
      );
      res.json(result);
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

    generateCaseXml: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationCaseParamsSchema['_output'];
      res.json(await service.generateXmlForCase(company.id, params.id, req.requestId));
    },

    getCaseXml: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationCaseParamsSchema['_output'];
      const xml = await service.getGeneratedXml(company.id, params.id);
      res.type('application/xml').send(xml);
    },

    getCaseSignedXml: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationCaseParamsSchema['_output'];
      const xml = await service.getSignedXml(company.id, params.id);
      res.type('application/xml').send(xml);
    },

    uploadManualSignedCaseXml: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationCaseParamsSchema['_output'];
      const file = requestFile(req)!;
      const signedXml = file.buffer.toString('utf8');
      res.json(await service.importManualSignedCaseXml(company.id, params.id, signedXml, file.originalname, req.requestId));
    },

    validateCaseXml: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationCaseParamsSchema['_output'];
      res.json(await service.validateCaseXml(company.id, params.id));
    },

    validateCaseXsd: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationCaseParamsSchema['_output'];
      res.json(await service.validateCaseXsd(company.id, params.id));
    },

    auditCase: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationCaseParamsSchema['_output'];
      res.json(await service.auditCase(company.id, params.id));
    },

    aiAuditCase: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationCaseParamsSchema['_output'];
      const body = req.body as typeof certificationAiAuditSchema['_output'];
      res.json(await service.aiAuditCase(company.id, params.id, body.aiApiKey ?? null, body.aiModel ?? null));
    },

    preflightCase: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationCaseParamsSchema['_output'];
      res.json(await service.preflightCase(company.id, params.id));
    },

    generateBatchXml: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationBatchParamsSchema['_output'];
      res.json(await service.generateXmlForBatch(company.id, params.id, req.requestId));
    },

    preflightBatch: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationBatchParamsSchema['_output'];
      res.json(await service.preflightBatch(company.id, params.id));
    },

    auditBatch: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationBatchParamsSchema['_output'];
      res.json(await service.auditBatch(company.id, params.id));
    },

    aiAuditBatch: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationBatchParamsSchema['_output'];
      const body = req.body as typeof certificationAiAuditSchema['_output'];
      res.json(await service.aiAuditBatch(company.id, params.id, body.aiApiKey ?? null, body.aiModel ?? null));
    },

    signCase: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationCaseParamsSchema['_output'];
      res.json(await service.signCase(company.id, params.id, req.requestId));
    },

    signBatch: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationBatchParamsSchema['_output'];
      res.json(await service.signBatch(company.id, params.id, req.requestId));
    },

    sendCase: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationCaseParamsSchema['_output'];
      res.json(await service.sendCase(company.id, params.id, req.requestId));
    },

    sendBatch: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationBatchParamsSchema['_output'];
      res.json(await service.sendBatch(company.id, params.id, req.requestId));
    },

    reprocessAndSendBatch: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationBatchParamsSchema['_output'];
      res.json(await service.reprocessAndSendBatch(company.id, params.id, req.requestId));
    },

    queryCaseResult: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationCaseParamsSchema['_output'];
      res.json(await service.queryCaseResult(company.id, params.id, req.requestId));
    },

    queryBatchResults: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationBatchParamsSchema['_output'];
      res.json(await service.queryBatchResults(company.id, params.id, req.requestId));
    },

    resetCase: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationCaseParamsSchema['_output'];
      const body = req.body as typeof certificationResetSchema['_output'];
      res.json(await service.resetCase(company.id, params.id, body.force, req.requestId));
    },

    resetBatch: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationBatchParamsSchema['_output'];
      const body = req.body as typeof certificationResetSchema['_output'];
      res.json(await service.resetBatch(company.id, params.id, body.force, req.requestId));
    },

    getBatchSummary: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationBatchParamsSchema['_output'];
      res.json(await service.getBatchSummary(company.id, params.id));
    },

    deleteBatch: async (req: Request, res: Response) => {
      const company = await resolveCompany(req);
      const params = req.params as unknown as typeof certificationBatchParamsSchema['_output'];
      res.json(await service.deleteBatch(company.id, params.id));
    },
  };
}

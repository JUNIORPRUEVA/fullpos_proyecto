import { Prisma } from '@prisma/client';
import { prisma } from '../../config/prisma';

export type CompanyIdentityInput = {
  companyId?: number;
  companyRnc?: string;
  companyCloudId?: string;
  companyTenantKey?: string;
  businessId?: string;
  deviceId?: string;
  terminalId?: string;
  companyName?: string;
  allowCreate?: boolean;
  source?: string;
};

export type CompanyIdentityLookup = Omit<CompanyIdentityInput, 'allowCreate' | 'source' | 'companyName'> & {
  companyName?: string;
};

export type CompanyIdentityRecord = {
  id: number;
  name: string;
  rnc: string | null;
  cloudCompanyId: string | null;
  tenantKey: string | null;
  normalizedRnc: string | null;
  sourceBusinessId: string | null;
  primaryDeviceId: string | null;
  isActive: boolean;
};

function normalizeText(value?: string | null) {
  const trimmed = value?.trim();
  return trimmed && trimmed.length > 0 ? trimmed : '';
}

export function normalizeRnc(value?: string | null) {
  return normalizeText(value).toLowerCase().replace(/[^a-z0-9]/g, '');
}

function normalizeTenantKey(value?: string | null) {
  return normalizeText(value).toLowerCase();
}

function normalizeCloudId(value?: string | null) {
  return normalizeText(value);
}

function normalizeNullable(value?: string | null) {
  const trimmed = normalizeText(value);
  return trimmed.length > 0 ? trimmed : undefined;
}

function diagnostic(company: CompanyIdentityRecord | null) {
  if (!company) return null;
  return {
    id: company.id,
    rnc: company.rnc ?? null,
    cloudCompanyId: company.cloudCompanyId ?? null,
    tenantKey: company.tenantKey ?? null,
    normalizedRnc: company.normalizedRnc ?? null,
  };
}

const companySelect = {
  id: true,
  name: true,
  rnc: true,
  cloudCompanyId: true,
  tenantKey: true,
  normalizedRnc: true,
  sourceBusinessId: true,
  primaryDeviceId: true,
  isActive: true,
} satisfies Prisma.CompanySelect;

type SelectedCompany = Prisma.CompanyGetPayload<{ select: typeof companySelect }>;

function asRecord(company: SelectedCompany): CompanyIdentityRecord {
  return company;
}

function apiError(status: number, message: string, errorCode: string, details?: Record<string, unknown>) {
  return { status, message, errorCode, details };
}

async function updateCompanyIdentityIfNeeded(
  company: CompanyIdentityRecord,
  input: {
    companyRnc: string;
    normalizedRnc: string;
    companyCloudId: string;
    tenantKey: string;
    businessId: string;
    deviceId: string;
  },
) {
  const data: Prisma.CompanyUpdateInput = {};

  if (!company.rnc && input.companyRnc) data.rnc = input.companyRnc;
  if (!company.normalizedRnc && input.normalizedRnc) data.normalizedRnc = input.normalizedRnc;
  if (!company.cloudCompanyId && input.companyCloudId) data.cloudCompanyId = input.companyCloudId;
  if (!company.tenantKey && input.tenantKey) data.tenantKey = input.tenantKey;
  if (!company.sourceBusinessId && input.businessId) data.sourceBusinessId = input.businessId;
  if (!company.primaryDeviceId && input.deviceId) data.primaryDeviceId = input.deviceId;
  if (!company.isActive) data.isActive = true;

  if (Object.keys(data).length === 0) return company;

  try {
    const updated = await prisma.company.update({
      where: { id: company.id },
      data,
      select: companySelect,
    });
    return asRecord(updated);
  } catch (err: any) {
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
      throw apiError(
        409,
        'La identidad de empresa ya pertenece a otra empresa en la nube',
        'COMPANY_TENANT_IDENTITY_CONFLICT',
        { company: diagnostic(company), attempted: input },
      );
    }
    throw err;
  }
}

async function findByNormalizedRnc(normalizedRnc: string) {
  if (!normalizedRnc) return [];
  const indexed = await prisma.company.findMany({
    where: { normalizedRnc },
    select: companySelect,
    orderBy: { id: 'asc' },
  });
  if (indexed.length > 0) return indexed.map(asRecord);

  const candidates = await prisma.company.findMany({
    where: { rnc: { not: null } },
    select: companySelect,
    orderBy: { id: 'asc' },
  });
  return candidates
    .map(asRecord)
    .filter((company) => normalizeRnc(company.rnc) === normalizedRnc);
}

async function createCompany(input: {
  companyName: string;
  companyRnc: string;
  normalizedRnc: string;
  companyCloudId: string;
  tenantKey: string;
  businessId: string;
  deviceId: string;
}) {
  const nameSeed = input.companyRnc || input.companyCloudId || input.tenantKey || 'nueva';
  let resolvedName = input.companyName || `Empresa ${nameSeed}`;
  const nameClash = await prisma.company.findFirst({
    where: { name: resolvedName },
    select: { id: true },
  });
  if (nameClash) {
    resolvedName = `Empresa ${nameSeed}`;
  }

  try {
    const created = await prisma.company.create({
      data: {
        name: resolvedName,
        rnc: input.companyRnc || null,
        normalizedRnc: input.normalizedRnc || null,
        cloudCompanyId: input.companyCloudId || null,
        tenantKey: input.tenantKey || null,
        sourceBusinessId: input.businessId || null,
        primaryDeviceId: input.deviceId || null,
        isActive: true,
      },
      select: companySelect,
    });
    return asRecord(created);
  } catch (err: any) {
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
      throw apiError(
        409,
        'Ya existe una empresa con esa identidad en la nube',
        'COMPANY_TENANT_IDENTITY_CONFLICT',
        { attempted: input },
      );
    }
    throw err;
  }
}

export async function resolveCompanyIdentity(params: CompanyIdentityInput): Promise<CompanyIdentityRecord> {
  const source = params.source ?? 'company_identity';
  const tenantKey = normalizeTenantKey(params.companyTenantKey);
  const companyCloudId = normalizeCloudId(params.companyCloudId);
  const companyRnc = normalizeText(params.companyRnc);
  const normalizedRnc = normalizeRnc(companyRnc);
  const businessId = normalizeText(params.businessId);
  const deviceId = normalizeText(params.deviceId) || normalizeText(params.terminalId);
  const companyName = normalizeText(params.companyName);

  if (!tenantKey && !companyCloudId && !companyRnc && params.companyId == null) {
    throw apiError(400, 'Identidad de empresa requerida', 'COMPANY_IDENTITY_REQUIRED');
  }

  const byId = params.companyId != null
    ? await prisma.company.findUnique({ where: { id: params.companyId }, select: companySelect })
    : null;
  const companyById = byId ? asRecord(byId) : null;

  if (tenantKey) {
    const byTenant = await prisma.company.findUnique({
      where: { tenantKey },
      select: companySelect,
    });
    if (byTenant) {
      const resolved = await updateCompanyIdentityIfNeeded(asRecord(byTenant), {
        companyRnc,
        normalizedRnc,
        companyCloudId,
        tenantKey,
        businessId,
        deviceId,
      });
      if (companyById && companyById.id !== resolved.id) {
        console.warn(`[${source}] legacy_company_id_ignored`, {
          requestedCompanyId: params.companyId,
          companyById: diagnostic(companyById),
          resolvedByTenant: diagnostic(resolved),
        });
      }
      return resolved;
    }
  }

  const byCloud = companyCloudId
    ? await prisma.company.findFirst({ where: { cloudCompanyId: companyCloudId }, select: companySelect })
    : null;
  const companyByCloud = byCloud ? asRecord(byCloud) : null;
  if (companyByCloud) {
    if (tenantKey && companyByCloud.tenantKey && companyByCloud.tenantKey !== tenantKey) {
      throw apiError(
        409,
        'companyCloudId pertenece a otra identidad de empresa',
        'COMPANY_TENANT_LOCATOR_CONFLICT',
        {
          requestedTenantKey: tenantKey,
          requestedCompanyCloudId: companyCloudId,
          companyByCloud: diagnostic(companyByCloud),
        },
      );
    }
    const resolved = await updateCompanyIdentityIfNeeded(companyByCloud, {
      companyRnc,
      normalizedRnc,
      companyCloudId,
      tenantKey,
      businessId,
      deviceId,
    });
    if (companyById && companyById.id !== resolved.id) {
      console.warn(`[${source}] legacy_company_id_ignored`, {
        requestedCompanyId: params.companyId,
        companyById: diagnostic(companyById),
        resolvedByCloudId: diagnostic(resolved),
      });
    }
    return resolved;
  }

  if (normalizedRnc) {
    const rncMatches = await findByNormalizedRnc(normalizedRnc);
    if (rncMatches.length === 1) {
      const match = rncMatches[0];
      if (tenantKey && match.tenantKey && match.tenantKey !== tenantKey) {
        throw apiError(
          409,
          'El RNC pertenece a otra identidad de empresa',
          'COMPANY_TENANT_LOCATOR_CONFLICT',
          { requestedTenantKey: tenantKey, companyByRnc: diagnostic(match) },
        );
      }
      const resolved = await updateCompanyIdentityIfNeeded(match, {
        companyRnc,
        normalizedRnc,
        companyCloudId,
        tenantKey,
        businessId,
        deviceId,
      });
      if (companyById && companyById.id !== resolved.id) {
        console.warn(`[${source}] legacy_company_id_ignored`, {
          requestedCompanyId: params.companyId,
          companyById: diagnostic(companyById),
          resolvedByRnc: diagnostic(resolved),
        });
      }
      return resolved;
    }

    if (rncMatches.length > 1 && !tenantKey) {
      throw apiError(
        409,
        'RNC ambiguo: envíe companyTenantKey para evitar mezclar empresas',
        'COMPANY_RNC_AMBIGUOUS',
        { normalizedRnc, matches: rncMatches.map(diagnostic) },
      );
    }

    if (rncMatches.length > 1 && tenantKey) {
      throw apiError(
        404,
        'No existe empresa con esa identidad; RNC ya tiene empresas duplicadas y requiere vinculación manual',
        'COMPANY_TENANT_NOT_LINKED',
        { requestedTenantKey: tenantKey, normalizedRnc, matches: rncMatches.map(diagnostic) },
      );
    }
  }

  if (companyById && !tenantKey && !companyCloudId && !companyRnc) {
    return companyById;
  }

  if (params.allowCreate) {
    return createCompany({
      companyName,
      companyRnc,
      normalizedRnc,
      companyCloudId,
      tenantKey,
      businessId,
      deviceId,
    });
  }

  throw apiError(404, 'Empresa no encontrada para la identidad enviada', 'COMPANY_NOT_FOUND', {
    requestedCompanyId: params.companyId ?? null,
    requestedCompanyRnc: companyRnc || null,
    requestedCompanyCloudId: companyCloudId || null,
    requestedTenantKey: tenantKey || null,
  });
}

export async function resolveCompanyIdentityId(
  identity: CompanyIdentityLookup,
  source: string,
  allowCreate = false,
) {
  const company = await resolveCompanyIdentity({
    ...identity,
    source,
    allowCreate,
  });
  return company.id;
}

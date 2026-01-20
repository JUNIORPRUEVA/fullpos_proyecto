import { prisma } from '../../config/prisma';
import { Prisma } from '@prisma/client';

const DEFAULT_THEME_KEY = 'proPos';

type UpdateCompanyConfigInput = {
  companyName?: string;
  logoUrl?: string | null;
  phone?: string | null;
  phone2?: string | null;
  email?: string | null;
  address?: string | null;
  city?: string | null;
  slogan?: string | null;
  website?: string | null;
  instagramUrl?: string | null;
  facebookUrl?: string | null;
  themeKey?: string;
};

type CompanyWithConfig = Prisma.CompanyGetPayload<{ include: { config: true } }>;

function normalizeRnc(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function sanitizePayload(input: UpdateCompanyConfigInput): UpdateCompanyConfigInput {
  const result: UpdateCompanyConfigInput = {};
  const nonNullableFields = new Set(['companyName', 'themeKey']);

  for (const [key, value] of Object.entries(input)) {
    if (value === undefined) continue;
    if (typeof value === 'string' && value.trim() === '') {
      if (nonNullableFields.has(key)) continue;
      result[key as keyof UpdateCompanyConfigInput] = null;
      continue;
    }
    result[key as keyof UpdateCompanyConfigInput] = value;
  }

  return result;
}

async function ensureCompanyConfig(companyId: number) {
  return prisma.companyConfig.upsert({
    where: { companyId },
    update: { updatedAt: new Date() },
    create: {
      companyId,
      themeKey: DEFAULT_THEME_KEY,
    },
  });
}

function mapConfigResponse(company: CompanyWithConfig | null) {
  if (!company) return null;
  const config = company.config ?? {
    companyId: company.id,
    themeKey: DEFAULT_THEME_KEY,
    logoUrl: null,
    phone: null,
    phone2: null,
    email: null,
    address: null,
    city: null,
    slogan: null,
    website: null,
    instagramUrl: null,
    facebookUrl: null,
    primaryColor: null,
    accentColor: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  return {
    companyId: company.id,
    companyName: company.name,
    rnc: company.rnc,
    logoUrl: config.logoUrl,
    phone: config.phone,
    phone2: config.phone2,
    email: config.email,
    address: config.address,
    city: config.city,
    slogan: config.slogan,
    website: config.website,
    instagramUrl: config.instagramUrl,
    facebookUrl: config.facebookUrl,
    themeKey: config.themeKey ?? DEFAULT_THEME_KEY,
    primaryColor: config.primaryColor,
    accentColor: config.accentColor,
    version: company.ownerAppVersion,
  };
}

export async function getCompanyConfig(companyId: number) {
  await ensureCompanyConfig(companyId);
  const company = await prisma.company.findUnique({
    where: { id: companyId },
    include: { config: true },
  });

  if (!company) {
    throw { status: 404, message: 'Compa\u00f1\u00eda no encontrada' };
  }

  return mapConfigResponse(company);
}

export async function updateCompanyConfig(companyId: number, payload: UpdateCompanyConfigInput) {
  const sanitized = sanitizePayload(payload);
  const companyName = sanitized.companyName?.trim();
  const { companyName: _ignored, ...configPayload } = sanitized;

  if (companyName) {
    await prisma.company.update({
      where: { id: companyId },
      data: { name: companyName },
    });
  }

  await prisma.companyConfig.upsert({
    where: { companyId },
    update: configPayload,
    create: {
      companyId,
      ...configPayload,
      themeKey: configPayload.themeKey ?? DEFAULT_THEME_KEY,
    },
  });

  return getCompanyConfig(companyId);
}

export async function updateCompanyConfigByRnc(
  companyRnc: string,
  payload: UpdateCompanyConfigInput,
) {
  const trimmed = companyRnc.trim();
  const normalized = normalizeRnc(trimmed);
  let company = await prisma.company.findFirst({
    where: { rnc: trimmed },
    select: { id: true, rnc: true },
  });

  if (!company && normalized.length > 0) {
    const candidates = await prisma.company.findMany({
      where: { rnc: { not: null } },
      select: { id: true, rnc: true },
    });
    company =
      candidates.find(
        (item) => item.rnc != null && normalizeRnc(item.rnc) === normalized,
      ) ?? null;
  }

  if (!company) {
    throw { status: 404, message: 'Compañía no encontrada' };
  }

  return updateCompanyConfig(company.id, payload);
}

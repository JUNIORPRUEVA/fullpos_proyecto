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

function normalizeNullable(value?: string | null) {
  if (value === undefined) return undefined;
  if (value === null) return null;
  const trimmed = value.trim();
  return trimmed.length === 0 ? null : trimmed;
}

function normalizeRequired(value?: string) {
  if (value === undefined) return undefined;
  const trimmed = value.trim();
  return trimmed.length === 0 ? undefined : trimmed;
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
  const companyName = normalizeRequired(payload.companyName);
  const normalized = {
    logoUrl:
      payload.logoUrl !== undefined ? normalizeNullable(payload.logoUrl) : undefined,
    phone: payload.phone !== undefined ? normalizeNullable(payload.phone) : undefined,
    phone2:
      payload.phone2 !== undefined ? normalizeNullable(payload.phone2) : undefined,
    email: payload.email !== undefined ? normalizeNullable(payload.email) : undefined,
    address:
      payload.address !== undefined ? normalizeNullable(payload.address) : undefined,
    city: payload.city !== undefined ? normalizeNullable(payload.city) : undefined,
    slogan: payload.slogan !== undefined ? normalizeNullable(payload.slogan) : undefined,
    website: payload.website !== undefined ? normalizeNullable(payload.website) : undefined,
    instagramUrl:
      payload.instagramUrl !== undefined ? normalizeNullable(payload.instagramUrl) : undefined,
    facebookUrl:
      payload.facebookUrl !== undefined ? normalizeNullable(payload.facebookUrl) : undefined,
  };

  const themeKey = normalizeRequired(payload.themeKey);
  const configUpdate: Prisma.CompanyConfigUpdateInput = {};

  if (normalized.logoUrl !== undefined) configUpdate.logoUrl = normalized.logoUrl;
  if (normalized.phone !== undefined) configUpdate.phone = normalized.phone;
  if (normalized.phone2 !== undefined) configUpdate.phone2 = normalized.phone2;
  if (normalized.email !== undefined) configUpdate.email = normalized.email;
  if (normalized.address !== undefined) configUpdate.address = normalized.address;
  if (normalized.city !== undefined) configUpdate.city = normalized.city;
  if (normalized.slogan !== undefined) configUpdate.slogan = normalized.slogan;
  if (normalized.website !== undefined) configUpdate.website = normalized.website;
  if (normalized.instagramUrl !== undefined)
    configUpdate.instagramUrl = normalized.instagramUrl;
  if (normalized.facebookUrl !== undefined)
    configUpdate.facebookUrl = normalized.facebookUrl;
  if (themeKey !== undefined) configUpdate.themeKey = themeKey;

  if (companyName) {
    await prisma.company.update({
      where: { id: companyId },
      data: { name: companyName },
    });
  }

  const configCreate: Prisma.CompanyConfigCreateInput = {
    company: { connect: { id: companyId } },
    themeKey: themeKey ?? DEFAULT_THEME_KEY,
  };

  if (normalized.logoUrl !== undefined) configCreate.logoUrl = normalized.logoUrl;
  if (normalized.phone !== undefined) configCreate.phone = normalized.phone;
  if (normalized.phone2 !== undefined) configCreate.phone2 = normalized.phone2;
  if (normalized.email !== undefined) configCreate.email = normalized.email;
  if (normalized.address !== undefined) configCreate.address = normalized.address;
  if (normalized.city !== undefined) configCreate.city = normalized.city;
  if (normalized.slogan !== undefined) configCreate.slogan = normalized.slogan;
  if (normalized.website !== undefined) configCreate.website = normalized.website;
  if (normalized.instagramUrl !== undefined)
    configCreate.instagramUrl = normalized.instagramUrl;
  if (normalized.facebookUrl !== undefined)
    configCreate.facebookUrl = normalized.facebookUrl;

  await prisma.companyConfig.upsert({
    where: { companyId },
    update: configUpdate,
    create: configCreate,
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

import { prisma } from '../../config/prisma';

function normalizeRnc(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

async function resolveCompanyId(companyRnc?: string, companyCloudId?: string) {
  const rnc = companyRnc?.trim() ?? '';
  const cloudId = companyCloudId?.trim() ?? '';
  if (!rnc && !cloudId) throw { status: 400, message: 'RNC o ID interno requerido' };

  let company = null as { id: number; rnc: string | null } | null;
  if (cloudId) {
    company = await prisma.company.findFirst({ where: { cloudCompanyId: cloudId }, select: { id: true, rnc: true } });
  }
  if (!company && rnc) {
    company = await prisma.company.findFirst({ where: { rnc }, select: { id: true, rnc: true } });
    if (!company) {
      const normalized = normalizeRnc(rnc);
      const candidates = await prisma.company.findMany({ where: { rnc: { not: null } }, select: { id: true, rnc: true } });
      company = candidates.find((item) => item.rnc != null && normalizeRnc(item.rnc) === normalized) ?? null;
    }
  }
  if (!company) throw { status: 404, message: 'Empresa no encontrada' };
  return company.id;
}

export type SyncCategoryInput = {
  localId: number;
  name: string;
  isActive?: boolean;
  createdAt?: string;
  updatedAt: string;
  deletedAt?: string | null;
};

export async function syncCategoriesByRnc(
  companyRnc: string | undefined,
  companyCloudId: string | undefined,
  categories: SyncCategoryInput[],
) {
  const companyId = await resolveCompanyId(companyRnc, companyCloudId);
  if (!categories || categories.length === 0) {
    return { ok: true, upserted: 0, companyId };
  }

  await prisma.$transaction(async (tx) => {
    const trx = tx as any;
    for (const c of categories) {
      await trx.category.upsert({
        where: { companyId_localId: { companyId, localId: c.localId } },
        update: {
          name: c.name,
          isActive: c.isActive ?? true,
          deletedAt: c.deletedAt ? new Date(c.deletedAt) : null,
          updatedAt: new Date(c.updatedAt),
        },
        create: {
          companyId,
          localId: c.localId,
          name: c.name,
          isActive: c.isActive ?? true,
          deletedAt: c.deletedAt ? new Date(c.deletedAt) : null,
          createdAt: c.createdAt ? new Date(c.createdAt) : new Date(c.updatedAt),
          updatedAt: new Date(c.updatedAt),
        },
      });
    }
  });

  return { ok: true, upserted: categories.length, companyId };
}

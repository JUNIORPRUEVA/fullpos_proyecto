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

export type SyncSupplierInput = {
  localId: number;
  name: string;
  phone?: string | null;
  note?: string | null;
  isActive?: boolean;
  createdAt?: string;
  updatedAt: string;
  deletedAt?: string | null;
};

export async function syncSuppliersByRnc(
  companyRnc: string | undefined,
  companyCloudId: string | undefined,
  suppliers: SyncSupplierInput[],
) {
  const companyId = await resolveCompanyId(companyRnc, companyCloudId);
  if (!suppliers || suppliers.length === 0) {
    return { ok: true, upserted: 0, companyId };
  }

  await prisma.$transaction(async (tx) => {
    const trx = tx as any;
    for (const s of suppliers) {
      await trx.supplier.upsert({
        where: { companyId_localId: { companyId, localId: s.localId } },
        update: {
          name: s.name,
          phone: s.phone ?? null,
          note: s.note ?? null,
          isActive: s.isActive ?? true,
          deletedAt: s.deletedAt ? new Date(s.deletedAt) : null,
          updatedAt: new Date(s.updatedAt),
        },
        create: {
          companyId,
          localId: s.localId,
          name: s.name,
          phone: s.phone ?? null,
          note: s.note ?? null,
          isActive: s.isActive ?? true,
          deletedAt: s.deletedAt ? new Date(s.deletedAt) : null,
          createdAt: s.createdAt ? new Date(s.createdAt) : new Date(s.updatedAt),
          updatedAt: new Date(s.updatedAt),
        },
      });
    }
  });

  return { ok: true, upserted: suppliers.length, companyId };
}

import { prisma } from '../../config/prisma';
import { CompanyIdentityLookup, resolveCompanyIdentityId } from '../companies/companyIdentity.service';

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
  identity: CompanyIdentityLookup,
  suppliers: SyncSupplierInput[],
) {
  const companyId = await resolveCompanyIdentityId(identity, 'suppliers.sync');
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

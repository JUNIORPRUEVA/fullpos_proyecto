import { prisma } from '../../config/prisma';
import { CompanyIdentityLookup, resolveCompanyIdentityId } from '../companies/companyIdentity.service';

export type SyncClientInput = {
  localId: number;
  nombre: string;
  telefono?: string | null;
  direccion?: string | null;
  rnc?: string | null;
  cedula?: string | null;
  isActive?: boolean;
  hasCredit?: boolean;
  createdAt?: string;
  updatedAt: string;
  deletedAt?: string | null;
};

export async function syncClientsByRnc(
  identity: CompanyIdentityLookup,
  clients: SyncClientInput[],
) {
  const companyId = await resolveCompanyIdentityId(identity, 'clients.sync');
  if (!clients || clients.length === 0) {
    return { ok: true, upserted: 0, companyId };
  }

  await prisma.$transaction(async (tx) => {
    const trx = tx as any;
    for (const c of clients) {
      await trx.client.upsert({
        where: { companyId_localId: { companyId, localId: c.localId } },
        update: {
          nombre: c.nombre,
          telefono: c.telefono ?? null,
          direccion: c.direccion ?? null,
          rnc: c.rnc ?? null,
          cedula: c.cedula ?? null,
          isActive: c.isActive ?? true,
          hasCredit: c.hasCredit ?? false,
          deletedAt: c.deletedAt ? new Date(c.deletedAt) : null,
          updatedAt: new Date(c.updatedAt),
        },
        create: {
          companyId,
          localId: c.localId,
          nombre: c.nombre,
          telefono: c.telefono ?? null,
          direccion: c.direccion ?? null,
          rnc: c.rnc ?? null,
          cedula: c.cedula ?? null,
          isActive: c.isActive ?? true,
          hasCredit: c.hasCredit ?? false,
          deletedAt: c.deletedAt ? new Date(c.deletedAt) : null,
          createdAt: c.createdAt ? new Date(c.createdAt) : new Date(c.updatedAt),
          updatedAt: new Date(c.updatedAt),
        },
      });
    }
  });

  return { ok: true, upserted: clients.length, companyId };
}

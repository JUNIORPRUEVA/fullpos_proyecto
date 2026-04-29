import { prisma } from '../../config/prisma';

function normalizeRnc(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

type CompanyScopeCandidate = {
  id: number;
  name: string;
  rnc: string | null;
  cloudCompanyId: string | null;
  products: number;
};

export async function resolveProductDataCompanyId(
  requestedCompanyId: number,
  context: string,
): Promise<number> {
  const requested = await prisma.company.findUnique({
    where: { id: requestedCompanyId },
    select: { id: true, name: true, rnc: true, cloudCompanyId: true },
  });

  if (!requested) return requestedCompanyId;

  const normalizedRnc = normalizeRnc(requested.rnc ?? '');
  const companies = normalizedRnc.length > 0
    ? await prisma.company.findMany({
        where: { rnc: { not: null } },
        select: { id: true, name: true, rnc: true, cloudCompanyId: true },
        orderBy: { id: 'asc' },
      })
    : [requested];

  const related = companies.filter(
    (company) => company.id === requested.id || (company.rnc != null && normalizeRnc(company.rnc) === normalizedRnc),
  );

  if (!related.some((company) => company.id === requested.id)) {
    related.unshift(requested);
  }

  const candidates: CompanyScopeCandidate[] = await Promise.all(
    related.map(async (company) => ({
      ...company,
      products: await prisma.product.count({
        where: {
          companyId: company.id,
          isDemo: false,
          deletedAt: null,
        },
      }),
    })),
  );

  const selected = candidates.reduce((best, current) => {
    if (current.products > best.products) return current;
    if (current.products === best.products && current.id === requestedCompanyId) return current;
    return best;
  }, candidates[0] ?? { ...requested, products: 0 });

  if (selected.id !== requestedCompanyId) {
    console.warn('[companyScope.resolveProductDataCompanyId] using_related_product_company', {
      context,
      requestedCompanyId,
      selectedCompanyId: selected.id,
      requestedCompany: requested,
      candidates,
      reason: 'selected company has the product/inventory catalog for this RNC',
    });
  }

  return selected.id;
}

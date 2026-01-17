import { Prisma } from '@prisma/client';
import { prisma } from '../../config/prisma';
import { buildPagination } from '../../utils/pagination';
import { createProductSchema } from './products.validation';
import { buildDemoProducts } from './demo-products';

function toNumber(value: Prisma.Decimal | number | null) {
  if (value === null || value === undefined) return 0;
  if (typeof value === 'number') return value;
  return value.toNumber();
}

export type CreateProductInput = Omit<
  ReturnType<typeof createProductSchema.parse>,
  'isDemo'
> & { isDemo?: boolean };

export async function listProducts(
  companyId: number,
  page = 1,
  pageSize = 20,
  search?: string,
) {
  const existingCount = await prisma.product.count({ where: { companyId } });
  if (existingCount === 0) {
    await prisma.product.createMany({
      data: buildDemoProducts(companyId),
      skipDuplicates: true,
    });
  }

  const { skip, take, page: safePage } = buildPagination(page, pageSize);
  const where = {
    companyId,
    ...(search
      ? {
          OR: [
            { name: { contains: search, mode: 'insensitive' as const } },
            { code: { contains: search, mode: 'insensitive' as const } },
          ],
        }
      : {}),
  };

  const [total, items] = await Promise.all([
    prisma.product.count({ where }),
    prisma.product.findMany({
      where,
      orderBy: [{ isDemo: 'desc' }, { createdAt: 'desc' }],
      skip,
      take,
    }),
  ]);

  return {
    data: items.map((p) => ({
      id: p.id,
      code: p.code,
      name: p.name,
      description: p.description,
      price: toNumber(p.price),
      stock: toNumber(p.stock),
      imageUrl: p.imageUrl,
      isDemo: p.isDemo,
      createdAt: p.createdAt,
    })),
    total,
    page: safePage,
    pageSize: take,
  };
}

export async function createProduct(companyId: number, input: CreateProductInput) {
  const data = {
    companyId,
    code: input.code,
    name: input.name,
    description: input.description,
    price: input.price,
    stock: input.stock ?? 0,
    imageUrl: input.imageUrl,
    isDemo: input.isDemo ?? false,
  };

  try {
    const created = await prisma.$transaction(async (tx) => {
      if (!data.isDemo) {
        const demoCount = await tx.product.count({ where: { companyId, isDemo: true } });
        if (demoCount > 0) {
          await tx.product.deleteMany({ where: { companyId, isDemo: true } });
        }
      }

      return tx.product.create({ data });
    });

    return {
      id: created.id,
      code: created.code,
      name: created.name,
      description: created.description,
      price: toNumber(created.price),
      stock: toNumber(created.stock),
      imageUrl: created.imageUrl,
      isDemo: created.isDemo,
      createdAt: created.createdAt,
    };
  } catch (err: any) {
    if (err.code === 'P2002') {
      throw { status: 409, message: 'Ya existe un producto con ese codigo' };
    }
    throw err;
  }
}

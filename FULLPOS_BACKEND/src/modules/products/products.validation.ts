import { z } from 'zod';

export const listProductsSchema = z.object({
  page: z.coerce.number().int().positive().optional(),
  pageSize: z.coerce.number().int().positive().max(100).optional(),
  search: z.string().trim().max(100).optional(),
});

export const createProductSchema = z.object({
  code: z.string().trim().min(1, 'El codigo es requerido'),
  name: z.string().trim().min(1, 'El nombre es requerido'),
  description: z.string().trim().max(500).optional(),
  price: z.coerce.number().nonnegative(),
  stock: z.coerce.number().nonnegative().default(0),
  imageUrl: z.string().url().optional(),
  isDemo: z.boolean().optional(),
});

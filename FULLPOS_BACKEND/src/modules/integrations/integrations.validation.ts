import { z } from 'zod';

export const listIntegrationProductsQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(500).optional(),
  updated_since: z.string().datetime().optional(),
  cursor: z.string().min(1).optional(),
});

export type ListIntegrationProductsQuery = z.infer<typeof listIntegrationProductsQuerySchema>;

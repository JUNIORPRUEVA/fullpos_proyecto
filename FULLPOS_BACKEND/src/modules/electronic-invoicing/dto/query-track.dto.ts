import { z } from 'zod';

export const queryTrackDtoSchema = z.object({
  trackId: z.string().trim().min(3),
});

export type QueryTrackDto = z.infer<typeof queryTrackDtoSchema>;
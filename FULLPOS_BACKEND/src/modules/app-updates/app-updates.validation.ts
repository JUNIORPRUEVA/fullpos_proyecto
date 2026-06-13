import { z } from 'zod';

const semanticVersion = z.string().trim().regex(
  /^v?\d+\.\d+\.\d+(?:\+\d+)?$/,
  'Version must use semantic X.Y.Z or X.Y.Z+BUILD format',
);

const installerUrl = z.string().url().superRefine((value, ctx) => {
  const url = new URL(value);
  if (url.protocol !== 'https:') {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Installer URL must use HTTPS' });
  }
  if (url.username || url.password) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Installer URL cannot contain credentials' });
  }
});

export const appUpdatePolicySchema = z.object({
  projectCode: z.literal('fullpos'),
  platform: z.literal('windows'),
  version: semanticVersion,
  buildNumber: z.coerce.number().int().positive(),
  minimumSupportedVersion: semanticVersion,
  minimumSupportedBuild: z.coerce.number().int().positive(),
  mandatory: z.boolean(),
  enabled: z.boolean(),
  installerUrl,
  installerFilename: z.literal('FullPOS-Setup.exe'),
  installerSizeBytes: z.coerce.bigint().positive().nullable().optional(),
  sha256: z.string().trim().regex(/^[0-9a-fA-F]{64}$/).transform((value) => value.toLowerCase()),
  releaseTitle: z.string().trim().min(1).max(160),
  releaseNotes: z.array(z.string().trim().min(1).max(500)).max(30),
  publishedAt: z.coerce.date(),
});

export const upsertAppUpdatePolicySchema = appUpdatePolicySchema;

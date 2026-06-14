import { z } from 'zod';

const semanticVersion = z.string().trim().regex(
  /^v?\d+\.\d+\.\d+(?:\+\d+)?$/,
  'Version must use semantic X.Y.Z or X.Y.Z+BUILD format',
);

const installerUrl = z.string().url().superRefine((value, ctx) => {
  const url = new URL(value);
  const allowedHosts = new Set([
    'github.com',
    'objects.githubusercontent.com',
    'github-releases.githubusercontent.com',
    'release-assets.githubusercontent.com',
  ]);
  if (url.protocol !== 'https:') {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Installer URL must use HTTPS' });
  }
  if (url.username || url.password) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Installer URL cannot contain credentials' });
  }
  if (!allowedHosts.has(url.hostname.toLowerCase())) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Installer URL host is not allowed' });
  }
});

const basePolicy = z.object({
  version: semanticVersion,
  buildNumber: z.coerce.number().int().positive(),
  minimumSupportedVersion: semanticVersion,
  minimumSupportedBuild: z.coerce.number().int().positive(),
  mandatory: z.boolean(),
  enabled: z.boolean(),
  installerUrl,
  installerSizeBytes: z.coerce.bigint().positive().nullable().optional(),
  sha256: z.string().trim().regex(/^[0-9a-fA-F]{64}$/).transform((value) => value.toLowerCase()),
  releaseTitle: z.string().trim().min(1).max(160),
  releaseNotes: z.array(z.string().trim().min(1).max(500)).max(30),
  publishedAt: z.coerce.date(),
});

export const appUpdatePolicySchema = z.discriminatedUnion('projectCode', [
  basePolicy.extend({
    projectCode: z.literal('fullpos'),
    platform: z.literal('windows'),
    installerFilename: z.literal('FullPOS-Setup.exe'),
  }),
  basePolicy.extend({
    projectCode: z.literal('fullcredit'),
    platform: z.literal('android'),
    installerFilename: z.literal('FullCredit-Android.apk'),
  }),
]);

export const upsertAppUpdatePolicySchema = appUpdatePolicySchema;

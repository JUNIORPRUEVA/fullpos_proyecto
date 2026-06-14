import { AppUpdateRelease } from '@prisma/client';
import { prisma } from '../../config/prisma';
import { appUpdatePolicySchema } from './app-updates.validation';

type PolicyInput = {
  projectCode: 'fullpos' | 'fullcredit';
  platform: 'windows' | 'android';
  version: string;
  buildNumber: number;
  minimumSupportedVersion: string;
  minimumSupportedBuild: number;
  mandatory: boolean;
  enabled: boolean;
  installerUrl: string;
  installerFilename: 'FullPOS-Setup.exe' | 'FullCredit-Android.apk';
  installerSizeBytes?: bigint | null;
  sha256: string;
  releaseTitle: string;
  releaseNotes: string[];
  publishedAt: Date;
};

function toPublicPolicy(row: AppUpdateRelease) {
  const validated = appUpdatePolicySchema.parse({
    ...row,
    projectCode: row.projectCode,
    platform: row.platform,
    installerSizeBytes: row.installerSizeBytes,
  });

  return {
    projectCode: validated.projectCode,
    platform: validated.platform,
    latestVersion: validated.version.replace(/^v/i, '').split('+')[0],
    latestBuild: validated.buildNumber,
    minimumSupportedVersion: validated.minimumSupportedVersion.replace(/^v/i, '').split('+')[0],
    minimumSupportedBuild: validated.minimumSupportedBuild,
    mandatory: validated.mandatory,
    enabled: validated.enabled,
    installerUrl: validated.installerUrl,
    installerFilename: validated.installerFilename,
    installerSizeBytes: validated.installerSizeBytes == null
      ? null
      : Number(validated.installerSizeBytes),
    sha256: validated.sha256,
    releaseTitle: validated.releaseTitle,
    releaseNotes: validated.releaseNotes,
    publishedAt: validated.publishedAt.toISOString(),
  };
}

export async function getAppUpdatePolicy(
  projectCode: 'fullpos' | 'fullcredit',
  platform: 'windows' | 'android',
) {
  const row = await prisma.appUpdateRelease.findFirst({
    where: {
      projectCode,
      platform,
      enabled: true,
    },
    orderBy: [
      { publishedAt: 'desc' },
      { buildNumber: 'desc' },
    ],
  });

  if (!row) {
    const error: any = new Error('No enabled update policy is configured');
    error.status = 404;
    error.errorCode = 'UPDATE_POLICY_NOT_CONFIGURED';
    throw error;
  }

  return toPublicPolicy(row);
}

export async function upsertAppUpdatePolicy(input: PolicyInput) {
  const validated = appUpdatePolicySchema.parse(input);
  const version = validated.version.replace(/^v/i, '').split('+')[0];
  const minimumVersion = validated.minimumSupportedVersion.replace(/^v/i, '').split('+')[0];

  const row = await prisma.appUpdateRelease.upsert({
    where: {
      projectCode_platform_version_buildNumber: {
        projectCode: validated.projectCode,
        platform: validated.platform,
        version,
        buildNumber: validated.buildNumber,
      },
    },
    create: {
      ...validated,
      version,
      minimumSupportedVersion: minimumVersion,
    },
    update: {
      minimumSupportedVersion: minimumVersion,
      minimumSupportedBuild: validated.minimumSupportedBuild,
      mandatory: validated.mandatory,
      enabled: validated.enabled,
      installerUrl: validated.installerUrl,
      installerFilename: validated.installerFilename,
      installerSizeBytes: validated.installerSizeBytes,
      sha256: validated.sha256,
      releaseTitle: validated.releaseTitle,
      releaseNotes: validated.releaseNotes,
      publishedAt: validated.publishedAt,
    },
  });

  return toPublicPolicy(row);
}

export const getFullPosWindowsUpdatePolicy = () =>
  getAppUpdatePolicy('fullpos', 'windows');
export const getFullCreditAndroidUpdatePolicy = () =>
  getAppUpdatePolicy('fullcredit', 'android');
export const upsertFullPosWindowsUpdatePolicy = upsertAppUpdatePolicy;
export const upsertFullCreditAndroidUpdatePolicy = upsertAppUpdatePolicy;

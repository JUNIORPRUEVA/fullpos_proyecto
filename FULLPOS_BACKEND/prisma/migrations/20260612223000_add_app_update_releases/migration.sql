CREATE TABLE "app_update_releases" (
    "id" SERIAL NOT NULL,
    "projectCode" TEXT NOT NULL,
    "platform" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "buildNumber" INTEGER NOT NULL,
    "minimumSupportedVersion" TEXT NOT NULL,
    "minimumSupportedBuild" INTEGER NOT NULL,
    "mandatory" BOOLEAN NOT NULL DEFAULT false,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "installerUrl" TEXT NOT NULL,
    "installerFilename" TEXT NOT NULL,
    "installerSizeBytes" BIGINT,
    "sha256" TEXT NOT NULL,
    "releaseTitle" TEXT NOT NULL,
    "releaseNotes" TEXT[] NOT NULL,
    "publishedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "app_update_releases_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "app_update_releases_buildNumber_check" CHECK ("buildNumber" > 0),
    CONSTRAINT "app_update_releases_minimumSupportedBuild_check" CHECK ("minimumSupportedBuild" > 0),
    CONSTRAINT "app_update_releases_installerSizeBytes_check" CHECK ("installerSizeBytes" IS NULL OR "installerSizeBytes" > 0),
    CONSTRAINT "app_update_releases_sha256_check" CHECK ("sha256" ~ '^[0-9A-Fa-f]{64}$'),
    CONSTRAINT "app_update_releases_installerFilename_check" CHECK (
      ("projectCode" = 'fullpos' AND "platform" = 'windows' AND "installerFilename" = 'FullPOS-Setup.exe')
      OR
      ("projectCode" = 'fullcredit' AND "platform" = 'android' AND "installerFilename" = 'FullCredit-Android.apk')
    )
);

CREATE UNIQUE INDEX "app_update_releases_projectCode_platform_version_buildNumber_key"
ON "app_update_releases"("projectCode", "platform", "version", "buildNumber");

CREATE INDEX "app_update_releases_projectCode_platform_enabled_publishedAt_idx"
ON "app_update_releases"("projectCode", "platform", "enabled", "publishedAt");

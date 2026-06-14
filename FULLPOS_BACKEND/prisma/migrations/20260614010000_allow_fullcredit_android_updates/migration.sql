ALTER TABLE "app_update_releases"
DROP CONSTRAINT IF EXISTS "app_update_releases_installerFilename_check";

ALTER TABLE "app_update_releases"
ADD CONSTRAINT "app_update_releases_installerFilename_check" CHECK (
  ("projectCode" = 'fullpos' AND "platform" = 'windows' AND "installerFilename" = 'FullPOS-Setup.exe')
  OR
  ("projectCode" = 'fullcredit' AND "platform" = 'android' AND "installerFilename" = 'FullCredit-Android.apk')
);

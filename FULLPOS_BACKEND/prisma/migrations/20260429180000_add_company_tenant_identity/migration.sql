-- Canonical cloud tenant identity used to prevent data from different POS/company
-- installations being mixed when RNC or legacy cloudCompanyId are duplicated or stale.
ALTER TABLE "Company" ADD COLUMN "tenantKey" TEXT;
ALTER TABLE "Company" ADD COLUMN "normalizedRnc" TEXT;
ALTER TABLE "Company" ADD COLUMN "sourceBusinessId" TEXT;
ALTER TABLE "Company" ADD COLUMN "primaryDeviceId" TEXT;

CREATE UNIQUE INDEX "Company_tenantKey_key" ON "Company"("tenantKey");
CREATE INDEX "Company_normalizedRnc_idx" ON "Company"("normalizedRnc");
ALTER TABLE "Product"
ADD COLUMN "localId" INTEGER,
ADD COLUMN "isActive" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN "version" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN "lastModifiedBy" TEXT,
ADD COLUMN "lastClientMutationId" TEXT,
ADD COLUMN "deletedAt" TIMESTAMP(3);

UPDATE "Product"
SET
  "isActive" = true,
  "version" = 1,
  "deletedAt" = NULL
WHERE "version" = 0;

CREATE UNIQUE INDEX "Product_companyId_localId_key"
ON "Product"("companyId", "localId");

CREATE INDEX "Product_companyId_deletedAt_updatedAt_idx"
ON "Product"("companyId", "deletedAt", "updatedAt");
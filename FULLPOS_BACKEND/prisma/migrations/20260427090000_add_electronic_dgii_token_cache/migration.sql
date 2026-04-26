CREATE TABLE IF NOT EXISTS "ElectronicDgiiTokenCache" (
    "id" SERIAL NOT NULL,
    "companyId" INTEGER NOT NULL,
    "environment" TEXT NOT NULL,
    "tokenEncrypted" TEXT NOT NULL,
    "issuedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "lastValidatedAt" TIMESTAMP(3),
    "lastErrorCode" TEXT,
    "lastErrorMessage" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ElectronicDgiiTokenCache_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "ElectronicDgiiTokenCache_companyId_environment_key"
ON "ElectronicDgiiTokenCache"("companyId", "environment");

CREATE INDEX IF NOT EXISTS "ElectronicDgiiTokenCache_companyId_expiresAt_idx"
ON "ElectronicDgiiTokenCache"("companyId", "expiresAt");

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.table_constraints
    WHERE constraint_name = 'ElectronicDgiiTokenCache_companyId_fkey'
      AND table_name = 'ElectronicDgiiTokenCache'
  ) THEN
    ALTER TABLE "ElectronicDgiiTokenCache"
      ADD CONSTRAINT "ElectronicDgiiTokenCache_companyId_fkey"
      FOREIGN KEY ("companyId") REFERENCES "Company"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
  END IF;
END $$;
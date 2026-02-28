-- Add IntegrationToken table for server-side integrations (hashed tokens bound to one company)

CREATE TABLE "IntegrationToken" (
  "id" SERIAL NOT NULL,
  "companyId" INTEGER NOT NULL,
  "name" TEXT,
  "tokenHash" TEXT NOT NULL,
  "scopes" TEXT[] NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "expiresAt" TIMESTAMP(3),
  "revokedAt" TIMESTAMP(3),
  "lastUsedAt" TIMESTAMP(3),

  CONSTRAINT "IntegrationToken_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "IntegrationToken_tokenHash_key" ON "IntegrationToken"("tokenHash");
CREATE INDEX "IntegrationToken_companyId_revokedAt_idx" ON "IntegrationToken"("companyId", "revokedAt");

ALTER TABLE "IntegrationToken" ADD CONSTRAINT "IntegrationToken_companyId_fkey"
  FOREIGN KEY ("companyId") REFERENCES "Company"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

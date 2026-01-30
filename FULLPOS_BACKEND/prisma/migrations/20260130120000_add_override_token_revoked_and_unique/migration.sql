-- Add revocation support + deterministic idempotency for override tokens

ALTER TABLE "OverrideToken" ADD COLUMN "revokedAt" TIMESTAMP(3);

-- Make token windows (virtual) and remote tokens idempotent per company+method
-- This enables safe concurrency and reliable "Token ya fue usado" behavior.
-- If older buggy code already created duplicates, dedupe first so the unique index can be created.
DELETE FROM "OverrideToken" t
USING "OverrideToken" d
WHERE t.id > d.id
	AND t."companyId" = d."companyId"
	AND t."tokenHash" = d."tokenHash"
	AND t."method" = d."method";

CREATE UNIQUE INDEX "OverrideToken_companyId_tokenHash_method_key"
ON "OverrideToken"("companyId", "tokenHash", "method");

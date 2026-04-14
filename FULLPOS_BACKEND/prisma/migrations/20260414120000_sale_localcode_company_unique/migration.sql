DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM "Sale"
    GROUP BY "companyId", "localCode"
    HAVING COUNT(*) > 1
  ) THEN
    RAISE EXCEPTION 'Cannot enforce Sale(companyId, localCode) uniqueness because duplicate localCode values already exist inside the same company';
  END IF;
END $$;

DROP INDEX IF EXISTS "Sale_localCode_key";

CREATE UNIQUE INDEX "Sale_companyId_localCode_key"
ON "Sale"("companyId", "localCode");
-- Fix production mismatch where ElectronicSequence may have endNumber but not maxNumber.
-- Keep maxNumber as the canonical Prisma field and backfill it safely.

ALTER TABLE "ElectronicSequence"
  ADD COLUMN IF NOT EXISTS "maxNumber" INTEGER;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'ElectronicSequence'
      AND column_name = 'endNumber'
  ) THEN
    EXECUTE '
      UPDATE "ElectronicSequence"
      SET "maxNumber" = COALESCE("maxNumber", "endNumber", "currentNumber")
      WHERE "maxNumber" IS NULL
    ';
  ELSE
    UPDATE "ElectronicSequence"
    SET "maxNumber" = COALESCE("maxNumber", "currentNumber")
    WHERE "maxNumber" IS NULL;
  END IF;
END $$;

ALTER TABLE "ElectronicSequence"
  ALTER COLUMN "maxNumber" SET NOT NULL;

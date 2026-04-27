-- Production compatibility: older databases may still have a legacy "endNumber"
-- column on "ElectronicSequence". Prisma now writes the canonical "maxNumber"
-- field, so a NOT NULL legacy "endNumber" column can reject inserts with:
--   Null constraint violation on the fields: (endNumber)
-- Keep existing data aligned, then make the legacy column nullable.

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
      SET "endNumber" = COALESCE("endNumber", "maxNumber", "currentNumber")
      WHERE "endNumber" IS NULL
    ';

    EXECUTE '
      ALTER TABLE "ElectronicSequence"
      ALTER COLUMN "endNumber" DROP NOT NULL
    ';
  END IF;
END $$;

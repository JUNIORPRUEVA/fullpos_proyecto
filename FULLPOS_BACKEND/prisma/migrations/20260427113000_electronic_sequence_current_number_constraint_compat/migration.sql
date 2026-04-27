-- Keep outbound allocation compatible with deployments that temporarily have both
-- canonical "maxNumber" and legacy "endNumber" columns.
--
-- Some production rows had "endNumber" updated to the authorized DGII limit
-- while "maxNumber" remained stale. The old check constraint validates
-- "currentNumber" against "maxNumber", so allocating E32 from 30 -> 31 failed
-- even though "endNumber" was 60.

DO $$
DECLARE
  has_max_number boolean;
  has_end_number boolean;
BEGIN
  SELECT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'ElectronicSequence'
      AND column_name = 'maxNumber'
  ) INTO has_max_number;

  SELECT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'ElectronicSequence'
      AND column_name = 'endNumber'
  ) INTO has_end_number;

  IF has_max_number AND has_end_number THEN
    EXECUTE '
      UPDATE "ElectronicSequence"
      SET
        "maxNumber" = GREATEST(
          COALESCE("maxNumber", 0),
          COALESCE("endNumber", 0),
          COALESCE("currentNumber", 0)
        ),
        "endNumber" = GREATEST(
          COALESCE("endNumber", 0),
          COALESCE("maxNumber", 0),
          COALESCE("currentNumber", 0)
        )
      WHERE "maxNumber" IS DISTINCT FROM GREATEST(
          COALESCE("maxNumber", 0),
          COALESCE("endNumber", 0),
          COALESCE("currentNumber", 0)
        )
        OR "endNumber" IS DISTINCT FROM GREATEST(
          COALESCE("endNumber", 0),
          COALESCE("maxNumber", 0),
          COALESCE("currentNumber", 0)
        )
    ';
  ELSIF has_max_number THEN
    EXECUTE '
      UPDATE "ElectronicSequence"
      SET "maxNumber" = GREATEST(COALESCE("maxNumber", 0), COALESCE("currentNumber", 0))
      WHERE "maxNumber" IS NULL OR "maxNumber" < "currentNumber"
    ';
  ELSIF has_end_number THEN
    EXECUTE '
      UPDATE "ElectronicSequence"
      SET "endNumber" = GREATEST(COALESCE("endNumber", 0), COALESCE("currentNumber", 0))
      WHERE "endNumber" IS NULL OR "endNumber" < "currentNumber"
    ';
  END IF;

  ALTER TABLE "ElectronicSequence"
    DROP CONSTRAINT IF EXISTS "ElectronicSequence_currentNumber_check";

  IF has_max_number AND has_end_number THEN
    EXECUTE '
      ALTER TABLE "ElectronicSequence"
      ADD CONSTRAINT "ElectronicSequence_currentNumber_check"
      CHECK (
        "currentNumber" >= 0
        AND "currentNumber" <= GREATEST(COALESCE("maxNumber", 0), COALESCE("endNumber", 0))
      )
    ';
  ELSIF has_max_number THEN
    EXECUTE '
      ALTER TABLE "ElectronicSequence"
      ADD CONSTRAINT "ElectronicSequence_currentNumber_check"
      CHECK ("currentNumber" >= 0 AND "currentNumber" <= "maxNumber")
    ';
  ELSIF has_end_number THEN
    EXECUTE '
      ALTER TABLE "ElectronicSequence"
      ADD CONSTRAINT "ElectronicSequence_currentNumber_check"
      CHECK ("currentNumber" >= 0 AND "currentNumber" <= "endNumber")
    ';
  ELSE
    EXECUTE '
      ALTER TABLE "ElectronicSequence"
      ADD CONSTRAINT "ElectronicSequence_currentNumber_check"
      CHECK ("currentNumber" >= 0)
    ';
  END IF;
END $$;

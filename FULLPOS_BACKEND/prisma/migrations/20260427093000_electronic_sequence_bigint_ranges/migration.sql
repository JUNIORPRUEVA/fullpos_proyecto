-- Allow DGII e-CF authorized ranges up to 10 digits.
-- PostgreSQL INTEGER overflows above 2,147,483,647, but e-CF numbers may reach 9,999,999,999.

ALTER TABLE "ElectronicSequence"
  ALTER COLUMN "currentNumber" TYPE BIGINT USING "currentNumber"::bigint,
  ALTER COLUMN "maxNumber" TYPE BIGINT USING "maxNumber"::bigint;

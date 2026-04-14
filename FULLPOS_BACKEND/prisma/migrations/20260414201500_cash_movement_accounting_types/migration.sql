ALTER TABLE "CashMovement"
  ADD COLUMN "movementType" TEXT NOT NULL DEFAULT 'expense',
  ADD COLUMN "affectsProfit" BOOLEAN NOT NULL DEFAULT true;

UPDATE "CashMovement"
SET "movementType" = 'expense'
WHERE COALESCE("movementType", '') = '';

UPDATE "CashMovement"
SET "affectsProfit" = CASE
  WHEN LOWER(COALESCE("type", '')) = 'out' AND COALESCE("movementType", 'expense') = 'expense' THEN true
  ELSE false
END;
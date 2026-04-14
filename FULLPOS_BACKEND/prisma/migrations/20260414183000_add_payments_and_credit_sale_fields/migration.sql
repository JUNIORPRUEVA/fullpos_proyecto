ALTER TABLE "Sale"
  ADD COLUMN "creditInterestRate" DECIMAL(7,4) NOT NULL DEFAULT 0,
  ADD COLUMN "creditTermDays" INTEGER,
  ADD COLUMN "creditDueDate" TIMESTAMP(3),
  ADD COLUMN "creditInstallments" INTEGER,
  ADD COLUMN "creditNote" TEXT;

CREATE TABLE "Payment" (
  "id" SERIAL NOT NULL,
  "companyId" INTEGER NOT NULL,
  "saleId" INTEGER NOT NULL,
  "sessionId" INTEGER,
  "localId" INTEGER,
  "kind" TEXT NOT NULL,
  "method" TEXT NOT NULL,
  "amount" DECIMAL(12,2) NOT NULL,
  "note" TEXT,
  "postedAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "Payment_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "CreditPayment" (
  "paymentId" INTEGER NOT NULL,
  "totalDueSnapshot" DECIMAL(12,2) NOT NULL DEFAULT 0,
  "totalPaidSnapshot" DECIMAL(12,2) NOT NULL DEFAULT 0,
  "pendingAmountSnapshot" DECIMAL(12,2) NOT NULL DEFAULT 0,

  CONSTRAINT "CreditPayment_pkey" PRIMARY KEY ("paymentId")
);

CREATE TABLE "LayawayPayment" (
  "paymentId" INTEGER NOT NULL,
  "totalDueSnapshot" DECIMAL(12,2) NOT NULL DEFAULT 0,
  "totalPaidSnapshot" DECIMAL(12,2) NOT NULL DEFAULT 0,
  "pendingAmountSnapshot" DECIMAL(12,2) NOT NULL DEFAULT 0,
  "statusSnapshot" TEXT,

  CONSTRAINT "LayawayPayment_pkey" PRIMARY KEY ("paymentId")
);

CREATE UNIQUE INDEX "Payment_companyId_kind_localId_key"
ON "Payment"("companyId", "kind", "localId");

CREATE INDEX "Payment_companyId_postedAt_idx"
ON "Payment"("companyId", "postedAt");

CREATE INDEX "Payment_saleId_postedAt_idx"
ON "Payment"("saleId", "postedAt");

ALTER TABLE "Payment"
  ADD CONSTRAINT "Payment_companyId_fkey"
  FOREIGN KEY ("companyId") REFERENCES "Company"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "Payment"
  ADD CONSTRAINT "Payment_saleId_fkey"
  FOREIGN KEY ("saleId") REFERENCES "Sale"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "Payment"
  ADD CONSTRAINT "Payment_sessionId_fkey"
  FOREIGN KEY ("sessionId") REFERENCES "CashSession"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "CreditPayment"
  ADD CONSTRAINT "CreditPayment_paymentId_fkey"
  FOREIGN KEY ("paymentId") REFERENCES "Payment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "LayawayPayment"
  ADD CONSTRAINT "LayawayPayment_paymentId_fkey"
  FOREIGN KEY ("paymentId") REFERENCES "Payment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

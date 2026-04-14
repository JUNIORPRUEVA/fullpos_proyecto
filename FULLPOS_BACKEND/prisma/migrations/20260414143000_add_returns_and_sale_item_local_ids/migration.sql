ALTER TABLE "SaleItem"
ADD COLUMN "localId" INTEGER;

CREATE UNIQUE INDEX "SaleItem_saleId_localId_key"
ON "SaleItem"("saleId", "localId");

CREATE TABLE "Return" (
  "id" SERIAL NOT NULL,
  "companyId" INTEGER NOT NULL,
  "localId" INTEGER,
  "originalSaleId" INTEGER NOT NULL,
  "returnSaleId" INTEGER NOT NULL,
  "note" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "Return_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ReturnItem" (
  "id" SERIAL NOT NULL,
  "returnId" INTEGER NOT NULL,
  "localId" INTEGER,
  "saleItemId" INTEGER,
  "productId" INTEGER,
  "description" TEXT NOT NULL,
  "qty" DECIMAL(12,3) NOT NULL,
  "price" DECIMAL(12,2) NOT NULL,
  "total" DECIMAL(12,2) NOT NULL,

  CONSTRAINT "ReturnItem_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "Return_companyId_localId_key"
ON "Return"("companyId", "localId");

CREATE UNIQUE INDEX "Return_returnSaleId_key"
ON "Return"("returnSaleId");

CREATE INDEX "Return_companyId_createdAt_idx"
ON "Return"("companyId", "createdAt");

CREATE INDEX "Return_originalSaleId_idx"
ON "Return"("originalSaleId");

CREATE UNIQUE INDEX "ReturnItem_returnId_localId_key"
ON "ReturnItem"("returnId", "localId");

CREATE INDEX "ReturnItem_returnId_idx"
ON "ReturnItem"("returnId");

ALTER TABLE "Return"
ADD CONSTRAINT "Return_companyId_fkey"
FOREIGN KEY ("companyId") REFERENCES "Company"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "Return"
ADD CONSTRAINT "Return_originalSaleId_fkey"
FOREIGN KEY ("originalSaleId") REFERENCES "Sale"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "Return"
ADD CONSTRAINT "Return_returnSaleId_fkey"
FOREIGN KEY ("returnSaleId") REFERENCES "Sale"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "ReturnItem"
ADD CONSTRAINT "ReturnItem_returnId_fkey"
FOREIGN KEY ("returnId") REFERENCES "Return"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "ReturnItem"
ADD CONSTRAINT "ReturnItem_saleItemId_fkey"
FOREIGN KEY ("saleItemId") REFERENCES "SaleItem"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "ReturnItem"
ADD CONSTRAINT "ReturnItem_productId_fkey"
FOREIGN KEY ("productId") REFERENCES "Product"("id") ON DELETE SET NULL ON UPDATE CASCADE;
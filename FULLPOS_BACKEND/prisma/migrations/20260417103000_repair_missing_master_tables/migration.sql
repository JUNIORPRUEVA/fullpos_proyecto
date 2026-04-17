CREATE TABLE IF NOT EXISTS "Client" (
  "id" SERIAL NOT NULL,
  "companyId" INTEGER NOT NULL,
  "localId" INTEGER,
  "nombre" TEXT NOT NULL,
  "telefono" TEXT,
  "direccion" TEXT,
  "rnc" TEXT,
  "cedula" TEXT,
  "isActive" BOOLEAN NOT NULL DEFAULT true,
  "hasCredit" BOOLEAN NOT NULL DEFAULT false,
  "deletedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "Client_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "Client_companyId_fkey" FOREIGN KEY ("companyId") REFERENCES "Company"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS "Category" (
  "id" SERIAL NOT NULL,
  "companyId" INTEGER NOT NULL,
  "localId" INTEGER,
  "name" TEXT NOT NULL,
  "isActive" BOOLEAN NOT NULL DEFAULT true,
  "deletedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "Category_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "Category_companyId_fkey" FOREIGN KEY ("companyId") REFERENCES "Company"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS "Supplier" (
  "id" SERIAL NOT NULL,
  "companyId" INTEGER NOT NULL,
  "localId" INTEGER,
  "name" TEXT NOT NULL,
  "phone" TEXT,
  "note" TEXT,
  "isActive" BOOLEAN NOT NULL DEFAULT true,
  "deletedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "Supplier_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "Supplier_companyId_fkey" FOREIGN KEY ("companyId") REFERENCES "Company"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS "Client_companyId_localId_key" ON "Client"("companyId", "localId");
CREATE INDEX IF NOT EXISTS "Client_companyId_updatedAt_idx" ON "Client"("companyId", "updatedAt");

CREATE UNIQUE INDEX IF NOT EXISTS "Category_companyId_localId_key" ON "Category"("companyId", "localId");
CREATE INDEX IF NOT EXISTS "Category_companyId_updatedAt_idx" ON "Category"("companyId", "updatedAt");

CREATE UNIQUE INDEX IF NOT EXISTS "Supplier_companyId_localId_key" ON "Supplier"("companyId", "localId");
CREATE INDEX IF NOT EXISTS "Supplier_companyId_updatedAt_idx" ON "Supplier"("companyId", "updatedAt");
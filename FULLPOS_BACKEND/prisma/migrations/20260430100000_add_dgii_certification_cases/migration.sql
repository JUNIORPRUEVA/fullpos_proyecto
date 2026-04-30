CREATE TABLE "DgiiCertificationBatch" (
  "id" SERIAL NOT NULL,
  "companyId" INTEGER NOT NULL,
  "rnc" TEXT,
  "fileName" TEXT NOT NULL,
  "uploadedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "status" TEXT NOT NULL DEFAULT 'IMPORTED',
  "totalCases" INTEGER NOT NULL DEFAULT 0,
  "ecfCases" INTEGER NOT NULL DEFAULT 0,
  "rfceCases" INTEGER NOT NULL DEFAULT 0,
  "rawMetadataJson" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "DgiiCertificationBatch_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "DgiiCertificationCase" (
  "id" SERIAL NOT NULL,
  "batchId" INTEGER NOT NULL,
  "companyId" INTEGER NOT NULL,
  "sheetName" TEXT NOT NULL,
  "rowNumber" INTEGER NOT NULL,
  "encf" TEXT,
  "tipoEcf" TEXT,
  "rncEmisor" TEXT,
  "rncComprador" TEXT,
  "fechaEmision" TIMESTAMP(3),
  "montoTotal" DECIMAL(14,2),
  "rawRowJson" JSONB NOT NULL,
  "status" TEXT NOT NULL DEFAULT 'IMPORTED',
  "xmlGenerated" TEXT,
  "xmlSigned" TEXT,
  "trackId" TEXT,
  "dgiiRawResponseJson" JSONB,
  "errorMessage" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "DgiiCertificationCase_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "DgiiCertificationBatch_companyId_uploadedAt_idx" ON "DgiiCertificationBatch"("companyId", "uploadedAt");
CREATE INDEX "DgiiCertificationBatch_companyId_status_idx" ON "DgiiCertificationBatch"("companyId", "status");

CREATE INDEX "DgiiCertificationCase_companyId_batchId_idx" ON "DgiiCertificationCase"("companyId", "batchId");
CREATE INDEX "DgiiCertificationCase_companyId_status_idx" ON "DgiiCertificationCase"("companyId", "status");
CREATE INDEX "DgiiCertificationCase_companyId_sheetName_idx" ON "DgiiCertificationCase"("companyId", "sheetName");
CREATE INDEX "DgiiCertificationCase_companyId_encf_idx" ON "DgiiCertificationCase"("companyId", "encf");

ALTER TABLE "DgiiCertificationBatch"
  ADD CONSTRAINT "DgiiCertificationBatch_companyId_fkey"
  FOREIGN KEY ("companyId") REFERENCES "Company"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "DgiiCertificationCase"
  ADD CONSTRAINT "DgiiCertificationCase_batchId_fkey"
  FOREIGN KEY ("batchId") REFERENCES "DgiiCertificationBatch"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "DgiiCertificationCase"
  ADD CONSTRAINT "DgiiCertificationCase_companyId_fkey"
  FOREIGN KEY ("companyId") REFERENCES "Company"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

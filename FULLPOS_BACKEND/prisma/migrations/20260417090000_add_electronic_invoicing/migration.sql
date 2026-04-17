CREATE TYPE "ElectronicInvoiceDirection" AS ENUM ('outbound', 'inbound');

CREATE TYPE "ElectronicInvoiceInternalStatus" AS ENUM (
  'DRAFT',
  'GENERATED',
  'SIGNED',
  'SUBMISSION_PENDING',
  'SUBMITTED',
  'ACCEPTED',
  'ACCEPTED_CONDITIONAL',
  'REJECTED',
  'COMMERCIAL_APPROVED',
  'COMMERCIAL_REJECTED',
  'VOID_PENDING',
  'VOIDED',
  'ERROR'
);

CREATE TYPE "ElectronicInvoiceCommercialStatus" AS ENUM (
  'NONE',
  'PENDING',
  'APPROVED',
  'REJECTED'
);

CREATE TYPE "ElectronicInvoiceDgiiStatus" AS ENUM (
  'NOT_SENT',
  'RECEIVED',
  'IN_PROCESS',
  'ACCEPTED',
  'ACCEPTED_CONDITIONAL',
  'REJECTED',
  'ERROR'
);

CREATE TYPE "ElectronicSequenceStatus" AS ENUM ('ACTIVE', 'PAUSED', 'EXHAUSTED', 'INACTIVE');

CREATE TYPE "ElectronicCertificateStatus" AS ENUM ('ACTIVE', 'EXPIRED', 'REVOKED', 'INACTIVE', 'INVALID');

CREATE TYPE "ElectronicAuditSeverity" AS ENUM ('INFO', 'WARN', 'ERROR', 'CRITICAL');

CREATE TABLE "ElectronicSequence" (
  "id" SERIAL NOT NULL,
  "companyId" INTEGER NOT NULL,
  "branchId" INTEGER NOT NULL DEFAULT 0,
  "documentTypeCode" TEXT NOT NULL,
  "prefix" TEXT NOT NULL,
  "currentNumber" INTEGER NOT NULL DEFAULT 0,
  "maxNumber" INTEGER NOT NULL,
  "status" "ElectronicSequenceStatus" NOT NULL DEFAULT 'ACTIVE',
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ElectronicSequence_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ElectronicCertificate" (
  "id" SERIAL NOT NULL,
  "companyId" INTEGER NOT NULL,
  "alias" TEXT NOT NULL,
  "filePath" TEXT,
  "secretReference" TEXT,
  "passwordEncrypted" TEXT NOT NULL,
  "serialNumber" TEXT NOT NULL,
  "issuer" TEXT NOT NULL,
  "subject" TEXT NOT NULL,
  "validFrom" TIMESTAMP(3) NOT NULL,
  "validTo" TIMESTAMP(3) NOT NULL,
  "status" "ElectronicCertificateStatus" NOT NULL DEFAULT 'ACTIVE',
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ElectronicCertificate_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ElectronicInboundEndpointConfig" (
  "id" SERIAL NOT NULL,
  "companyId" INTEGER NOT NULL,
  "branchId" INTEGER NOT NULL DEFAULT 0,
  "authEnabled" BOOLEAN NOT NULL DEFAULT true,
  "authPath" TEXT NOT NULL,
  "receptionPath" TEXT NOT NULL,
  "approvalPath" TEXT NOT NULL,
  "publicBaseUrl" TEXT NOT NULL,
  "active" BOOLEAN NOT NULL DEFAULT true,
  "outboundEnabled" BOOLEAN NOT NULL DEFAULT false,
  "environment" TEXT NOT NULL DEFAULT 'precertification',
  "tokenTtlSeconds" INTEGER NOT NULL DEFAULT 300,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ElectronicInboundEndpointConfig_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ElectronicInvoice" (
  "id" SERIAL NOT NULL,
  "companyId" INTEGER NOT NULL,
  "branchId" INTEGER NOT NULL DEFAULT 0,
  "saleId" INTEGER,
  "originalInvoiceId" INTEGER,
  "certificateId" INTEGER,
  "direction" "ElectronicInvoiceDirection" NOT NULL,
  "documentTypeCode" TEXT NOT NULL,
  "ecf" TEXT NOT NULL,
  "sequenceNumber" INTEGER NOT NULL,
  "issuerRnc" TEXT NOT NULL,
  "issuerName" TEXT NOT NULL,
  "buyerRnc" TEXT,
  "buyerName" TEXT,
  "issueDate" TIMESTAMP(3) NOT NULL,
  "totalAmount" DECIMAL(14,2) NOT NULL,
  "taxAmount" DECIMAL(14,2) NOT NULL,
  "currencyCode" TEXT NOT NULL DEFAULT 'DOP',
  "xmlUnsigned" TEXT,
  "xmlSigned" TEXT,
  "xmlHash" TEXT,
  "dgiiTrackId" TEXT,
  "dgiiStatus" "ElectronicInvoiceDgiiStatus" NOT NULL DEFAULT 'NOT_SENT',
  "commercialStatus" "ElectronicInvoiceCommercialStatus" NOT NULL DEFAULT 'NONE',
  "internalStatus" "ElectronicInvoiceInternalStatus" NOT NULL DEFAULT 'DRAFT',
  "rejectionCode" TEXT,
  "rejectionMessage" TEXT,
  "dgiiRawResponseJson" JSONB,
  "signedAt" TIMESTAMP(3),
  "submittedAt" TIMESTAMP(3),
  "acceptedAt" TIMESTAMP(3),
  "rejectedAt" TIMESTAMP(3),
  "canceledAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ElectronicInvoice_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ElectronicInvoiceStatusHistory" (
  "id" SERIAL NOT NULL,
  "electronicInvoiceId" INTEGER NOT NULL,
  "fromStatus" TEXT,
  "toStatus" TEXT NOT NULL,
  "note" TEXT,
  "rawPayloadJson" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "createdBy" TEXT,
  CONSTRAINT "ElectronicInvoiceStatusHistory_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ElectronicAuditLog" (
  "id" SERIAL NOT NULL,
  "companyId" INTEGER NOT NULL,
  "invoiceId" INTEGER,
  "eventType" TEXT NOT NULL,
  "eventSource" TEXT NOT NULL,
  "severity" "ElectronicAuditSeverity" NOT NULL DEFAULT 'INFO',
  "message" TEXT NOT NULL,
  "payloadJson" JSONB,
  "requestId" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ElectronicAuditLog_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ElectronicAuthSeed" (
  "id" TEXT NOT NULL,
  "companyId" INTEGER NOT NULL,
  "nonce" TEXT NOT NULL,
  "challengeHash" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "validatedAt" TIMESTAMP(3),
  "usedAt" TIMESTAMP(3),
  "tokenHash" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ElectronicAuthSeed_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "ElectronicSequence_companyId_branchId_documentTypeCode_key" ON "ElectronicSequence"("companyId", "branchId", "documentTypeCode");
CREATE INDEX "ElectronicSequence_companyId_status_idx" ON "ElectronicSequence"("companyId", "status");

CREATE UNIQUE INDEX "ElectronicCertificate_companyId_alias_key" ON "ElectronicCertificate"("companyId", "alias");
CREATE INDEX "ElectronicCertificate_companyId_status_idx" ON "ElectronicCertificate"("companyId", "status");

CREATE UNIQUE INDEX "ElectronicInboundEndpointConfig_companyId_branchId_key" ON "ElectronicInboundEndpointConfig"("companyId", "branchId");

CREATE UNIQUE INDEX "ElectronicInvoice_companyId_ecf_key" ON "ElectronicInvoice"("companyId", "ecf");
CREATE INDEX "ElectronicInvoice_companyId_direction_createdAt_idx" ON "ElectronicInvoice"("companyId", "direction", "createdAt");
CREATE INDEX "ElectronicInvoice_companyId_internalStatus_createdAt_idx" ON "ElectronicInvoice"("companyId", "internalStatus", "createdAt");
CREATE INDEX "ElectronicInvoice_companyId_dgiiTrackId_idx" ON "ElectronicInvoice"("companyId", "dgiiTrackId");
CREATE INDEX "ElectronicInvoice_saleId_idx" ON "ElectronicInvoice"("saleId");

CREATE INDEX "ElectronicInvoiceStatusHistory_electronicInvoiceId_createdAt_idx" ON "ElectronicInvoiceStatusHistory"("electronicInvoiceId", "createdAt");

CREATE INDEX "ElectronicAuditLog_companyId_createdAt_idx" ON "ElectronicAuditLog"("companyId", "createdAt");
CREATE INDEX "ElectronicAuditLog_invoiceId_createdAt_idx" ON "ElectronicAuditLog"("invoiceId", "createdAt");

CREATE INDEX "ElectronicAuthSeed_companyId_expiresAt_idx" ON "ElectronicAuthSeed"("companyId", "expiresAt");

ALTER TABLE "ElectronicSequence"
  ADD CONSTRAINT "ElectronicSequence_companyId_fkey"
  FOREIGN KEY ("companyId") REFERENCES "Company"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "ElectronicCertificate"
  ADD CONSTRAINT "ElectronicCertificate_companyId_fkey"
  FOREIGN KEY ("companyId") REFERENCES "Company"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "ElectronicInboundEndpointConfig"
  ADD CONSTRAINT "ElectronicInboundEndpointConfig_companyId_fkey"
  FOREIGN KEY ("companyId") REFERENCES "Company"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "ElectronicInvoice"
  ADD CONSTRAINT "ElectronicInvoice_companyId_fkey"
  FOREIGN KEY ("companyId") REFERENCES "Company"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "ElectronicInvoice"
  ADD CONSTRAINT "ElectronicInvoice_saleId_fkey"
  FOREIGN KEY ("saleId") REFERENCES "Sale"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "ElectronicInvoice"
  ADD CONSTRAINT "ElectronicInvoice_originalInvoiceId_fkey"
  FOREIGN KEY ("originalInvoiceId") REFERENCES "ElectronicInvoice"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "ElectronicInvoice"
  ADD CONSTRAINT "ElectronicInvoice_certificateId_fkey"
  FOREIGN KEY ("certificateId") REFERENCES "ElectronicCertificate"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "ElectronicInvoiceStatusHistory"
  ADD CONSTRAINT "ElectronicInvoiceStatusHistory_electronicInvoiceId_fkey"
  FOREIGN KEY ("electronicInvoiceId") REFERENCES "ElectronicInvoice"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "ElectronicAuditLog"
  ADD CONSTRAINT "ElectronicAuditLog_companyId_fkey"
  FOREIGN KEY ("companyId") REFERENCES "Company"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "ElectronicAuditLog"
  ADD CONSTRAINT "ElectronicAuditLog_invoiceId_fkey"
  FOREIGN KEY ("invoiceId") REFERENCES "ElectronicInvoice"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "ElectronicAuthSeed"
  ADD CONSTRAINT "ElectronicAuthSeed_companyId_fkey"
  FOREIGN KEY ("companyId") REFERENCES "Company"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
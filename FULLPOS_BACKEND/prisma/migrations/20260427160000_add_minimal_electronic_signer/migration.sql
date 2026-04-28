-- Add minimal electronic invoicing responsible signer fields
ALTER TABLE "ElectronicInboundEndpointConfig"
  ADD COLUMN IF NOT EXISTS "signerFullName" TEXT,
  ADD COLUMN IF NOT EXISTS "signerDocumentType" TEXT,
  ADD COLUMN IF NOT EXISTS "signerDocumentNumber" TEXT,
  ADD COLUMN IF NOT EXISTS "signerAuthorizedForDgii" BOOLEAN NOT NULL DEFAULT false;

export type SupportedDocumentTypeCode =
  | '31'
  | '32'
  | '33'
  | '34'
  | '41'
  | '43'
  | '44'
  | '45';

export type InvoiceDirection = 'outbound' | 'inbound';

export interface ElectronicParty {
  rnc?: string | null;
  name: string;
  address?: string | null;
  email?: string | null;
  phone?: string | null;
}

export interface ElectronicInvoiceLineInput {
  lineNumber: number;
  productCode?: string | null;
  description: string;
  quantity: number;
  unitPrice: number;
  lineExtensionAmount: number;
  taxAmount: number;
}

export interface ElectronicInvoiceReference {
  modifiedEcf: string;
  modifiedDocumentTypeCode?: string | null;
  reason?: string | null;
  modifiedIssueDate?: Date | null;
}

export interface ElectronicInvoiceBuildInput {
  saleIdResolved?: number;
  ecf: string;
  documentTypeCode: SupportedDocumentTypeCode;
  issueDate: Date;
  currencyCode: string;
  issuer: ElectronicParty;
  buyer: ElectronicParty;
  lines: ElectronicInvoiceLineInput[];
  subtotalAmount: number;
  taxAmount: number;
  totalAmount: number;
  reference?: ElectronicInvoiceReference | null;
  signatureDate?: Date;
}

export interface ParsedInvoiceXmlMetadata {
  ecf?: string;
  documentTypeCode?: string;
  issuerRnc?: string;
  issuerName?: string;
  buyerRnc?: string;
  buyerName?: string;
  issueDate?: Date;
  totalAmount?: number;
  taxAmount?: number;
  currencyCode?: string;
}

export interface OutboundInvoiceListFilters {
  documentTypeCode?: string;
  internalStatus?: string;
  dgiiStatus?: string;
  fromDate?: Date;
  toDate?: Date;
  search?: string;
}

export interface PublicAuthTokenPayload {
  companyId: number;
  branchId: number;
  seedId: string;
  certificateSerialNumber: string;
  subject: string;
}
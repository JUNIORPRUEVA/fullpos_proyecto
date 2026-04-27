import { PrismaClient, ElectronicAuditSeverity } from '@prisma/client';

type AuditInput = {
  companyId: number;
  invoiceId?: number | null;
  eventType: string;
  eventSource: string;
  severity?: ElectronicAuditSeverity;
  message: string;
  payload?: unknown;
  requestId?: string;
};

function redactPayload(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(redactPayload);
  }

  if (!value || typeof value !== 'object') {
    return value;
  }

  const clone: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    const lowerKey = key.toLowerCase();
    if (
      lowerKey.includes('password') ||
      lowerKey.includes('secret') ||
      lowerKey.includes('token') ||
      lowerKey.includes('authorization')
    ) {
      clone[key] = '[REDACTED]';
      continue;
    }

    clone[key] = redactPayload(entry);
  }

  return clone;
}

function stringifyJsonValue(value: unknown) {
  return JSON.stringify(redactPayload(value), (_key, entry) => (
    typeof entry === 'bigint' ? Number(entry) : entry
  ));
}

export class ElectronicInvoicingAuditService {
  constructor(private readonly prisma: PrismaClient) {}

  private toJsonValue(value: unknown) {
    return value == null ? null : JSON.parse(stringifyJsonValue(value));
  }

  async log(input: AuditInput) {
    await this.prisma.electronicAuditLog.create({
      data: {
        companyId: input.companyId,
        invoiceId: input.invoiceId ?? null,
        eventType: input.eventType,
        eventSource: input.eventSource,
        severity: input.severity ?? 'INFO',
        message: input.message,
        payloadJson: this.toJsonValue(input.payload),
        requestId: input.requestId,
      },
    });
  }

  listInvoiceAudit(companyId: number, invoiceId: number) {
    return this.prisma.electronicAuditLog.findMany({
      where: { companyId, invoiceId },
      orderBy: { createdAt: 'asc' },
    });
  }
}
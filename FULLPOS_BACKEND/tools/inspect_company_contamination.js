/*
  Diagnóstico seguro de posible contaminación por empresa/RNC/tenant.
  No modifica datos.

  Uso PowerShell:
    Set-Location "FULLPOS_BACKEND";
    $env:COMPANY_RNC="133080206"; node tools/inspect_company_contamination.js

  Opcionales:
    $env:COMPANY_ID="1";
    $env:COMPANY_TENANT_KEY="fullpos:133080206:business:terminal";
    $env:OUTPUT_JSON="contamination-report.json";
*/

const fs = require('node:fs');
const path = require('node:path');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

function normalizeRnc(value) {
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9]/g, '');
}

function compact(obj) {
  return Object.fromEntries(Object.entries(obj).filter(([, value]) => value !== undefined && value !== null && value !== ''));
}

async function findCompanies() {
  const companyId = process.env.COMPANY_ID ? Number(process.env.COMPANY_ID) : null;
  const tenantKey = String(process.env.COMPANY_TENANT_KEY || '').trim().toLowerCase();
  const rnc = String(process.env.COMPANY_RNC || '').trim();
  const normalizedRnc = normalizeRnc(rnc);

  if (companyId && (!Number.isInteger(companyId) || companyId <= 0)) {
    throw new Error(`COMPANY_ID inválido: ${process.env.COMPANY_ID}`);
  }

  if (companyId) {
    return prisma.company.findMany({ where: { id: companyId }, orderBy: { id: 'asc' } });
  }

  if (tenantKey) {
    return prisma.company.findMany({ where: { tenantKey }, orderBy: { id: 'asc' } });
  }

  if (normalizedRnc) {
    const indexed = await prisma.company.findMany({ where: { normalizedRnc }, orderBy: { id: 'asc' } });
    if (indexed.length > 0) return indexed;

    const candidates = await prisma.company.findMany({ where: { rnc: { not: null } }, orderBy: { id: 'asc' } });
    return candidates.filter((company) => normalizeRnc(company.rnc) === normalizedRnc);
  }

  throw new Error('Indique COMPANY_ID, COMPANY_TENANT_KEY o COMPANY_RNC para inspeccionar.');
}

async function countCompanyData(companyId) {
  const [
    users,
    refreshTokens,
    terminals,
    integrationTokens,
    companyConfig,
    products,
    clients,
    categories,
    suppliers,
    sales,
    saleItems,
    payments,
    creditPayments,
    layawayPayments,
    returns,
    returnItems,
    cashSessions,
    cashMovements,
    expenses,
    quotes,
    quoteItems,
    cloudBackups,
    overrideTokens,
    overrideRequests,
    auditLogs,
    electronicInvoices,
    electronicInvoiceStatusHistory,
    electronicSequences,
    electronicCertificates,
    electronicInboundEndpointConfigs,
    electronicDgiiTokenCaches,
    electronicAuditLogs,
    electronicAuthSeeds,
  ] = await Promise.all([
    prisma.user.count({ where: { companyId } }),
    prisma.refreshToken.count({ where: { user: { companyId } } }),
    prisma.terminal.count({ where: { companyId } }),
    prisma.integrationToken.count({ where: { companyId } }),
    prisma.companyConfig.count({ where: { companyId } }),
    prisma.product.count({ where: { companyId } }),
    prisma.client.count({ where: { companyId } }),
    prisma.category.count({ where: { companyId } }),
    prisma.supplier.count({ where: { companyId } }),
    prisma.sale.count({ where: { companyId } }),
    prisma.saleItem.count({ where: { sale: { companyId } } }),
    prisma.payment.count({ where: { companyId } }),
    prisma.creditPayment.count({ where: { payment: { companyId } } }),
    prisma.layawayPayment.count({ where: { payment: { companyId } } }),
    prisma.return.count({ where: { companyId } }),
    prisma.returnItem.count({ where: { return: { companyId } } }),
    prisma.cashSession.count({ where: { companyId } }),
    prisma.cashMovement.count({ where: { companyId } }),
    prisma.expense.count({ where: { companyId } }),
    prisma.quote.count({ where: { companyId } }),
    prisma.quoteItem.count({ where: { quote: { companyId } } }),
    prisma.cloudBackup.count({ where: { companyId } }),
    prisma.overrideToken.count({ where: { companyId } }),
    prisma.overrideRequest.count({ where: { companyId } }),
    prisma.auditLog.count({ where: { companyId } }),
    prisma.electronicInvoice.count({ where: { companyId } }),
    prisma.electronicInvoiceStatusHistory.count({ where: { electronicInvoice: { companyId } } }),
    prisma.electronicSequence.count({ where: { companyId } }),
    prisma.electronicCertificate.count({ where: { companyId } }),
    prisma.electronicInboundEndpointConfig.count({ where: { companyId } }),
    prisma.electronicDgiiTokenCache.count({ where: { companyId } }),
    prisma.electronicAuditLog.count({ where: { companyId } }),
    prisma.electronicAuthSeed.count({ where: { companyId } }),
  ]);

  return {
    users,
    refreshTokens,
    terminals,
    integrationTokens,
    companyConfig,
    products,
    clients,
    categories,
    suppliers,
    sales,
    saleItems,
    payments,
    creditPayments,
    layawayPayments,
    returns,
    returnItems,
    cashSessions,
    cashMovements,
    expenses,
    quotes,
    quoteItems,
    cloudBackups,
    overrideTokens,
    overrideRequests,
    auditLogs,
    electronicInvoices,
    electronicInvoiceStatusHistory,
    electronicSequences,
    electronicCertificates,
    electronicInboundEndpointConfigs,
    electronicDgiiTokenCaches,
    electronicAuditLogs,
    electronicAuthSeeds,
  };
}

async function sampleRecent(companyId) {
  const [sales, products, users, terminals] = await Promise.all([
    prisma.sale.findMany({
      where: { companyId },
      orderBy: { updatedAt: 'desc' },
      take: 5,
      select: { id: true, localCode: true, total: true, status: true, createdAt: true, updatedAt: true },
    }),
    prisma.product.findMany({
      where: { companyId },
      orderBy: { updatedAt: 'desc' },
      take: 5,
      select: { id: true, localId: true, code: true, name: true, updatedAt: true },
    }),
    prisma.user.findMany({
      where: { companyId },
      orderBy: { id: 'asc' },
      take: 10,
      select: { id: true, username: true, role: true, isActive: true },
    }),
    prisma.terminal.findMany({
      where: { companyId },
      orderBy: { id: 'asc' },
      take: 10,
      select: { id: true, deviceId: true, name: true, lastSeen: true, isActive: true },
    }),
  ]);

  return { sales, products, users, terminals };
}

async function main() {
  const companies = await findCompanies();
  const report = {
    generatedAt: new Date().toISOString(),
    filter: compact({
      companyId: process.env.COMPANY_ID,
      companyTenantKey: process.env.COMPANY_TENANT_KEY,
      companyRnc: process.env.COMPANY_RNC,
      normalizedRnc: normalizeRnc(process.env.COMPANY_RNC),
    }),
    duplicateWarning: companies.length > 1,
    companies: [],
  };

  for (const company of companies) {
    report.companies.push({
      company: {
        id: company.id,
        name: company.name,
        rnc: company.rnc,
        normalizedRnc: company.normalizedRnc,
        cloudCompanyId: company.cloudCompanyId,
        tenantKey: company.tenantKey,
        sourceBusinessId: company.sourceBusinessId,
        primaryDeviceId: company.primaryDeviceId,
        isActive: company.isActive,
        createdAt: company.createdAt,
        updatedAt: company.updatedAt,
      },
      counts: await countCompanyData(company.id),
      sampleRecent: await sampleRecent(company.id),
    });
  }

  console.dir(report, { depth: null });

  if (process.env.OUTPUT_JSON) {
    const outputPath = path.resolve(process.env.OUTPUT_JSON);
    fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
    console.log(`Reporte guardado en ${outputPath}`);
  }

  if (companies.length > 1) {
    console.warn('ADVERTENCIA: hay más de una empresa para el filtro. No purgue hasta confirmar cuál es la contaminada.');
  }
}

main()
  .catch((err) => {
    console.error('ERROR:', err?.message ?? err);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

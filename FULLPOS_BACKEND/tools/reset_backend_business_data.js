/*
  Reseteo seguro de datos de negocio del backend para resincronizar limpio.

  No borra migraciones de Prisma. Por defecto NO borra Company ni Users.
  Primero siempre corre en DRY_RUN=true.

  Uso PowerShell:
    Set-Location "FULLPOS_BACKEND";
    $env:DATABASE_URL="postgresql://..."; # o crear .env con DATABASE_URL real
    node tools/reset_backend_business_data.js

  Para borrar datos de negocio de TODAS las empresas:
    $env:DRY_RUN="false";
    $env:RESET_SCOPE="ALL_COMPANIES";
    $env:CONFIRM_RESET_CLOUD_DATA="RESET_FULLPOS_CLOUD_DATA";
    node tools/reset_backend_business_data.js

  Para limitar por RNC:
    $env:COMPANY_RNC="133080206";
    $env:DRY_RUN="false";
    $env:RESET_SCOPE="MATCHED_COMPANIES";
    $env:CONFIRM_RESET_CLOUD_DATA="RESET_FULLPOS_CLOUD_DATA";
    node tools/reset_backend_business_data.js

  Opcionales:
    $env:OUTPUT_BACKUP_JSON="reset-backup.json";
    $env:DELETE_COMPANIES="true"; # peligroso: borra Company después de limpiar dependencias
    $env:DELETE_USERS="true";     # peligroso: borra usuarios de esas empresas
*/

require('dotenv').config();

const fs = require('node:fs');
const path = require('node:path');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

function parseBool(value, fallback = false) {
  if (value == null || value === '') return fallback;
  const normalized = String(value).trim().toLowerCase();
  return normalized === 'true' || normalized === '1' || normalized === 'yes';
}

function normalizeRnc(value) {
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9]/g, '');
}

function jsonSafe(value) {
  return JSON.parse(JSON.stringify(value, (_key, item) => (typeof item === 'bigint' ? item.toString() : item)));
}

function summarizeDeleteMany(result) {
  const out = {};
  for (const [key, value] of Object.entries(result)) {
    if (value && typeof value === 'object' && 'count' in value) out[key] = value.count;
  }
  return out;
}

async function findTargetCompanies() {
  const scope = String(process.env.RESET_SCOPE || 'DRY_RUN_ONLY').trim().toUpperCase();
  const companyId = process.env.COMPANY_ID ? Number(process.env.COMPANY_ID) : null;
  const tenantKey = String(process.env.COMPANY_TENANT_KEY || '').trim().toLowerCase();
  const normalizedRnc = normalizeRnc(process.env.COMPANY_RNC);

  if (companyId) {
    if (!Number.isInteger(companyId) || companyId <= 0) throw new Error(`COMPANY_ID inválido: ${process.env.COMPANY_ID}`);
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

  if (scope === 'ALL_COMPANIES') {
    return prisma.company.findMany({ orderBy: { id: 'asc' } });
  }

  throw new Error('Filtro requerido: use COMPANY_ID, COMPANY_TENANT_KEY, COMPANY_RNC o RESET_SCOPE=ALL_COMPANIES.');
}

async function getCounts(companyIds) {
  const whereCompany = { companyId: { in: companyIds } };
  const whereUserCompany = { user: { companyId: { in: companyIds } } };
  const whereSaleCompany = { sale: { companyId: { in: companyIds } } };
  const wherePaymentCompany = { payment: { companyId: { in: companyIds } } };
  const whereReturnCompany = { return: { companyId: { in: companyIds } } };
  const whereQuoteCompany = { quote: { companyId: { in: companyIds } } };
  const whereInvoiceCompany = { electronicInvoice: { companyId: { in: companyIds } } };

  const [
    companies,
    users,
    refreshTokens,
    terminals,
    integrationTokens,
    companyConfigs,
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
    prisma.company.count({ where: { id: { in: companyIds } } }),
    prisma.user.count({ where: whereCompany }),
    prisma.refreshToken.count({ where: whereUserCompany }),
    prisma.terminal.count({ where: whereCompany }),
    prisma.integrationToken.count({ where: whereCompany }),
    prisma.companyConfig.count({ where: whereCompany }),
    prisma.product.count({ where: whereCompany }),
    prisma.client.count({ where: whereCompany }),
    prisma.category.count({ where: whereCompany }),
    prisma.supplier.count({ where: whereCompany }),
    prisma.sale.count({ where: whereCompany }),
    prisma.saleItem.count({ where: whereSaleCompany }),
    prisma.payment.count({ where: whereCompany }),
    prisma.creditPayment.count({ where: wherePaymentCompany }),
    prisma.layawayPayment.count({ where: wherePaymentCompany }),
    prisma.return.count({ where: whereCompany }),
    prisma.returnItem.count({ where: whereReturnCompany }),
    prisma.cashSession.count({ where: whereCompany }),
    prisma.cashMovement.count({ where: whereCompany }),
    prisma.expense.count({ where: whereCompany }),
    prisma.quote.count({ where: whereCompany }),
    prisma.quoteItem.count({ where: whereQuoteCompany }),
    prisma.cloudBackup.count({ where: whereCompany }),
    prisma.overrideToken.count({ where: whereCompany }),
    prisma.overrideRequest.count({ where: whereCompany }),
    prisma.auditLog.count({ where: whereCompany }),
    prisma.electronicInvoice.count({ where: whereCompany }),
    prisma.electronicInvoiceStatusHistory.count({ where: whereInvoiceCompany }),
    prisma.electronicSequence.count({ where: whereCompany }),
    prisma.electronicCertificate.count({ where: whereCompany }),
    prisma.electronicInboundEndpointConfig.count({ where: whereCompany }),
    prisma.electronicDgiiTokenCache.count({ where: whereCompany }),
    prisma.electronicAuditLog.count({ where: whereCompany }),
    prisma.electronicAuthSeed.count({ where: whereCompany }),
  ]);

  return {
    companies,
    users,
    refreshTokens,
    terminals,
    integrationTokens,
    companyConfigs,
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

async function exportBackup(companies, counts) {
  if (!process.env.OUTPUT_BACKUP_JSON) return;
  const companyIds = companies.map((company) => company.id);
  const backup = {
    generatedAt: new Date().toISOString(),
    companies,
    counts,
    samples: {
      users: await prisma.user.findMany({ where: { companyId: { in: companyIds } }, select: { id: true, companyId: true, username: true, role: true, isActive: true } }),
      terminals: await prisma.terminal.findMany({ where: { companyId: { in: companyIds } } }),
      products: await prisma.product.findMany({ where: { companyId: { in: companyIds } }, take: 500, orderBy: { id: 'asc' } }),
      clients: await prisma.client.findMany({ where: { companyId: { in: companyIds } }, take: 500, orderBy: { id: 'asc' } }),
      categories: await prisma.category.findMany({ where: { companyId: { in: companyIds } }, take: 500, orderBy: { id: 'asc' } }),
      suppliers: await prisma.supplier.findMany({ where: { companyId: { in: companyIds } }, take: 500, orderBy: { id: 'asc' } }),
      sales: await prisma.sale.findMany({ where: { companyId: { in: companyIds } }, take: 500, orderBy: { id: 'asc' }, include: { items: true, payments: true } }),
      cashSessions: await prisma.cashSession.findMany({ where: { companyId: { in: companyIds } }, take: 500, orderBy: { id: 'asc' }, include: { movements: true } }),
      quotes: await prisma.quote.findMany({ where: { companyId: { in: companyIds } }, take: 500, orderBy: { id: 'asc' }, include: { items: true } }),
      electronicInvoices: await prisma.electronicInvoice.findMany({ where: { companyId: { in: companyIds } }, take: 500, orderBy: { id: 'asc' } }),
    },
  };

  const outputPath = path.resolve(process.env.OUTPUT_BACKUP_JSON);
  fs.writeFileSync(outputPath, JSON.stringify(jsonSafe(backup), null, 2));
  console.log(`Backup/resumen guardado en ${outputPath}`);
}

async function resetData(companyIds, options) {
  const whereCompany = { companyId: { in: companyIds } };
  return prisma.$transaction(async (tx) => {
    const deleted = {};

    deleted.electronicInvoiceStatusHistory = await tx.electronicInvoiceStatusHistory.deleteMany({ where: { electronicInvoice: { companyId: { in: companyIds } } } });
    deleted.electronicAuditLogs = await tx.electronicAuditLog.deleteMany({ where: whereCompany });
    deleted.electronicAuthSeeds = await tx.electronicAuthSeed.deleteMany({ where: whereCompany });
    deleted.electronicDgiiTokenCaches = await tx.electronicDgiiTokenCache.deleteMany({ where: whereCompany });
    deleted.electronicInboundEndpointConfigs = await tx.electronicInboundEndpointConfig.deleteMany({ where: whereCompany });
    deleted.electronicSequences = await tx.electronicSequence.deleteMany({ where: whereCompany });
    deleted.electronicInvoices = await tx.electronicInvoice.deleteMany({ where: whereCompany });
    deleted.electronicCertificates = await tx.electronicCertificate.deleteMany({ where: whereCompany });

    deleted.cloudBackups = await tx.cloudBackup.deleteMany({ where: whereCompany });
    deleted.auditLogs = await tx.auditLog.deleteMany({ where: whereCompany });
    deleted.overrideTokens = await tx.overrideToken.deleteMany({ where: whereCompany });
    deleted.overrideRequests = await tx.overrideRequest.deleteMany({ where: whereCompany });

    deleted.returnItems = await tx.returnItem.deleteMany({ where: { return: { companyId: { in: companyIds } } } });
    deleted.returns = await tx.return.deleteMany({ where: whereCompany });

    deleted.creditPayments = await tx.creditPayment.deleteMany({ where: { payment: { companyId: { in: companyIds } } } });
    deleted.layawayPayments = await tx.layawayPayment.deleteMany({ where: { payment: { companyId: { in: companyIds } } } });
    deleted.payments = await tx.payment.deleteMany({ where: whereCompany });

    deleted.sales = await tx.sale.deleteMany({ where: whereCompany });
    deleted.cashMovements = await tx.cashMovement.deleteMany({ where: whereCompany });
    deleted.cashSessions = await tx.cashSession.deleteMany({ where: whereCompany });
    deleted.expenses = await tx.expense.deleteMany({ where: whereCompany });
    deleted.quotes = await tx.quote.deleteMany({ where: whereCompany });

    deleted.clients = await tx.client.deleteMany({ where: whereCompany });
    deleted.categories = await tx.category.deleteMany({ where: whereCompany });
    deleted.suppliers = await tx.supplier.deleteMany({ where: whereCompany });
    deleted.products = await tx.product.deleteMany({ where: whereCompany });
    deleted.companyConfigs = await tx.companyConfig.deleteMany({ where: whereCompany });
    deleted.terminals = await tx.terminal.deleteMany({ where: whereCompany });

    if (options.deleteUsers || options.deleteCompanies) {
      deleted.refreshTokens = await tx.refreshToken.deleteMany({ where: { user: { companyId: { in: companyIds } } } });
      deleted.integrationTokens = await tx.integrationToken.deleteMany({ where: whereCompany });
      deleted.users = await tx.user.deleteMany({ where: whereCompany });
    }

    if (options.deleteCompanies) {
      deleted.companies = await tx.company.deleteMany({ where: { id: { in: companyIds } } });
    }

    return deleted;
  }, { timeout: 60000 });
}

async function main() {
  if (!process.env.DATABASE_URL) throw new Error('Falta DATABASE_URL o archivo .env con DATABASE_URL.');

  const dryRun = parseBool(process.env.DRY_RUN, true);
  const confirm = String(process.env.CONFIRM_RESET_CLOUD_DATA || '').trim();
  const options = {
    deleteCompanies: parseBool(process.env.DELETE_COMPANIES),
    deleteUsers: parseBool(process.env.DELETE_USERS),
  };

  const companies = await findTargetCompanies();
  if (companies.length === 0) throw new Error('No se encontraron empresas para el filtro indicado.');

  const companyIds = companies.map((company) => company.id);
  const before = await getCounts(companyIds);

  console.log('Empresas objetivo:');
  console.table(companies.map((company) => ({
    id: company.id,
    name: company.name,
    rnc: company.rnc || '',
    normalizedRnc: company.normalizedRnc || '',
    cloudCompanyId: company.cloudCompanyId || '',
    tenantKey: company.tenantKey || '',
    isActive: company.isActive,
  })));
  console.log('Opciones:', { dryRun, ...options });
  console.log('Antes:', before);

  await exportBackup(companies, before);

  if (dryRun) {
    console.log('DRY_RUN=true: no se borró nada. Revise la lista antes de ejecutar borrado real.');
    return;
  }

  if (confirm !== 'RESET_FULLPOS_CLOUD_DATA') {
    throw new Error('Confirmación requerida: CONFIRM_RESET_CLOUD_DATA=RESET_FULLPOS_CLOUD_DATA');
  }

  const deleted = await resetData(companyIds, options);
  console.log('Borrados:', summarizeDeleteMany(deleted));

  const remainingCompanyIds = options.deleteCompanies ? [] : companyIds;
  const after = remainingCompanyIds.length > 0 ? await getCounts(remainingCompanyIds) : { companies: 0 };
  console.log('Después:', after);
  console.log('OK. La DB quedó lista para resincronizar limpio desde FULLPOS actualizado.');
}

main()
  .catch((err) => {
    console.error('ERROR:', err?.message ?? err);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

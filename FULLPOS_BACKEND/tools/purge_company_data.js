/*
  Purga segura de datos de una empresa contaminada en la nube.

  Seguridad obligatoria:
  - Requiere COMPANY_ID.
  - Requiere EXPECTED_TENANT_KEY y debe coincidir con Company.tenantKey.
  - Por defecto es DRY_RUN=true y no borra nada.
  - Para ejecutar borrado real requiere:
      DRY_RUN=false
      CONFIRM_PURGE=DELETE_COMPANY_DATA

  Uso recomendado PowerShell:
    Set-Location "FULLPOS_BACKEND";
    $env:COMPANY_ID="1";
    $env:EXPECTED_TENANT_KEY="fullpos:133080206:business:terminal";
    node tools/purge_company_data.js

  Borrado real:
    $env:DRY_RUN="false";
    $env:CONFIRM_PURGE="DELETE_COMPANY_DATA";
    node tools/purge_company_data.js

  Opcionales:
    $env:OUTPUT_BACKUP_JSON="backup-company-1.json"; # exporta resumen antes de borrar
    $env:PURGE_MASTER_DATA="true"; # productos, clientes, categorías, suplidores
    $env:PURGE_TERMINALS="true";
    $env:PURGE_USERS="true"; # peligroso: borra usuarios/tokens de esa empresa
    $env:PURGE_COMPANY_CONFIG="true";
*/

const fs = require('node:fs');
const path = require('node:path');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

function parseBool(value, fallback = false) {
  if (value == null || value === '') return fallback;
  return String(value).trim().toLowerCase() === 'true' || String(value).trim() === '1';
}

function summarizeDeleteMany(obj) {
  const out = {};
  for (const [key, val] of Object.entries(obj)) {
    if (val && typeof val === 'object' && 'count' in val) out[key] = val.count;
  }
  return out;
}

function jsonSafe(value) {
  return JSON.parse(
    JSON.stringify(value, (_key, item) => (typeof item === 'bigint' ? item.toString() : item)),
  );
}

async function getCounts(companyId) {
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

async function exportBackup(company, counts) {
  if (!process.env.OUTPUT_BACKUP_JSON) return;

  const companyId = company.id;
  const backup = {
    generatedAt: new Date().toISOString(),
    company,
    counts,
    samples: {
      users: await prisma.user.findMany({ where: { companyId }, select: { id: true, username: true, role: true, isActive: true } }),
      terminals: await prisma.terminal.findMany({ where: { companyId }, select: { id: true, deviceId: true, name: true, lastSeen: true, isActive: true } }),
      products: await prisma.product.findMany({ where: { companyId }, take: 200, orderBy: { id: 'asc' } }),
      clients: await prisma.client.findMany({ where: { companyId }, take: 200, orderBy: { id: 'asc' } }),
      categories: await prisma.category.findMany({ where: { companyId }, take: 200, orderBy: { id: 'asc' } }),
      suppliers: await prisma.supplier.findMany({ where: { companyId }, take: 200, orderBy: { id: 'asc' } }),
      sales: await prisma.sale.findMany({ where: { companyId }, take: 200, orderBy: { id: 'asc' }, include: { items: true, payments: true } }),
      cashSessions: await prisma.cashSession.findMany({ where: { companyId }, take: 200, orderBy: { id: 'asc' }, include: { movements: true } }),
      quotes: await prisma.quote.findMany({ where: { companyId }, take: 200, orderBy: { id: 'asc' }, include: { items: true } }),
      electronicInvoices: await prisma.electronicInvoice.findMany({ where: { companyId }, take: 200, orderBy: { id: 'asc' } }),
    },
  };

  const outputPath = path.resolve(process.env.OUTPUT_BACKUP_JSON);
  fs.writeFileSync(outputPath, JSON.stringify(jsonSafe(backup), null, 2));
  console.log(`Backup/resumen guardado en ${outputPath}`);
}

async function purgeCompanyData(companyId, options) {
  return prisma.$transaction(async (tx) => {
    const deleted = {};

    deleted.electronicInvoiceStatusHistory = await tx.electronicInvoiceStatusHistory.deleteMany({
      where: { electronicInvoice: { companyId } },
    });
    deleted.electronicAuditLogs = await tx.electronicAuditLog.deleteMany({ where: { companyId } });
    deleted.electronicAuthSeeds = await tx.electronicAuthSeed.deleteMany({ where: { companyId } });
    deleted.electronicDgiiTokenCaches = await tx.electronicDgiiTokenCache.deleteMany({ where: { companyId } });
    deleted.electronicInboundEndpointConfigs = await tx.electronicInboundEndpointConfig.deleteMany({ where: { companyId } });
    deleted.electronicSequences = await tx.electronicSequence.deleteMany({ where: { companyId } });
    deleted.electronicInvoices = await tx.electronicInvoice.deleteMany({ where: { companyId } });
    deleted.electronicCertificates = await tx.electronicCertificate.deleteMany({ where: { companyId } });

    deleted.cloudBackups = await tx.cloudBackup.deleteMany({ where: { companyId } });
    deleted.auditLogs = await tx.auditLog.deleteMany({ where: { companyId } });
    deleted.overrideTokens = await tx.overrideToken.deleteMany({ where: { companyId } });
    deleted.overrideRequests = await tx.overrideRequest.deleteMany({ where: { companyId } });

    deleted.returnItems = await tx.returnItem.deleteMany({ where: { return: { companyId } } });
    deleted.returns = await tx.return.deleteMany({ where: { companyId } });

    deleted.creditPayments = await tx.creditPayment.deleteMany({ where: { payment: { companyId } } });
    deleted.layawayPayments = await tx.layawayPayment.deleteMany({ where: { payment: { companyId } } });
    deleted.payments = await tx.payment.deleteMany({ where: { companyId } });

    deleted.sales = await tx.sale.deleteMany({ where: { companyId } });

    deleted.cashMovements = await tx.cashMovement.deleteMany({ where: { companyId } });
    deleted.cashSessions = await tx.cashSession.deleteMany({ where: { companyId } });
    deleted.expenses = await tx.expense.deleteMany({ where: { companyId } });
    deleted.quotes = await tx.quote.deleteMany({ where: { companyId } });

    if (options.purgeMasterData) {
      deleted.clients = await tx.client.deleteMany({ where: { companyId } });
      deleted.categories = await tx.category.deleteMany({ where: { companyId } });
      deleted.suppliers = await tx.supplier.deleteMany({ where: { companyId } });
      deleted.products = await tx.product.deleteMany({ where: { companyId } });
    }

    if (options.purgeCompanyConfig) {
      deleted.companyConfig = await tx.companyConfig.deleteMany({ where: { companyId } });
    }

    if (options.purgeTerminals) {
      deleted.terminals = await tx.terminal.deleteMany({ where: { companyId } });
    }

    if (options.purgeUsers) {
      deleted.refreshTokens = await tx.refreshToken.deleteMany({ where: { user: { companyId } } });
      deleted.integrationTokens = await tx.integrationToken.deleteMany({ where: { companyId } });
      deleted.users = await tx.user.deleteMany({ where: { companyId } });
    }

    return deleted;
  });
}

async function main() {
  const companyIdRaw = process.env.COMPANY_ID;
  const expectedTenantKey = String(process.env.EXPECTED_TENANT_KEY || '').trim().toLowerCase();
  const dryRun = parseBool(process.env.DRY_RUN, true);
  const confirm = process.env.CONFIRM_PURGE;

  if (!companyIdRaw) throw new Error('Falta COMPANY_ID.');
  if (!expectedTenantKey) throw new Error('Falta EXPECTED_TENANT_KEY. Ejecute inspect primero y copie Company.tenantKey correcto.');

  const companyId = Number(companyIdRaw);
  if (!Number.isInteger(companyId) || companyId <= 0) throw new Error(`COMPANY_ID inválido: ${companyIdRaw}`);

  const options = {
    purgeMasterData: parseBool(process.env.PURGE_MASTER_DATA),
    purgeTerminals: parseBool(process.env.PURGE_TERMINALS),
    purgeUsers: parseBool(process.env.PURGE_USERS),
    purgeCompanyConfig: parseBool(process.env.PURGE_COMPANY_CONFIG),
  };

  const company = await prisma.company.findUnique({
    where: { id: companyId },
    select: {
      id: true,
      name: true,
      rnc: true,
      normalizedRnc: true,
      cloudCompanyId: true,
      tenantKey: true,
      sourceBusinessId: true,
      primaryDeviceId: true,
      isActive: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  if (!company) throw new Error(`No existe Company con id=${companyId}`);
  if (String(company.tenantKey || '').trim().toLowerCase() !== expectedTenantKey) {
    throw new Error(`EXPECTED_TENANT_KEY no coincide. Esperado por env=${expectedTenantKey}; empresa tiene=${company.tenantKey}`);
  }

  if (!dryRun && confirm !== 'DELETE_COMPANY_DATA') {
    throw new Error('Confirmación requerida para borrado real: CONFIRM_PURGE=DELETE_COMPANY_DATA');
  }

  const before = await getCounts(companyId);
  console.log('Empresa validada:', company);
  console.log('Opciones:', { dryRun, ...options });
  console.log('Antes:', before);

  await exportBackup(company, before);

  if (dryRun) {
    console.log('DRY_RUN=true: no se borró nada. Revise el conteo y repita con DRY_RUN=false si corresponde.');
    return;
  }

  const deleted = await purgeCompanyData(companyId, options);
  console.log('Borrados:', summarizeDeleteMany(deleted));

  const after = await getCounts(companyId);
  console.log('Después:', after);
  console.log('OK. Con backend actualizado, sincronice de nuevo desde el POS correcto para recargar datos limpios.');
}

main()
  .catch((err) => {
    console.error('ERROR:', err?.message ?? err);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

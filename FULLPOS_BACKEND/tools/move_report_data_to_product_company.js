/*
  Mueve datos de reportes/ventas desde empresas duplicadas hacia la empresa
  correcta: la misma empresa donde están productos e inventario.

  Uso seguro (primero diagnóstico, no modifica):
    $env:TARGET_COMPANY_CLOUD_ID="fp-..."; node tools/move_report_data_to_product_company.js

  Aplicar cambios:
    $env:TARGET_COMPANY_CLOUD_ID="fp-..."
    $env:SOURCE_COMPANY_IDS="2,3"                  # opcional; si no se envía usa empresas con el mismo RNC
    $env:CONFIRM_MOVE_REPORT_DATA="MOVE_TO_PRODUCT_COMPANY"
    node tools/move_report_data_to_product_company.js

  También acepta TARGET_COMPANY_ID si ya conoces el ID cloud/backend correcto.
  El script aborta si encuentra conflictos de códigos/localId contra la empresa destino.
*/

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

function normalizeRnc(value) {
  return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function parseIds(value) {
  return String(value || '')
    .split(',')
    .map((item) => Number(item.trim()))
    .filter((item) => Number.isInteger(item) && item > 0);
}

async function resolveTargetCompany() {
  const targetId = Number(process.env.TARGET_COMPANY_ID || '0');
  const targetCloudId = String(process.env.TARGET_COMPANY_CLOUD_ID || '').trim();

  if (Number.isInteger(targetId) && targetId > 0) {
    return prisma.company.findUnique({
      where: { id: targetId },
      select: { id: true, name: true, rnc: true, cloudCompanyId: true },
    });
  }

  if (targetCloudId) {
    return prisma.company.findFirst({
      where: { cloudCompanyId: targetCloudId },
      select: { id: true, name: true, rnc: true, cloudCompanyId: true },
    });
  }

  throw new Error('Falta TARGET_COMPANY_ID o TARGET_COMPANY_CLOUD_ID.');
}

async function resolveSourceCompanyIds(target) {
  const explicit = parseIds(process.env.SOURCE_COMPANY_IDS);
  if (explicit.length > 0) {
    return explicit.filter((id) => id !== target.id);
  }

  const targetRnc = normalizeRnc(target.rnc);
  if (!targetRnc) {
    throw new Error('La empresa destino no tiene RNC; indica SOURCE_COMPANY_IDS manualmente.');
  }

  const companies = await prisma.company.findMany({
    where: { rnc: { not: null } },
    select: { id: true, name: true, rnc: true, cloudCompanyId: true },
    orderBy: { id: 'asc' },
  });

  return companies
    .filter((company) => company.id !== target.id && normalizeRnc(company.rnc) === targetRnc)
    .map((company) => company.id);
}

async function countCompanyData(companyId) {
  const [products, sales, payments, returnsCount, cashSessions, cashMovements, expenses, quotes, electronicInvoices] = await Promise.all([
    prisma.product.count({ where: { companyId } }),
    prisma.sale.count({ where: { companyId } }),
    prisma.payment.count({ where: { companyId } }),
    prisma.return.count({ where: { companyId } }),
    prisma.cashSession.count({ where: { companyId } }),
    prisma.cashMovement.count({ where: { companyId } }),
    prisma.expense.count({ where: { companyId } }),
    prisma.quote.count({ where: { companyId } }),
    prisma.electronicInvoice.count({ where: { companyId } }),
  ]);
  return { products, sales, payments, returns: returnsCount, cashSessions, cashMovements, expenses, quotes, electronicInvoices };
}

async function findConflicts(targetId, sourceIds) {
  const conflicts = [];

  async function checkRows(label, sql) {
    const rows = await prisma.$queryRawUnsafe(sql);
    if (rows.length > 0) conflicts.push({ label, rows });
  }

  const sourceList = sourceIds.join(',');
  await checkRows('Sale.localCode', `
    SELECT s."localCode", array_agg(DISTINCT s."companyId") AS "companyIds", COUNT(*)::int AS count
    FROM "Sale" s
    WHERE s."companyId" IN (${targetId}, ${sourceList})
    GROUP BY s."localCode"
    HAVING COUNT(DISTINCT s."companyId") > 1
    ORDER BY s."localCode"
    LIMIT 25
  `);

  await checkRows('CashSession.localId', `
    SELECT cs."localId", array_agg(DISTINCT cs."companyId") AS "companyIds", COUNT(*)::int AS count
    FROM "CashSession" cs
    WHERE cs."companyId" IN (${targetId}, ${sourceList}) AND cs."localId" IS NOT NULL
    GROUP BY cs."localId"
    HAVING COUNT(DISTINCT cs."companyId") > 1
    ORDER BY cs."localId"
    LIMIT 25
  `);

  await checkRows('CashMovement.localId', `
    SELECT cm."localId", array_agg(DISTINCT cm."companyId") AS "companyIds", COUNT(*)::int AS count
    FROM "CashMovement" cm
    WHERE cm."companyId" IN (${targetId}, ${sourceList}) AND cm."localId" IS NOT NULL
    GROUP BY cm."localId"
    HAVING COUNT(DISTINCT cm."companyId") > 1
    ORDER BY cm."localId"
    LIMIT 25
  `);

  await checkRows('Payment.kind.localId', `
    SELECT p.kind, p."localId", array_agg(DISTINCT p."companyId") AS "companyIds", COUNT(*)::int AS count
    FROM "Payment" p
    WHERE p."companyId" IN (${targetId}, ${sourceList}) AND p."localId" IS NOT NULL
    GROUP BY p.kind, p."localId"
    HAVING COUNT(DISTINCT p."companyId") > 1
    ORDER BY p.kind, p."localId"
    LIMIT 25
  `);

  await checkRows('Return.localId', `
    SELECT r."localId", array_agg(DISTINCT r."companyId") AS "companyIds", COUNT(*)::int AS count
    FROM "Return" r
    WHERE r."companyId" IN (${targetId}, ${sourceList}) AND r."localId" IS NOT NULL
    GROUP BY r."localId"
    HAVING COUNT(DISTINCT r."companyId") > 1
    ORDER BY r."localId"
    LIMIT 25
  `);

  await checkRows('Quote.localId', `
    SELECT q."localId", array_agg(DISTINCT q."companyId") AS "companyIds", COUNT(*)::int AS count
    FROM "Quote" q
    WHERE q."companyId" IN (${targetId}, ${sourceList}) AND q."localId" IS NOT NULL
    GROUP BY q."localId"
    HAVING COUNT(DISTINCT q."companyId") > 1
    ORDER BY q."localId"
    LIMIT 25
  `);

  await checkRows('ElectronicInvoice.ecf', `
    SELECT ei.ecf, array_agg(DISTINCT ei."companyId") AS "companyIds", COUNT(*)::int AS count
    FROM "ElectronicInvoice" ei
    WHERE ei."companyId" IN (${targetId}, ${sourceList})
    GROUP BY ei.ecf
    HAVING COUNT(DISTINCT ei."companyId") > 1
    ORDER BY ei.ecf
    LIMIT 25
  `);

  return conflicts;
}

async function main() {
  const target = await resolveTargetCompany();
  if (!target) throw new Error('No se encontró la empresa destino.');

  const sourceIds = await resolveSourceCompanyIds(target);
  if (sourceIds.length === 0) {
    console.log('No hay empresas origen relacionadas para mover.');
    console.log('Empresa destino:', target);
    console.log('Conteo destino:', await countCompanyData(target.id));
    return;
  }

  const sources = await prisma.company.findMany({
    where: { id: { in: sourceIds } },
    select: { id: true, name: true, rnc: true, cloudCompanyId: true },
    orderBy: { id: 'asc' },
  });

  console.log('Empresa destino (productos/inventario):', target);
  console.log('Empresas origen a corregir:', sources);
  console.log('Conteo destino antes:', await countCompanyData(target.id));
  for (const source of sources) {
    console.log(`Conteo origen antes companyId=${source.id}:`, await countCompanyData(source.id));
  }

  const conflicts = await findConflicts(target.id, sources.map((source) => source.id));
  if (conflicts.length > 0) {
    console.error('CONFLICTOS: no se puede mover automáticamente sin revisar duplicados.');
    for (const conflict of conflicts) {
      console.error(conflict.label, conflict.rows);
    }
    process.exitCode = 2;
    return;
  }

  const apply = process.env.CONFIRM_MOVE_REPORT_DATA === 'MOVE_TO_PRODUCT_COMPANY';
  if (!apply) {
    console.log('Modo diagnóstico: no se modificó nada. Para aplicar usa CONFIRM_MOVE_REPORT_DATA=MOVE_TO_PRODUCT_COMPANY.');
    return;
  }

  const sourceIdsFilter = { in: sources.map((source) => source.id) };
  const result = await prisma.$transaction(async (tx) => {
    const moved = {};
    moved.electronicInvoices = await tx.electronicInvoice.updateMany({
      where: { companyId: sourceIdsFilter },
      data: { companyId: target.id },
    });
    moved.payments = await tx.payment.updateMany({
      where: { companyId: sourceIdsFilter },
      data: { companyId: target.id },
    });
    moved.returns = await tx.return.updateMany({
      where: { companyId: sourceIdsFilter },
      data: { companyId: target.id },
    });
    moved.sales = await tx.sale.updateMany({
      where: { companyId: sourceIdsFilter },
      data: { companyId: target.id },
    });
    moved.cashMovements = await tx.cashMovement.updateMany({
      where: { companyId: sourceIdsFilter },
      data: { companyId: target.id },
    });
    moved.cashSessions = await tx.cashSession.updateMany({
      where: { companyId: sourceIdsFilter },
      data: { companyId: target.id },
    });
    moved.expenses = await tx.expense.updateMany({
      where: { companyId: sourceIdsFilter },
      data: { companyId: target.id },
    });
    moved.quotes = await tx.quote.updateMany({
      where: { companyId: sourceIdsFilter },
      data: { companyId: target.id },
    });
    return moved;
  });

  console.log('Movidos:', Object.fromEntries(Object.entries(result).map(([key, val]) => [key, val.count])));
  console.log('Conteo destino después:', await countCompanyData(target.id));
  for (const source of sources) {
    console.log(`Conteo origen después companyId=${source.id}:`, await countCompanyData(source.id));
  }
}

main()
  .catch((err) => {
    console.error('MOVE_REPORT_DATA_ERROR:', err?.message || err);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

/**
 * fix_company_tenant_key_conflict.js
 *
 * Diagnostica y corrige el conflicto COMPANY_TENANT_LOCATOR_CONFLICT
 * causado por un normalizedRnc incorrecto en la base de datos.
 *
 * Problema detectado (2026-05-03):
 *   - Company id=4 tiene normalizedRnc="1330802061" (10 dígitos, incorrecto)
 *   - El RNC real es "133080206" (9 dígitos)
 *   - El tenantKey almacenado usa "1330802061" en vez de "133080206"
 *   - La app envía tenantKey con "133080206" → 409 COMPANY_TENANT_LOCATOR_CONFLICT
 *
 * USO:
 *   node tools/fix_company_tenant_key_conflict.js          (diagnóstico solo)
 *   DRY_RUN=false node tools/fix_company_tenant_key_conflict.js   (aplica fix)
 *
 * SEGURIDAD: solo actualiza el registro con el cloudCompanyId exacto especificado.
 */

require('dotenv').config();

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

const DRY_RUN = process.env.DRY_RUN !== 'false';

// ─── Helpers ────────────────────────────────────────────────────────────────

function normalizeRnc(value) {
  if (!value) return '';
  return value.trim().toLowerCase().replace(/[^a-z0-9]/g, '');
}

function normalizeKeyPart(value) {
  if (!value) return '';
  return value.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-');
}

// Reconstruye el tenantKey a partir de las partes originales del tenantKey viejo
// reemplazando solo la parte del RNC.
function rebuildTenantKey(oldTenantKey, wrongRnc, correctRnc) {
  if (!oldTenantKey) return null;
  // Reemplazar todas las ocurrencias del RNC incorrecto por el correcto
  const fixed = oldTenantKey.replace(new RegExp(wrongRnc, 'g'), correctRnc);
  return fixed;
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  console.log('=== fix_company_tenant_key_conflict.js ===');
  console.log(`DRY_RUN=${DRY_RUN} (set DRY_RUN=false to apply changes)\n`);

  // Buscar todos los registros de empresa que tengan normalizedRnc distinto
  // del normalizeRnc(rnc), lo que indica una inconsistencia.
  const companies = await prisma.company.findMany({
    select: {
      id: true,
      name: true,
      rnc: true,
      cloudCompanyId: true,
      normalizedRnc: true,
      tenantKey: true,
      isActive: true,
    },
    orderBy: { id: 'asc' },
  });

  console.log(`Total empresas en DB: ${companies.length}`);

  const conflicted = [];

  for (const company of companies) {
    const expectedNormalizedRnc = normalizeRnc(company.rnc);
    const storedNormalizedRnc = company.normalizedRnc ?? '';

    if (expectedNormalizedRnc !== storedNormalizedRnc) {
      conflicted.push({
        company,
        expectedNormalizedRnc,
        storedNormalizedRnc,
      });
    }
  }

  if (conflicted.length === 0) {
    console.log('✓ No se encontraron inconsistencias en normalizedRnc.');
    // Aún así mostrar todos los registros para diagnóstico
    console.log('\n=== Estado actual de empresas ===');
    console.table(companies.map(c => ({
      id: c.id,
      name: c.name,
      rnc: c.rnc ?? '',
      cloudCompanyId: c.cloudCompanyId ?? '',
      normalizedRnc: c.normalizedRnc ?? '',
      tenantKey: c.tenantKey ?? '',
    })));
    return;
  }

  console.log(`\n⚠ Se encontraron ${conflicted.length} empresa(s) con normalizedRnc incorrecto:\n`);

  for (const { company, expectedNormalizedRnc, storedNormalizedRnc } of conflicted) {
    console.log(`  Company id=${company.id} name="${company.name}"`);
    console.log(`    rnc=${company.rnc ?? 'null'}`);
    console.log(`    cloudCompanyId=${company.cloudCompanyId ?? 'null'}`);
    console.log(`    normalizedRnc actual   = "${storedNormalizedRnc}"`);
    console.log(`    normalizedRnc esperado = "${expectedNormalizedRnc}"`);
    console.log(`    tenantKey actual       = "${company.tenantKey ?? 'null'}"`);

    if (!DRY_RUN) {
      const newNormalizedRnc = expectedNormalizedRnc;
      const newTenantKey = rebuildTenantKey(
        company.tenantKey,
        storedNormalizedRnc,
        newNormalizedRnc,
      );

      console.log(`    tenantKey nuevo        = "${newTenantKey ?? 'null'}"`);
      console.log(`    → Aplicando corrección...`);

      await prisma.company.update({
        where: { id: company.id },
        data: {
          normalizedRnc: newNormalizedRnc || null,
          ...(newTenantKey ? { tenantKey: newTenantKey } : {}),
        },
      });

      // Verificar que quedó bien
      const updated = await prisma.company.findUnique({
        where: { id: company.id },
        select: { id: true, normalizedRnc: true, tenantKey: true },
      });
      console.log(`    ✓ Actualizado: normalizedRnc="${updated?.normalizedRnc}" tenantKey="${updated?.tenantKey}"`);
    } else {
      const newTenantKey = rebuildTenantKey(
        company.tenantKey,
        storedNormalizedRnc,
        expectedNormalizedRnc,
      );
      console.log(`    tenantKey nuevo (preview) = "${newTenantKey ?? 'null'}"`);
      console.log(`    → DRY_RUN: no se aplican cambios.`);
    }
    console.log('');
  }

  if (DRY_RUN) {
    console.log('Para aplicar los cambios ejecuta:');
    console.log('  DRY_RUN=false node tools/fix_company_tenant_key_conflict.js');
  } else {
    console.log('✓ Correcciones aplicadas. La sincronización debería funcionar en el próximo intento.');
  }
}

main()
  .catch((err) => {
    console.error('ERROR:', err?.message ?? String(err));
    if (err?.stack) console.error(err.stack);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function main() {
  const rows = await prisma.$queryRawUnsafe(
    'SELECT migration_name, finished_at, rolled_back_at, checksum FROM "_prisma_migrations" ORDER BY started_at',
  );
  console.table(rows);
}

main()
  .catch((e) => {
    console.error(e);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

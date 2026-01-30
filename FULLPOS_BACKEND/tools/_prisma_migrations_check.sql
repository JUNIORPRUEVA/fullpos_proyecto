SELECT migration_name, finished_at, rolled_back_at, checksum
FROM "_prisma_migrations"
ORDER BY started_at;

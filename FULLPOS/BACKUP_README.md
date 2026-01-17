# Backups (LOS NILKAS POS)

## Qué se respalda
- Base de datos SQLite: `los_nilkas_pos.db` (o el nombre actual de `AppDb.dbFileName`)
- Archivos opcionales (si existen en Documents de la app):
  - `product_images/`

El backup se guarda como **ZIP** con esta estructura:
- `db/<dbFileName>`
- `files/<carpeta>/...` (opcional)
- `meta/backup.json` (metadata)

## Dónde se guardan
- Windows/macOS/Linux: `Documents/LOS_NILKAS_POS_BACKUPS/`
- Android: `getApplicationDocumentsDirectory()/LOS_NILKAS_POS_BACKUPS/`

## Cómo crear backup (manual)
- Ir a **Configuración → BACKUP**
- Usar **Crear backup ahora**

## Backup automático
- Windows: al cerrar la ventana (hook con `window_manager`).
- Android: cuando la app pasa a `paused`/`detached` (mejor esfuerzo).

## Cómo restaurar
- Ir a **Configuración → BACKUP**
- **Restaurar backup** o **Restaurar** desde la lista
- Confirmar (reemplaza datos)
- Recomendación: reiniciar la app después del restore

El restore hace un safety backup del DB actual:
- `Documents/LOS_NILKAS_POS_BACKUPS/backup_before_restore_<timestamp>.db`

## Retención
- Configurable desde la pantalla de Backups.
- Se conservan los últimos N ZIP y se borran los más viejos.

## Verificación
- En creación:
  - valida existencia y tamaño del ZIP
  - `PRAGMA integrity_check` es opcional (en auto-backup está desactivado)

## Cómo probar rápido
1. Abrir app y crear un backup manual.
2. Verificar que exista el ZIP en la carpeta indicada y que contenga `meta/backup.json` y `db/...`.
3. Crear 3 backups con retención 2 → deben quedar 2 ZIP.
4. Restaurar un backup y reiniciar la app.


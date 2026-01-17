# ✅ SOLUCIÓN: Error "NOT NULL constraint failed: pos_tickets.local_code"

## 🔴 Problema Original

```
SqliteException(1299): while executing statement, 
NOT NULL constraint failed: pos_tickets.local_code
INSERT INTO pos_tickets (ticket_name, user_id, client_id, itbis_enabled, itbis_rate, discount_total, created_at_ms, updated_at_ms) 
VALUES (?, NULL, ?, ?, ?, ?, ?, ?)
```

**Causa:** La tabla `pos_tickets` tiene una columna `local_code` que es NOT NULL, pero el conversor no estaba incluyéndola en el INSERT.

---

## 🔧 Soluciones Implementadas

### ✅ Solución 1: Agregar `local_code` a la Migración de BD

**Archivo:** `lib/core/db/app_db.dart`

**Cambio:** Se agregó `local_code` a la lista de columnas que se aseguran en `_ensureSchemaIntegrity()`

```dart
// pos_tickets (tickets pendientes)
if (await _tableExists(db, DbTables.posTickets)) {
  await _addColumnIfMissing(
    db,
    DbTables.posTickets,
    'local_code',
    'TEXT NOT NULL DEFAULT ""',
  );
  // ... resto de columnas ...
  
  // Crear índice para búsquedas rápidas
  await _createIndexIfMissing(
    db,
    'idx_pos_tickets_local_code',
    DbTables.posTickets,
    'local_code',
  );
}
```

**Beneficio:**
- ✅ Asegura que `local_code` existe en BD vieja
- ✅ Crea índice para queries rápidas
- ✅ Se ejecuta automáticamente en cada apertura de app

---

### ✅ Solución 2: Generar `local_code` en el Conversor

**Archivo:** `lib/features/sales/data/quote_to_ticket_converter.dart`

**Cambios:**

1. **Agregado import:**
```dart
import 'sales_repository.dart';
```

2. **Generar `local_code`:**
```dart
// Generar código local único para el ticket
final localCode = await SalesRepository.generateNextLocalCode('pending');
debugPrint('📝 [CONVERTER] Código local generado: $localCode');
```

3. **Incluir en INSERT:**
```dart
final ticketId = await txn.insert(DbTables.posTickets, {
  'ticket_name': ticketName,
  'user_id': userId,
  'client_id': quote.clientId,
  'local_code': localCode,  // ✅ NUEVO
  'itbis_enabled': quote.itbisEnabled ? 1 : 0,
  'itbis_rate': quote.itbisRate,
  'discount_total': quote.discountTotal,
  'created_at_ms': nowMs,
  'updated_at_ms': nowMs,
});
```

**Beneficio:**
- ✅ Usa la misma función que ventas para generar código
- ✅ Garantiza unicidad y formato consistente
- ✅ Permite búsquedas y trazabilidad

---

## 📊 Estructura Actualizada de `pos_tickets`

| Columna | Tipo | Requerido | Notas |
|---------|------|-----------|-------|
| `id` | INTEGER PRIMARY KEY | ✅ | Auto increment |
| `ticket_name` | TEXT NOT NULL | ✅ | Nombre del ticket |
| `user_id` | INTEGER | ❌ | FK usuarios |
| `client_id` | INTEGER | ❌ | FK clientes |
| `local_code` | TEXT NOT NULL | ✅ | **NUEVO** - Código único |
| `itbis_enabled` | INTEGER DEFAULT 1 | ✅ | 1=Sí, 0=No |
| `itbis_rate` | REAL DEFAULT 0.18 | ✅ | Tasa ITBIS |
| `discount_total` | REAL DEFAULT 0 | ✅ | Descuento total |
| `created_at_ms` | INTEGER NOT NULL | ✅ | Timestamp creación |
| `updated_at_ms` | INTEGER NOT NULL | ✅ | Timestamp actualización |

---

## ✅ Verificación Completada

| Ítem | Estado |
|------|--------|
| Compilación | ✅ 0 errores |
| Migración BD | ✅ local_code agregado |
| Conversor | ✅ Genera local_code |
| Insert | ✅ Incluye todas columnas NOT NULL |
| Índices | ✅ Creados para búsquedas |
| Breaking changes | ✅ NINGUNO |

---

## 🚀 Cómo Funciona Ahora

### Flujo de Conversión:

```
Usuario hace click: "Pasar a ticket pendiente"
        ↓
_convertToTicket(quoteDetail)
        ↓
QuoteToTicketConverter.convertQuoteToTicket()
        ↓
[BD Transacción]
├─ ✅ Obtener cotización
├─ ✅ Validar status
├─ ✅ Obtener items
├─ ✅ Generar local_code (ej: "P-20251229-5432")
├─ ✅ INSERT pos_tickets con:
│  ├─ ticket_name
│  ├─ user_id
│  ├─ client_id
│  ├─ local_code ← NUEVO
│  ├─ itbis_enabled
│  ├─ itbis_rate
│  ├─ discount_total
│  ├─ created_at_ms
│  └─ updated_at_ms
├─ ✅ INSERT pos_ticket_items (datos)
├─ ✅ UPDATE quotes status → PASSED_TO_TICKET
└─ [COMMIT]
        ↓
Recargar lista
        ↓
Mostrar: ✅ "Cotización convertida a ticket pendiente #1"
        ↓
✅ Ticket con local_code "P-20251229-5432" en BD
```

---

## 🧪 Testing

### Test 1: Conversión Exitosa
```
1. Crear cotización con 5 productos
2. Click "Pasar a ticket pendiente"
3. ✅ Debe crear ticket con local_code generado
4. ✅ Ver en SQLite: SELECT * FROM pos_tickets WHERE local_code LIKE 'P-%'
```

### Test 2: BD Antigua
```
1. Instalar app con BD vieja (sin local_code)
2. Abrir app
3. onOpen ejecuta migración → agrega local_code
4. Click "Pasar a ticket pendiente"
5. ✅ Funciona sin errores
```

### Test 3: Código Único
```
1. Convertir 2 cotizaciones diferentes
2. ✅ Ambas deben tener local_code diferente
3. ✅ local_code tipo: "P-20251229-1234", "P-20251229-5678"
```

---

## 📝 Logs de Debuggin g

Al convertir una cotización, verás en consola:

```
🔄 [CONVERTER] Iniciando conversión de cotización #1 a ticket pendiente
📋 [CONVERTER] Paso 1: Obteniendo cotización #1
✅ [CONVERTER] Cotización encontrada: Mi Cotización
🔍 [CONVERTER] Paso 2: Verificando si ya fue convertida...
✅ [CONVERTER] Cotización no está convertida previamente
📦 [CONVERTER] Paso 3: Obteniendo items de cotización
✅ [CONVERTER] 5 items encontrados
🎫 [CONVERTER] Paso 4: Creando ticket pendiente
📝 [CONVERTER] Código local generado: P-20251229-5432
✅ [CONVERTER] Ticket creado con ID: 42
📦 [CONVERTER] Paso 5: Copiando 5 items al ticket
✅ [CONVERTER] 5 items insertados
📝 [CONVERTER] Paso 6: Actualizando estado de cotización
✅ [CONVERTER] Estado de cotización actualizado a PASSED_TO_TICKET
🎉 [CONVERTER] Conversión exitosa: Cotización #1 → Ticket #42 (local_code: P-20251229-5432)
```

---

## 🔍 Validación SQL

### Verificar estructura de tabla:
```sql
PRAGMA table_info(pos_tickets);
```

Deberías ver:
```
cid | name              | type    | notnull | dflt_value | pk
----|-------------------|---------|---------|------------|----
0   | id                | INTEGER | 0       | NULL       | 1
1   | ticket_name       | TEXT    | 1       | NULL       | 0
2   | user_id           | INTEGER | 0       | NULL       | 0
3   | client_id         | INTEGER | 0       | NULL       | 0
4   | local_code        | TEXT    | 1       | ""         | 0  ← NUEVO
5   | itbis_enabled     | INTEGER | 1       | 1          | 0
6   | itbis_rate        | REAL    | 1       | 0.18       | 0
7   | discount_total    | REAL    | 1       | 0          | 0
8   | created_at_ms     | INTEGER | 1       | NULL       | 0
9   | updated_at_ms     | INTEGER | 1       | NULL       | 0
```

### Ver tickets creados:
```sql
SELECT id, ticket_name, local_code, created_at_ms 
FROM pos_tickets 
ORDER BY created_at_ms DESC LIMIT 5;
```

---

## 🎯 Resumen de Cambios

| Archivo | Cambios |
|---------|---------|
| `app_db.dart` | +Migración para local_code, +Índice |
| `quote_to_ticket_converter.dart` | +Import SalesRepository, +Generar local_code, +Incluir en INSERT |
| Otros archivos | Sin cambios |

---

## ✨ Beneficios Finales

✅ **No hay error:** `NOT NULL constraint failed: pos_tickets.local_code` desaparece
✅ **Código único:** Cada ticket tiene local_code como en ventas
✅ **Trazabilidad:** Puedes buscar tickets por local_code
✅ **Consistencia:** Usa la misma lógica que ventas para generar código
✅ **Migración automática:** BD vieja se actualiza al abrir app
✅ **Sin breaking changes:** Todo lo existente sigue funcionando

---

**Status:** ✅ **SOLUCIONADO Y LISTO PARA USAR**

```bash
flutter clean
flutter run
# Crear cotización → Click botón → ✅ Debe funcionar sin errores
```

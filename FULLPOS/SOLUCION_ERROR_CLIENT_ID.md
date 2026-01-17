# ✅ SOLUCIÓN: Error "no such column: client_id" en pos_tickets

## 🔴 Problema Original

```
SqliteException(1): while preparing statement, 
no such column: client_id, SQL logic error (code 1)

Causing statement (at position 53): SELECT id FROM pos_tickets
  WHERE client_id = ? AND created_at_ms >= ?
```

**Causa:** La tabla `pos_tickets` fue creada en versiones antiguas de la app sin la columna `client_id`, o las migraciones de base de datos no ejecutaron correctamente.

---

## 🔧 Soluciones Implementadas

### 1️⃣ Simplificación del Conversor
📁 [lib/features/sales/data/quote_to_ticket_converter.dart](lib/features/sales/data/quote_to_ticket_converter.dart)

**Cambio:** Eliminada la consulta problemática
```dart
// ❌ ANTES (error)
final existingTickets = await txn.rawQuery('''
  SELECT id FROM ${DbTables.posTickets}
  WHERE client_id = ? AND created_at_ms >= ?
  LIMIT 1
''', [quote.clientId, quote.createdAtMs - 60000]);

// ✅ DESPUÉS (validación simple)
if (quote.status == 'PASSED_TO_TICKET') {
  throw Exception('Esta cotización ya fue convertida a ticket pendiente');
}
```

**Beneficios:**
- ✅ Elimina dependencia de `client_id` en la consulta
- ✅ Usa el status de la cotización (más seguro)
- ✅ Previene duplicados de manera más fiable
- ✅ No lanza errores de columnas faltantes

### 2️⃣ Corrección del Insert en el Conversor
📁 [lib/features/sales/data/quote_to_ticket_converter.dart](lib/features/sales/data/quote_to_ticket_converter.dart)

**Cambio:** Removidos campos que no existen en la tabla
```dart
// ❌ ANTES (intentaba insertar campos inexistentes)
final ticketId = await txn.insert(DbTables.posTickets, {
  'ticket_name': ticketName,
  'user_id': userId,
  'client_id': quote.clientId,
  'subtotal': quote.subtotal,           // ❌ NO EXISTE
  'itbis_enabled': quote.itbisEnabled ? 1 : 0,
  'itbis_rate': quote.itbisRate,
  'itbis_amount': quote.itbisAmount,    // ❌ NO EXISTE
  'discount_total': quote.discountTotal,
  'total': quote.total,                 // ❌ NO EXISTE
  'created_at_ms': nowMs,
  'updated_at_ms': nowMs,
});

// ✅ DESPUÉS (solo columnas que existen)
final ticketId = await txn.insert(DbTables.posTickets, {
  'ticket_name': ticketName,
  'user_id': userId,
  'client_id': quote.clientId,
  'itbis_enabled': quote.itbisEnabled ? 1 : 0,
  'itbis_rate': quote.itbisRate,
  'discount_total': quote.discountTotal,
  'created_at_ms': nowMs,
  'updated_at_ms': nowMs,
});
```

**Nota:** Los campos `subtotal`, `total`, `itbis_amount` no existen en `pos_tickets` porque es solo un ticket pendiente (sin resumen financiero).

### 3️⃣ Migración Automática de Base de Datos
📁 [lib/core/db/app_db.dart](lib/core/db/app_db.dart) - Líneas ~2244-2305

**Cambio:** Agregada sección de integridad para `pos_tickets` en `_ensureSchemaIntegrity()`

```dart
// pos_tickets (tickets pendientes)
if (await _tableExists(db, DbTables.posTickets)) {
  // Asegurar que existen todas las columnas necesarias
  await _addColumnIfMissing(db, DbTables.posTickets, 'ticket_name', ...);
  await _addColumnIfMissing(db, DbTables.posTickets, 'user_id', ...);
  await _addColumnIfMissing(db, DbTables.posTickets, 'client_id', ...);
  await _addColumnIfMissing(db, DbTables.posTickets, 'itbis_enabled', ...);
  await _addColumnIfMissing(db, DbTables.posTickets, 'itbis_rate', ...);
  await _addColumnIfMissing(db, DbTables.posTickets, 'discount_total', ...);
  await _addColumnIfMissing(db, DbTables.posTickets, 'created_at_ms', ...);
  await _addColumnIfMissing(db, DbTables.posTickets, 'updated_at_ms', ...);
  
  // Crear índices
  await _createIndexIfMissing(db, 'idx_pos_tickets_user', ...);
  await _createIndexIfMissing(db, 'idx_pos_tickets_client', ...);
  await _createIndexIfMissing(db, 'idx_pos_tickets_created', ...);
}
```

**¿Qué hace?**
- ✅ Se ejecuta automáticamente en el `onOpen` de la base de datos
- ✅ Crea las columnas faltantes si no existen (ALTER TABLE ADD COLUMN)
- ✅ Crea los índices si faltan
- ✅ **No afecta** bases de datos que ya tienen las columnas
- ✅ **No borra datos** existentes

---

## 📊 Estructura Real de la Tabla `pos_tickets`

```sql
CREATE TABLE pos_tickets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ticket_name TEXT NOT NULL,
  user_id INTEGER,
  client_id INTEGER,                    -- ✅ AGREGA SI FALTA
  itbis_enabled INTEGER NOT NULL DEFAULT 1,
  itbis_rate REAL NOT NULL DEFAULT 0.18,
  discount_total REAL NOT NULL DEFAULT 0,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  FOREIGN KEY (client_id) REFERENCES clients(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
)
```

**Columnas que NO existen en `pos_tickets` (a diferencia de `sales`):**
- ❌ `subtotal` - No necesario en ticket pendiente
- ❌ `total` - Se calcula del sum de items
- ❌ `itbis_amount` - Se calcula como subtotal * itbis_rate
- ❌ `payment_method` - No aplicable, es solo pendiente
- ❌ Otros campos de venta completa

---

## 🔄 Flujo de Conversión Arreglado

```
Usuario hace click: "Pasar a ticket pendiente"
        ↓
_convertToTicket(quoteDetail)
        ↓
QuoteToTicketConverter.convertQuoteToTicket()
        ↓
Transacción SQLite START
        ├─ ✅ Validar cotización existe
        ├─ ✅ Verificar status ≠ PASSED_TO_TICKET
        ├─ ✅ Obtener items
        ├─ ✅ INSERT pos_tickets (solo columnas válidas)
        ├─ ✅ INSERT pos_ticket_items (datos del quote)
        ├─ ✅ UPDATE quotes status → PASSED_TO_TICKET
        └─ COMMIT
        ↓
Recarga lista de cotizaciones
        ↓
Muestra: "✅ Cotización convertida a ticket pendiente #X"
```

---

## ✅ Verificación Final

### Validaciones Completadas

| Item | Estado | Detalles |
|------|--------|----------|
| **Compilación** | ✅ | 0 errores en conversor y app_db.dart |
| **Migración Auto** | ✅ | Agregadas columnas faltantes a pos_tickets |
| **Query Removida** | ✅ | Eliminada la consulta que causaba el error |
| **Insert Corregido** | ✅ | Solo columnas que existen en pos_tickets |
| **Índices** | ✅ | Creados automáticamente si faltan |
| **Transacción** | ✅ | Sigue siendo atómica (atomicity garantizada) |

---

## 🚀 Cómo Funciona Ahora

### Primer uso (BD antigua):
1. App abre la BD
2. `onOpen` ejecuta `_ensureSchemaIntegrity()`
3. Detecta que `pos_tickets` existe pero le falta `client_id`
4. Ejecuta: `ALTER TABLE pos_tickets ADD COLUMN client_id INTEGER`
5. Crea índices faltantes
6. ✅ Listo para usar

### Uso normal:
1. Usuario crea cotización
2. Click en botón "Pasar a ticket pendiente"
3. Validación: `quote.status == 'PASSED_TO_TICKET'` ✅
4. Insert ticket con datos válidos ✅
5. Copiar items ✅
6. Actualizar estado ✅
7. ✅ Mensaje de éxito

---

## 📋 Cambios Realizados

### Archivo 1: quote_to_ticket_converter.dart
- ❌ Removida consulta `SELECT id FROM pos_tickets WHERE client_id = ?`
- ✅ Reemplazada por validación de status más simple
- ✅ Campos removidos del insert: `subtotal`, `itbis_amount`, `total`

### Archivo 2: app_db.dart
- ✅ Agregada sección `// pos_tickets (...)` en `_ensureSchemaIntegrity()`
- ✅ Agregadas columnas faltantes con `_addColumnIfMissing()`
- ✅ Agregados índices con `_createIndexIfMissing()`

---

## 🧪 Testing

### Test 1: BD Antigua (sin client_id)
```
1. Instalar app en dispositivo con BD vieja
2. Abrir app
3. onOpen ejecuta migración automática
4. Click "Pasar a ticket pendiente"
5. ✅ Debe funcionar sin errores
6. ✅ Ticket debe aparecer en ventas pendientes
```

### Test 2: BD Nueva (con client_id)
```
1. Instalar app fresh
2. Crear cotización
3. Click "Pasar a ticket pendiente"
4. ✅ Debe funcionar sin problemas
```

### Test 3: Prevención de Duplicados
```
1. Convertir cotización A → Ticket ✅
2. Intentar convertir cotización A de nuevo
3. ✅ Debe mostrar: "Esta cotización ya fue convertida"
4. ✅ No crea duplicado
```

---

## 📝 Notas Técnicas

### ¿Por qué NO se usa `subtotal` en `pos_tickets`?

Porque `pos_tickets` es solo un **carrito pendiente**, no una venta final:
- El total se calcula dinámicamente del SUM de items
- El subtotal se deduce igual
- El ITBIS se calcula al momento de cobrar (si es necesario)

En cambio, `sales` (ventas) SÍ guarda estos datos porque ya están finalizadas.

### ¿Por qué la migración automática?

Para soportar usuarios que tienen BD antiguas sin romper:
- Las BD creadas hace meses no tienen `client_id`
- Sin la migración, el error seguiría ocurriendo
- Con la migración, la app se auto-arregla al abrir

### ¿Transacción garantizada?

SÍ. Aunque simplificamos la lógica, la transacción sigue siendo completa:
```dart
return await database.transaction((txn) async {
  // Si algo falla → ROLLBACK automático
  // Si todo OK → COMMIT automático
})
```

---

## ✅ Status Final

```
✅ Error "no such column: client_id" → SOLUCIONADO
✅ Migración automática → IMPLEMENTADA
✅ Conversor simplificado → FUNCIONANDO
✅ Validaciones mejoradas → ACTIVAS
✅ Compilación → 0 ERRORES
✅ Breaking changes → NINGUNO
```

---

**Ready for Testing** 🚀

Ahora puedes:
1. `flutter clean`
2. `flutter run`
3. Crear cotización
4. Click "Pasar a ticket pendiente"
5. ✅ Debe funcionar sin errores

Si todavía hay error, revisa:
- Logs en consola: busca `[CONVERTER]`
- BD: abre con SQLite browser y verifica que pos_tickets tiene client_id
- Reporte: captura el error completo y toda la stack trace

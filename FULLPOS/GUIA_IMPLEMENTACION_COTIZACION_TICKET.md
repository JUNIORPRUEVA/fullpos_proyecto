# 📋 GUÍA DE IMPLEMENTACIÓN: Convertir Cotización → Ticket Pendiente (COMPLETO)

## Objetivo
Permitir que el usuario pueda convertir una cotización en un ticket pendiente que aparecerá en el módulo de ventas.

---

## ✅ Estado Actual

### Implementación: 100% COMPLETADA

```
✅ Schema de BD actualizado (product_code_snapshot + product_name_snapshot)
✅ Migración automática en _ensureSchemaIntegrity()
✅ Modelo PosTicketItemModel actualizado
✅ TicketsRepository actualizado
✅ QuoteToTicketConverter implementado
✅ Botón en UI agregado
✅ Callback en quotes_page.dart agregado
✅ 0 errores de compilación (warnings ignorables)
```

---

## 🚀 Flujo Operativo

### 1. Usuario Crea Cotización
- Va a: Módulo Cotizaciones
- Crea nueva cotización
- Agrega 1 o más productos
- Guarda la cotización

### 2. Usuario Convierte a Ticket
- Ve lista de cotizaciones
- Hace clic en botón naranja "Pasar a ticket pendiente" (ícono: Icons.receipt_long)
- La app valida que la cotización no haya sido convertida previamente
- Se abre transacción en BD

### 3. Proceso de Conversión (Transaccional)
**Paso 1**: Obtiene cotización completa desde BD  
**Paso 2**: Verifica que no fue convertida previamente  
**Paso 3**: Obtiene todos los items de la cotización  
**Paso 4**: Crea nuevo ticket pendiente en pos_tickets con:
- ticket_name (nombre de la cotización)
- user_id (usuario actual)
- client_id (cliente de la cotización)
- local_code (generado automáticamente)
- itbis_enabled, itbis_rate, discount_total (copiados)
- timestamps (createdAtMs, updatedAtMs)

**Paso 5**: Copia cada item de cotización al ticket:
```dart
// Por cada item de cotización:
INSERT INTO pos_ticket_items (
  ticket_id,                  // ID del ticket creado
  product_id,                 // ID del producto
  product_code_snapshot,      // Código del producto (o PROD-{id})
  product_name_snapshot,      // Nombre del producto
  description,                // Descripción del item
  qty,                        // Cantidad exacta
  price,                      // Precio unitario
  cost,                       // Costo (si está disponible)
  discount_line,              // Descuento por línea
  total_line                  // Total de la línea
)
```

**Paso 6**: Actualiza estado de cotización a 'PASSED_TO_TICKET'  
**Paso 7**: Retorna ID del ticket creado

### 4. Post-Conversión
- ✅ Recarga lista de cotizaciones
- ✅ Muestra SnackBar: "✅ Cotización convertida a ticket pendiente #42"
- ✅ Ticket aparece automáticamente en Ventas → Tickets Pendientes
- ✅ Cajero puede cobrar el ticket sin errores

---

## 📊 Mapeo de Datos

| Origen (Cotización) | Destino (Ticket) | Tipo |
|-------------------|-----------------|------|
| `quote.id` | - (para referencia) | - |
| `quote.clientId` | `pos_tickets.client_id` | INTEGER |
| `quote.userId` | `pos_tickets.user_id` | INTEGER |
| `quote.ticketName` | `pos_tickets.ticket_name` | TEXT |
| `quote.itbisEnabled` | `pos_tickets.itbis_enabled` | BOOLEAN (1/0) |
| `quote.itbisRate` | `pos_tickets.itbis_rate` | REAL |
| `quote.discountTotal` | `pos_tickets.discount_total` | REAL |
| `quote.status` | → 'PASSED_TO_TICKET' | TEXT |
| ↓ | | |
| **Item de Cotización** | **Item de Ticket** | **Tipo** |
| `item.productId` | `pos_ticket_items.product_id` | INTEGER |
| `item.productCode` | `pos_ticket_items.product_code_snapshot` | TEXT |
| `item.productName` | `pos_ticket_items.product_name_snapshot` | TEXT |
| `item.description` | `pos_ticket_items.description` | TEXT |
| `item.qty` | `pos_ticket_items.qty` | REAL |
| `item.price` | `pos_ticket_items.price` | REAL |
| `item.cost` | `pos_ticket_items.cost` | REAL |
| `item.discountLine` | `pos_ticket_items.discount_line` | REAL |
| `item.totalLine` | `pos_ticket_items.total_line` | REAL |

---

## 🔧 Componentes Implementados

### 1. **Widget: Botón en Quote Row**
📁 `lib/features/sales/ui/widgets/compact_quote_row.dart`

```dart
// Constructor:
final VoidCallback? onConvertToTicket;

// Botón:
ElevatedButton(
  onPressed: onConvertToTicket,
  style: ElevatedButton.styleFrom(
    backgroundColor: Colors.orange,
  ),
  child: Tooltip(
    message: 'Pasar a ticket pendiente',
    child: Icon(Icons.receipt_long),
  ),
)
```

### 2. **Page: Quotes Page**
📁 `lib/features/sales/ui/quotes_page.dart`

```dart
// Callback en constructor:
onConvertToTicket: () => _convertToTicket(quoteDetail),

// Método _convertToTicket():
Future<void> _convertToTicket(QuoteDetailDto quote) async {
  final ticketId = await QuoteToTicketConverter.convertQuoteToTicket(
    quoteId: quote.quote.id!,
    userId: quote.quote.userId,
  );
  
  await _loadQuotes(); // Recarga ANTES del SnackBar
  
  if (!mounted) return;
  
  ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(
      content: Text('✅ Cotización convertida a ticket #$ticketId'),
      backgroundColor: Colors.green,
    ),
  );
}
```

### 3. **Converter: Quote to Ticket**
📁 `lib/features/sales/data/quote_to_ticket_converter.dart`

```dart
static Future<int> convertQuoteToTicket({
  required int quoteId,
  required int? userId,
}) async {
  // 6 pasos transaccionales:
  // 1. Obtener cotización
  // 2. Validar no convertida
  // 3. Obtener items
  // 4. Crear ticket
  // 5. Copiar items (con product_code_snapshot + product_name_snapshot)
  // 6. Actualizar estado
  
  return ticketId;
}
```

### 4. **Modelo: Ticket Item**
📁 `lib/features/sales/data/ticket_model.dart`

```dart
class PosTicketItemModel {
  final int? id;
  final int? ticketId;
  final int? productId;
  final String productCodeSnapshot;    // ← NUEVO
  final String productNameSnapshot;    // ← NUEVO
  final String description;
  final double qty;
  final double price;
  final double cost;
  final double discountLine;
  final double totalLine;
  
  // toMap() incluye ambas snapshots
  // fromMap() extrae ambas snapshots
}
```

### 5. **Repository: Tickets**
📁 `lib/features/sales/data/tickets_repository.dart`

```dart
// saveTicket() y updateTicket() incluyen en INSERT:
'product_code_snapshot': item.productCodeSnapshot,
'product_name_snapshot': item.productNameSnapshot,
```

### 6. **Base de Datos**
📁 `lib/core/db/app_db.dart`

```sql
CREATE TABLE pos_ticket_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ticket_id INTEGER NOT NULL,
  product_id INTEGER,
  product_code_snapshot TEXT NOT NULL,      ← NUEVO
  product_name_snapshot TEXT NOT NULL,      ← NUEVO
  description TEXT NOT NULL,
  qty REAL NOT NULL,
  price REAL NOT NULL,
  cost REAL NOT NULL DEFAULT 0,
  discount_line REAL NOT NULL DEFAULT 0,
  total_line REAL NOT NULL,
  ...
)

-- Migración automática en _ensureSchemaIntegrity():
await _addColumnIfMissing(db, DbTables.posTicketItems, 'product_code_snapshot', 'TEXT NOT NULL DEFAULT ""');
await _addColumnIfMissing(db, DbTables.posTicketItems, 'product_name_snapshot', 'TEXT NOT NULL DEFAULT ""');
```

---

## 🧪 Testing

### Test 1: Conversión Básica
```
1. Crear cotización "Cotización Test" con 2 productos
2. Click "Pasar a ticket pendiente"
3. Verificar: ✅ SnackBar verde aparece
4. Verificar: ✅ Ticket aparece en Ventas → Tickets Pendientes
5. Verificar: ✅ Código y nombre están guardados
```

### Test 2: Validación de Duplicados
```
1. Intentar convertir misma cotización 2 veces
2. Primera vez: ✅ FUNCIONA
3. Segunda vez: ❌ MENSAJE "Ya fue convertida"
```

### Test 3: Con Cliente y Descuentos
```
1. Crear cotización CON cliente asignado
2. CON descuento total
3. CON múltiples items
4. Click "Pasar a ticket pendiente"
5. Verificar: Ticket en ventas tiene:
   - Cliente correcto
   - Descuento aplicado
   - Todos los items
```

### Test 4: Venta Completa
```
1. Convertir cotización a ticket
2. Ir a Módulo Ventas
3. Abrir ticket pendiente
4. Cobrar ticket completo
5. Verificar: ✅ Venta registrada sin errores
```

---

## 🔍 Validaciones Implementadas

```dart
// 1. Validar cotización existe
if (quoteResults.isEmpty) throw Exception('Cotización no encontrada');

// 2. Validar no fue convertida previamente
if (quote.status == 'PASSED_TO_TICKET') throw Exception('Ya fue convertida');

// 3. Validar items existen
if (items.isEmpty) debugPrint('⚠️ ADVERTENCIA: Sin items en cotización');

// 4. Fallback para código del producto
final codeSnapshot = item.productCode?.isNotEmpty == true 
    ? item.productCode! 
    : 'PROD-${item.productId}';

// 5. Fallback para nombre del producto
final nameSnapshot = item.productName.isNotEmpty 
    ? item.productName 
    : 'Producto Desconocido';

// 6. Try/catch en UI
try {
  final ticketId = await QuoteToTicketConverter.convertQuoteToTicket(...);
  // Éxito
} catch (e) {
  // Mostrar error en SnackBar
}
```

---

## 📝 Logs Esperados

```
🔄 [CONVERTER] Iniciando conversión de cotización #1 a ticket pendiente
📋 [CONVERTER] Paso 1: Obteniendo cotización #1
✅ [CONVERTER] Cotización encontrada: Cotización Test
🔍 [CONVERTER] Paso 2: Verificando si ya fue convertida...
✅ [CONVERTER] Cotización no está convertida previamente
📦 [CONVERTER] Paso 3: Obteniendo items de cotización
✅ [CONVERTER] 2 items encontrados
🎫 [CONVERTER] Paso 4: Creando ticket pendiente
📝 [CONVERTER] Código local generado: P-20251229-5432
✅ [CONVERTER] Ticket creado con ID: 42
📦 [CONVERTER] Paso 5: Copiando 2 items al ticket
  → Item: CODE-001 | Producto A | qty=5.0
  → Item: CODE-002 | Producto B | qty=3.0
✅ [CONVERTER] 2 items insertados
📝 [CONVERTER] Paso 6: Actualizando estado de cotización
✅ [CONVERTER] Estado actualizado a PASSED_TO_TICKET
🎉 [CONVERTER] Conversión exitosa: Cotización #1 → Ticket #42
```

---

## ⚠️ Manejo de Errores

### Errores Posibles

| Error | Causa | Solución |
|-------|-------|----------|
| Cotización no encontrada | ID inválido | Recargar lista y reintentar |
| Ya fue convertida | Status == PASSED_TO_TICKET | Mostrar mensaje al usuario |
| SQLite constraint | Falta product_code_snapshot | Ejecutar migración (automática) |
| No hay items | Cotización vacía | Permitir pero advertir |

### Manejo en Código

```dart
try {
  final ticketId = await QuoteToTicketConverter.convertQuoteToTicket(...);
  await _loadQuotes();
  
  if (!mounted) return;
  
  ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(
      content: Text('✅ Convertido a ticket #$ticketId'),
      backgroundColor: Colors.green,
    ),
  );
} catch (e, stack) {
  debugPrint('❌ Error: $e');
  debugPrint('Stack: $stack');
  
  if (!mounted) return;
  
  ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(
      content: Text('❌ Error: $e'),
      backgroundColor: Colors.red,
      duration: Duration(seconds: 4),
    ),
  );
}
```

---

## 📊 Checklist de Verificación

```
SCHEMA:
✅ pos_ticket_items tiene product_code_snapshot
✅ pos_ticket_items tiene product_name_snapshot
✅ Ambas son TEXT NOT NULL
✅ Migración automática existe

MODELO:
✅ PosTicketItemModel tiene productCodeSnapshot
✅ PosTicketItemModel tiene productNameSnapshot
✅ toMap() incluye ambas
✅ fromMap() extrae ambas

REPOSITORY:
✅ saveTicket() inserta ambas
✅ updateTicket() inserta ambas

CONVERTER:
✅ Obtiene productCode de item
✅ Obtiene productName de item
✅ Incluye en INSERT
✅ Tiene fallbacks

UI:
✅ Botón aparece
✅ Callback conectado
✅ Mensaje de éxito aparece
✅ Sin pantalla negra

TESTING:
✅ Conversión exitosa
✅ Ticket aparece en ventas
✅ Se puede cobrar
✅ Validaciones funcionan
```

---

## 🎯 Resumen Final

✅ **100% Implementado**  
✅ **0 Errores Compilación**  
✅ **Retrocompatible**  
✅ **Documentado**  
✅ **Validado**  

---

**Fecha de Implementación**: 2025-12-29  
**Estado**: LISTO PARA PRODUCCIÓN ✅

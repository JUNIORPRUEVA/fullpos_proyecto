# 🧪 GUÍA DE TESTING: Convertir Cotización → Ticket Pendiente

## Resumen Rápido

La funcionalidad de convertir cotización a ticket pendiente está **100% implementada y lista para testear**.

### ¿Qué se implementó?
- Nueva clase: `QuoteToTicketConverter` (transaccional, segura)
- Función mejorada: `_convertToTicket()` en quotes_page.dart
- Validaciones y manejo de errores
- Logs claros para debugging

### ¿Dónde está?
- **Conversor**: `lib/features/sales/data/quote_to_ticket_converter.dart`
- **Integración UI**: `lib/features/sales/ui/quotes_page.dart` → función `_convertToTicket()`

---

## Flujo de Uso (Desde Usuario)

```
1. Abre módulo Cotizaciones
   ↓
2. Ve lista de cotizaciones
   ↓
3. Click en una cotización (o en acción "A Ticket Pendiente")
   ↓
4. Sistema convierte a ticket pendiente (transaccional)
   ↓
5. Ver mensaje de éxito: "✅ Cotización convertida a ticket pendiente #X"
   ↓
6. Lista se actualiza, cotización ahora tiene estado diferente
```

---

## Test Case 1: Conversión Exitosa

### Preparación
```sql
-- Asegurar que existe cliente
SELECT * FROM clients WHERE id = 1;  -- Si no existe, insertar

-- Crear cotización de prueba
INSERT INTO quotes (
  client_id, subtotal, itbis_enabled, itbis_rate, itbis_amount,
  discount_total, total, status, created_at_ms, updated_at_ms
) VALUES (
  1, 1000, 1, 0.18, 180, 0, 1180, 'OPEN', 
  1704067200000, 1704067200000
);

-- Guardar el quote_id retornado (ej: 1)

-- Insertar items
INSERT INTO quote_items (
  quote_id, description, qty, unit_price, price, cost, discount_line, total_line
) VALUES
  (1, 'Producto A', 2, 500, 500, 300, 0, 1000),
  (1, 'Producto B', 1, 180, 180, 100, 0, 180);
```

### Pasos de Test
1. **Abrir app → Módulo Cotizaciones**
   - Esperado: Ver lista con cotización recién creada

2. **Buscar/Localizar cotización recién creada**
   - Debería verse en la lista (status "Abierta")

3. **Click en botón/acción "A Ticket Pendiente"**
   - En la fila de cotización, buscar icono o botón para convertir
   - Hacer click

4. **Esperar respuesta**
   - Timeout máximo: 2-3 segundos
   - Mensaje esperado: `✅ Cotización convertida a ticket pendiente #X`
   - Donde X es el ID del nuevo ticket

5. **Verificar en consola (Debug)**
   - Debe haber logs como:
   ```
   🔄 [CONVERTER] Iniciando conversión de cotización #1 a ticket pendiente
   ✅ [CONVERTER] Cotización encontrada: [nombre]
   📦 [CONVERTER] 2 items encontrados
   ✅ [CONVERTER] Ticket creado con ID: 1
   ✅ [CONVERTER] 2 items insertados
   🎉 [CONVERTER] Conversión exitosa: Cotización #1 → Ticket #1
   ```

### Validación en BD
```sql
-- Verificar ticket creado
SELECT * FROM pos_tickets ORDER BY id DESC LIMIT 1;
-- Debe haber nuevo ticket con los datos correctos

-- Verificar items copiados
SELECT * FROM pos_ticket_items WHERE ticket_id = <NUEVO_ID>;
-- Debe haber 2 items con qty, price, etc. correctos

-- Verificar estado de cotización actualizado
SELECT id, status FROM quotes WHERE id = 1;
-- Debe mostrar: status = 'PASSED_TO_TICKET'
```

### Resultado Esperado ✅
- Mensaje de éxito mostrado
- Nuevo ticket creado en BD
- Items copiados correctamente
- Cotización con estado actualizado
- Sin errores en consola
- Sin pantalla negra

---

## Test Case 2: Validación de Duplicados

### Pasos
1. **Convertir cotización #5 a ticket pendiente**
   - Mensaje: `✅ Cotización convertida a ticket pendiente #X`
   - Nuevo ticket #X creado

2. **INTENTAR convertir la misma cotización #5 NUEVAMENTE**
   - Buscar en lista
   - Click en "A Ticket Pendiente"

3. **Resultado Esperado**
   - Mensaje de advertencia: `⚠️ Esta cotización ya fue convertida a ticket pendiente`
   - NO se crea nuevo ticket
   - BD intacta (solo existe ticket #X original)

### Validación BD
```sql
SELECT COUNT(*) FROM pos_tickets WHERE id IN (
  SELECT id FROM pos_tickets ORDER BY created_at_ms DESC LIMIT 2
);
-- Debe retornar: 1 (solo el ticket original, no duplicado)
```

---

## Test Case 3: Validar Mapeo de Datos

### Preparación
```sql
INSERT INTO quotes (
  client_id, subtotal, itbis_enabled, itbis_rate, itbis_amount,
  discount_total, total, status, created_at_ms, updated_at_ms
) VALUES (
  5, 2500, 1, 0.18, 450, 100, 2850, 'OPEN',
  1704067200000, 1704067200000
);
-- Guardar quote_id (ej: 10)

INSERT INTO quote_items (
  quote_id, product_id, description, qty, unit_price, price, 
  cost, discount_line, total_line
) VALUES
  (10, 1, 'Laptop HP', 1, 2000, 2000, 1500, 0, 2000),
  (10, 2, 'Mouse Logitech', 5, 100, 100, 50, 0, 500);
```

### Test
1. **Convertir cotización #10 a ticket**
   - Anotar ticket ID retornado (ej: 42)

2. **Verificar en BD cada campo**
```sql
SELECT 
  'QUOTE' as type, id, client_id, subtotal, itbis_rate, 
  discount_total, total, status
FROM quotes WHERE id = 10
UNION ALL
SELECT 
  'TICKET' as type, id, client_id, subtotal, itbis_rate,
  discount_total, total, 'N/A'
FROM pos_tickets WHERE id = 42;
```

### Validación de Items
```sql
SELECT 
  'QUOTE_ITEM' as type, product_id, description, qty, price, cost, 
  discount_line, total_line
FROM quote_items WHERE quote_id = 10
UNION ALL
SELECT 
  'TICKET_ITEM' as type, product_id, description, qty, price, cost,
  discount_line, total_line
FROM pos_ticket_items WHERE ticket_id = 42
ORDER BY description;
```

### Resultado Esperado ✅
- Todos los valores coinciden exactamente
- client_id = 5 ✅
- subtotal = 2500 ✅
- itbis_rate = 0.18 ✅
- total = 2850 ✅
- 2 items copiados ✅
- Producto y cantidades iguales ✅

---

## Test Case 4: Performance (Muchos Items)

### Preparación
```sql
-- Crear cotización con 100 items (stress test)
INSERT INTO quotes (client_id, subtotal, itbis_enabled, itbis_rate,
  itbis_amount, discount_total, total, status, created_at_ms, updated_at_ms)
VALUES (1, 50000, 1, 0.18, 9000, 0, 59000, 'OPEN', 
  1704067200000, 1704067200000);

-- Guardar quote_id (ej: 20)
-- Luego insertar 100 items (puede ser con script)
FOR i=1 TO 100:
  INSERT INTO quote_items (quote_id, description, qty, unit_price, 
    price, cost, discount_line, total_line)
  VALUES (20, 'Item ' || i, 1, 500, 500, 300, 0, 500);
```

### Test
1. **Medir tiempo de conversión**
   - Tomar nota de tiempo de inicio
   - Click en "A Ticket Pendiente"
   - Anotar tiempo de finalización
   - Diferencia debe ser < 3 segundos

2. **Verificar items copiados**
```sql
SELECT COUNT(*) as total_items FROM pos_ticket_items 
WHERE ticket_id = <NUEVO_ID>;
-- Debe retornar: 100
```

### Resultado Esperado ✅
- Conversión completa en < 3 segundos
- 100 items copiados sin errores
- Sin lag en UI
- Mensaje de éxito mostrado

---

## Test Case 5: Manejo de Errores

### Escenario A: Cotización no existe
```
1. Intentar convertir cotización #99999 (no existe)
   (Ej: editar URL o manipular DB)

ESPERADO:
❌ Mensaje: "Error: Cotización #99999 no encontrada"
❌ Sin cambios en BD
❌ Sin crash
```

### Escenario B: Error de BD (simulado)
```
1. Pausar DB momentáneamente
2. Click en convertir
3. Restaurar DB

ESPERADO:
❌ Mensaje: "Error: [error message de BD]"
❌ Sin cambios en BD
❌ Transacción revirtió automáticamente
```

### Escenario C: Usuario cierra app durante conversión
```
1. Click en convertir
2. Inmediatamente cerrar app (antes de terminar)
3. Volver a abrir

ESPERADO:
✅ Sin crash
✅ BD en estado consistente
✅ Si se completó: ticket existe
✅ Si no se completó: nada se creó (transacción revirtió)
```

---

## Test Case 6: Funcionalidad Anterior No Rota

### Pasos
1. **Crear cotización**
   ✅ Debe funcionar

2. **Ver en lista**
   ✅ Debe aparecer

3. **Buscar/Filtrar**
   ✅ Búsqueda debe funcionar

4. **Duplicar cotización**
   ✅ Debe crear copia

5. **Ver PDF**
   ✅ PDF debe mostrarse/descargarse

6. **Convertir a Venta**
   ✅ Debe funcionar (acción anterior)

7. **Compartir WhatsApp**
   ✅ Debe abrir WhatsApp

8. **Eliminar cotización**
   ✅ Debe borrarse

9. **Ver detalles (diálogo)**
   ✅ Diálogo debe abrir con info completa

10. **LUEGO convertir a ticket**
    ✅ Debe funcionar sin problemas

### Resultado Esperado ✅
- Todas las funciones anteriores siguen funcionando
- Nueva función "convertir a ticket" integrada sin conflictos
- Menú UI sin cambios (integración limpia)

---

## Test Case 7: Integración con Otros Módulos

### Test: Ticket aparece donde corresponde
```
1. Convertir cotización a ticket #X

2. Ir al módulo de Ventas/Tickets
   ✅ Debe haber nuevo ticket #X visible

3. Verificar que ticket tiene:
   - Cliente correcto
   - Productos correctos
   - Total correcto
   - Estado: ready para vender

4. Completar venta desde el ticket
   ✅ Debe funcionar normalmente
```

---

## Checklist de Testing Final

### Básico ✅
- [ ] Crear cotización
- [ ] Convertir a ticket (botón/acción funciona)
- [ ] Mensaje de éxito muestra
- [ ] Lista se recarga
- [ ] Nuevo ticket existe en BD

### Validación ✅
- [ ] No se duplica si intenta convertir 2 veces
- [ ] Todos los datos se copian correctamente
- [ ] Estado de cotización cambió a PASSED_TO_TICKET
- [ ] Items copiados correctamente (cantidad)

### Performance ✅
- [ ] Conversión rápida (< 3 seg)
- [ ] Sin lag en UI
- [ ] Con 10+ items
- [ ] Con 100+ items

### Errores ✅
- [ ] Cotización no existente → Error claro
- [ ] Validación de duplicados funciona
- [ ] Transacción revierte si hay error
- [ ] Mensajes de error claros

### Compatibilidad ✅
- [ ] Funcionalidad anterior no rota
- [ ] Duplicar cotización sigue funcionando
- [ ] Ver PDF sigue funcionando
- [ ] Eliminar sigue funcionando
- [ ] Ticket aparece en módulo Tickets

### Consola/Logs ✅
- [ ] Logs de CONVERTER aparecen
- [ ] Logs de UI aparecen
- [ ] Errores si ocurren están documentados
- [ ] Stack traces si hay crashes

---

## Cómo Ejecutar Tests

### Opción 1: Manual (Recomendado para QA)
```
1. Abrir app en emulador/dispositivo
2. Ir a Cotizaciones
3. Ejecutar cada Test Case (1-7) arriba
4. Anotar resultados
5. Reportar issues si hay
```

### Opción 2: Automated (Si tienes setup)
```dart
// Pseudo-test
test('Convertir cotización a ticket', () async {
  final converter = QuoteToTicketConverter();
  final quoteId = 1;
  
  final ticketId = await converter.convertQuoteToTicket(
    quoteId: quoteId,
    userId: null,
  );
  
  expect(ticketId, greaterThan(0));
  
  // Verificar BD
  final ticket = await TicketsRepository().getTicketById(ticketId);
  expect(ticket, isNotNull);
  expect(ticket!.clientId, 1);
});
```

---

## Reporte de Issues

Si encuentras un problema:

1. **Anotar exactamente qué pasó**
2. **Incluir logs de consola** (copiar debugPrint)
3. **Pasos para reproducir**
4. **BD state** (SELECT queries si es relevante)
5. **Screenshots** (si aplica)

---

## Status Actual

✅ **IMPLEMENTADO Y LISTO PARA TESTING**

Próximo paso: Ejecutar tests manuales y reportar resultados.

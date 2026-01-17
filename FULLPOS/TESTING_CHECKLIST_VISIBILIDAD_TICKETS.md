# ✅ TESTING CHECKLIST: Visibilidad de Tickets

## Test Case 1: Convertir Cotización → Ticket

### Pre-requisitos
- [ ] App compilada sin errores
- [ ] Usuario logueado
- [ ] Base de datos funcional

### Pasos

1. **Abrir Cotizaciones**
   - [ ] Navega a Cotizaciones
   - [ ] Verifica que se ve la lista de cotizaciones

2. **Crear Cotización**
   - [ ] Click en "+" para crear nueva cotización
   - [ ] Selecciona un cliente
   - [ ] Agrega 1-2 productos
   - [ ] Confirma los valores
   - [ ] Guarda la cotización
   - [ ] Verifica que aparece en la lista

3. **Convertir a Ticket**
   - [ ] Hace clic en el botón naranja "Pasar a ticket pendiente" (ícono receipt_long)
   - [ ] Verifica que aparece mensaje ✅ "Cotización convertida a ticket"
   - [ ] Espera 1-2 segundos

4. **Verificar Navegación Automática**
   - [ ] Se redirige automáticamente a Ventas
   - [ ] Aparece un SnackBar de confirmación verde

5. **Verificar Visibilidad en Ventas**
   - [ ] Ahora está en pantalla de Ventas (Ventas aparece en tab activo)
   - [ ] Se ven las pestañas de carritos (Ticket 1, Ticket 2, etc.)
   - [ ] **IMPORTANTE:** El ticket nuevo aparece en las pestañas ✅
   - [ ] El nombre del ticket es el mismo que en la cotización
   - [ ] Los items están presentes con los mismos productos

6. **Verificar Contenido del Ticket**
   - [ ] Hace clic en la pestaña del nuevo ticket
   - [ ] Verifica que el ticket contiene:
     - [ ] Nombre/referencia de la cotización
     - [ ] Cliente correcto
     - [ ] Todos los productos que añadiste
     - [ ] Cantidades correctas
     - [ ] Precios correctos

7. **Verificar Persistencia**
   - [ ] Cierra completamente la app (kill process)
   - [ ] Reabre la app
   - [ ] Navega a Ventas
   - [ ] **IMPORTANTE:** El ticket aún aparece en las pestañas ✅
   - [ ] Los datos del ticket son idénticos

### Resultado Esperado
```
✅ Ticket creado desde cotización
✅ Automáticamente navegado a Ventas
✅ Ticket visible en lista de pestañas
✅ Contenido correcto (nombre, items, totales)
✅ Persiste después de cerrar/abrir app
```

---

## Test Case 2: Workflow Normal NO Afectado

### Pasos

1. **Crear Ticket Normal en Ventas**
   - [ ] En Ventas, con el carrito "Ticket 1"
   - [ ] Agrega 1-2 productos
   - [ ] Click en "Guardar como Ticket"
   - [ ] Asigna un nombre
   - [ ] Confirma

2. **Verificar Comportamiento**
   - [ ] El ticket se guarda correctamente
   - [ ] Aparece como nueva pestaña
   - [ ] Funciona exactamente como ANTES
   - [ ] NO hay diferencias en el workflow

3. **Verificar Carrito Vacío**
   - [ ] Después de guardar, vuelve a haber un carrito vacío disponible
   - [ ] Puedo seguir vendiendo sin problemas

### Resultado Esperado
```
✅ Funciona exactamente igual que antes
✅ Sin breaking changes
✅ Workflow normal intacto
```

---

## Test Case 3: Múltiples Tickets Simultáneos

### Pasos

1. **Crear 3 cotizaciones**
   - [ ] Crea 3 cotizaciones diferentes con productos distintos
   - [ ] Guarda todas

2. **Convertir 2 de ellas**
   - [ ] Convierte la cotización #1 → Automáticamente a Ventas
   - [ ] Regresa a Cotizaciones (usando back button o menú)
   - [ ] Convierte la cotización #2 → Automáticamente a Ventas

3. **Verificar en Ventas**
   - [ ] Ve las 2 pestañas nuevas con tickets
   - [ ] Los datos son diferentes y correctos
   - [ ] Puede seguir trabajando con ambos sin conflictos

4. **Cerrar y Reabrir**
   - [ ] Cierra app completamente
   - [ ] Reabre
   - [ ] Va a Ventas
   - [ ] **IMPORTANTE:** Ambos tickets siguen visibles ✅

### Resultado Esperado
```
✅ Múltiples tickets coexisten sin conflictos
✅ Cada uno mantiene su datos
✅ Persisten correctamente
```

---

## Test Case 4: Edición y Pago

### Pasos

1. **Después de convertir una cotización**
   - [ ] En Ventas, verifica que el ticket es editable
   - [ ] Puede cambiar cantidades
   - [ ] Puede agregar/remover productos
   - [ ] Los totales se actualizan correctamente

2. **Procesar Pago**
   - [ ] Hace clic en "Procesar Pago" o "Cobrar"
   - [ ] Selecciona método de pago
   - [ ] Completa la transacción
   - [ ] Verifica que se guarda correctamente como venta

3. **Verificación de Estado**
   - [ ] Después de cobrar, el ticket desaparece de Ventas (se convirtió en venta)
   - [ ] Puedo ver la venta en Historial de Ventas

### Resultado Esperado
```
✅ Ticket es completamente funcional
✅ Se puede editar, cobrar, usar normalmente
✅ Ninguna diferencia con tickets creados en Ventas
```

---

## Test Case 5: Logs y Debugging

### Pasos

1. **Abrir Logcat/Console**
   - [ ] Ejecutar: `flutter logs`
   - [ ] O revisar Output en IDE

2. **Convertir una cotización**
   - [ ] Observar los logs
   - [ ] Deberías ver:
     ```
     [CONVERTER] 🎫 Paso 4: Creando ticket pendiente
     [CONVERTER] ✅ Ticket creado con ID: XX
     [CONVERTER] ✅ 3 items insertados
     [CONVERTER] ✅ Estado actualizado a PASSED_TO_TICKET
     [UI] 🎉 Cotización convertida exitosamente a ticket #XX
     ```

3. **Verificar el flujo**
   - [ ] Los logs muestran cada paso
   - [ ] El ticketId es válido (número positivo)
   - [ ] El número de items es correcto

### Resultado Esperado
```
✅ Logs muestran flujo completo
✅ Sin errores en la consola
✅ Operación transaccional confirmada
```

---

## Checklist Rápido (TL;DR)

- [ ] **Test 1:** Convertir cotización → Visible en Ventas ✅
- [ ] **Test 2:** Workflow normal sin cambios ✅
- [ ] **Test 3:** Múltiples tickets funcionan ✅
- [ ] **Test 4:** Ticket es editable y pagable ✅
- [ ] **Test 5:** Logs son claros ✅

---

## Si Algo Falla

### Síntoma: Ticket no visible en Ventas
- [ ] Verifica que estás en Ventas (tab activo)
- [ ] Verifica que esperas 1-2 segundos tras el mensaje
- [ ] Verifica que el ticket tiene un nombre (no vacío)
- [ ] Revisa los logs en consola para errores

### Síntoma: Error en compilación
- [ ] Ejecuta: `flutter clean`
- [ ] Luego: `flutter pub get`
- [ ] Recompila: `flutter run`

### Síntoma: Ticket desaparece al reabrir
- [ ] Verifica que la BD se está guardando
- [ ] En logcat, busca "database error" o "sqlite error"
- [ ] Intenta eliminar la BD: `rm los_nilkas_pos.db`
- [ ] Reabre la app (creará BD nueva)

---

## Validación Final

Marca esto cuando todo esté ok:

- [ ] Compilación exitosa (0 errores)
- [ ] Test 1: Cotización → Ventas funciona
- [ ] Test 2: Workflow normal intacto
- [ ] Test 3: Múltiples tickets ok
- [ ] Test 4: Ticket es editable/pagable
- [ ] Test 5: Logs claros
- [ ] Sin breaking changes
- [ ] Persistencia confirmada

**Si todo está marcado: ✅ PRODUCCIÓN LISTO**

---

**Última revisión:** [Marca la fecha]  
**Probado por:** [Tu nombre]  
**Status:** ✅ APROBADO

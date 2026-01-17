╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║                   🧪 CHECKLIST DE PRUEBAS - COTIZACIONES 🧪               ║
║                                                                            ║
║                    VERIFICACIÓN DE CERO PANTALLA NEGRA                    ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝

⚠️  INSTRUCCIONES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Abre una terminal y ejecuta:
   flutter run -v

2. Abre la consola de Flutter (Ctrl+Alt+D en Windows)

3. Ve al módulo de Cotizaciones en la app

4. Realiza cada prueba en orden

5. Marca ✅ cuando CONFIRMES que funciona SIN pantalla negra

6. Si hay problema, captura el error de consola

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🎯 PRUEBAS CRÍTICAS (Reparadas)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### PRUEBA 1: Duplicar desde Lista (CRÍTICA)
┌─────────────────────────────────────────────────────────────────────────┐
│ Descripción:                                                            │
│ Duplicar una cotización desde el botón "Duplicar" en la lista           │
│                                                                         │
│ Pasos:                                                                  │
│ 1. [ ] Abre lista de cotizaciones                                       │
│ 2. [ ] Selecciona una cotización con items (ej: COT-00001)             │
│ 3. [ ] En la fila de botones, haz clic en "Duplicar"                  │
│ 4. [ ] Espera a que aparezca SnackBar verde                            │
│                                                                         │
│ Validaciones:                                                           │
│ [ ] ✅ La pantalla NO se pone negra                                    │
│ [ ] ✅ Aparece SnackBar: "✅ Cotización duplicada exitosamente"        │
│ [ ] ✅ La lista se actualiza mostrando la copia                        │
│ [ ] ✅ La copia tiene nombre original + "(Copia)"                      │
│ [ ] ✅ En consola ves: "📋 Duplicando... ✅ Cotización duplicada..."  │
│                                                                         │
│ Resultado: [ ] PASA  [ ] FALLA                                          │
│ Notas: ____________________________________                            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

### PRUEBA 2: Eliminar desde Lista (CRÍTICA)
┌─────────────────────────────────────────────────────────────────────────┐
│ Descripción:                                                            │
│ Eliminar una cotización desde el botón "Eliminar" en la lista           │
│                                                                         │
│ Pasos:                                                                  │
│ 1. [ ] Abre lista de cotizaciones                                       │
│ 2. [ ] Selecciona una cotización para eliminar (ej: COT-00002)         │
│ 3. [ ] En la fila de botones, haz clic en "Eliminar"                  │
│ 4. [ ] Se abre diálogo pidiendo confirmación                           │
│ 5. [ ] Haz clic en "Eliminar" (botón rojo)                            │
│ 6. [ ] Espera a que aparezca SnackBar                                  │
│                                                                         │
│ Validaciones:                                                           │
│ [ ] ✅ La pantalla NO se pone negra                                    │
│ [ ] ✅ Diálogo de confirmación se muestra                              │
│ [ ] ✅ Aparece SnackBar: "✅ Cotización eliminada"                     │
│ [ ] ✅ La cotización desaparece de la lista                            │
│ [ ] ✅ En consola ves: "🗑️  Eliminando... ✅ Cotización eliminada..." │
│                                                                         │
│ Resultado: [ ] PASA  [ ] FALLA                                          │
│ Notas: ____________________________________                            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

### PRUEBA 3: Convertir a Ticket Pendiente (CRÍTICA)
┌─────────────────────────────────────────────────────────────────────────┐
│ Descripción:                                                            │
│ Convertir cotización a ticket pendiente desde la lista                  │
│                                                                         │
│ Pasos:                                                                  │
│ 1. [ ] Abre lista de cotizaciones                                       │
│ 2. [ ] Selecciona una cotización no convertida (ej: COT-00003)         │
│ 3. [ ] En la fila de botones, haz clic en "A Ticket Pendiente"       │
│ 4. [ ] Espera a que se cree el ticket                                  │
│                                                                         │
│ Validaciones:                                                           │
│ [ ] ✅ La pantalla NO se pone negra                                    │
│ [ ] ✅ Aparece SnackBar: "✅ Convertido a ticket pendiente #..."       │
│ [ ] ✅ La cotización ahora muestra status "SENT"                       │
│ [ ] ✅ En consola ves: "✅ Convertido a ticket. Recargando..."        │
│                                                                         │
│ Resultado: [ ] PASA  [ ] FALLA                                          │
│ Notas: ____________________________________                            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🎯 PRUEBAS SECUNDARIAS (Ya funcionaban, verificar que sigue)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### PRUEBA 4: Cancelar Cotización
┌─────────────────────────────────────────────────────────────────────────┐
│ Pasos:                                                                  │
│ 1. [ ] En lista, haz clic en "Cancelar" en una cotización              │
│ 2. [ ] Confirma en el diálogo                                          │
│                                                                         │
│ Esperado:                                                               │
│ [ ] ✅ Sin pantalla negra                                              │
│ [ ] ✅ Cotización ahora muestra status "CANCELLED"                    │
│ [ ] ✅ SnackBar "✅ Cotización cancelada"                              │
│                                                                         │
│ Resultado: [ ] PASA  [ ] FALLA                                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

### PRUEBA 5: Convertir a Venta
┌─────────────────────────────────────────────────────────────────────────┐
│ Pasos:                                                                  │
│ 1. [ ] En lista de cotizaciones, haz clic "Convertir a Venta"         │
│ 2. [ ] Confirma en el diálogo (advierte sobre descuento de stock)     │
│ 3. [ ] Si pregunta por imprimir, elige una opción                     │
│                                                                         │
│ Esperado:                                                               │
│ [ ] ✅ Sin pantalla negra                                              │
│ [ ] ✅ Venta se crea exitosamente                                      │
│ [ ] ✅ Cotización ahora muestra status "CONVERTED"                    │
│ [ ] ✅ SnackBar con código de venta (ej: "Venta creada: VTA-00001")   │
│                                                                         │
│ Resultado: [ ] PASA  [ ] FALLA                                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

### PRUEBA 6: Duplicar desde Diálogo
┌─────────────────────────────────────────────────────────────────────────┐
│ Pasos:                                                                  │
│ 1. [ ] En lista, haz clic en una cotización para ver detalles          │
│ 2. [ ] Se abre diálogo con detalles                                    │
│ 3. [ ] En el footer del diálogo, haz clic "DUPLICAR"                  │
│ 4. [ ] Diálogo se cierra                                               │
│ 5. [ ] Lista se recarga en background                                  │
│                                                                         │
│ Esperado:                                                               │
│ [ ] ✅ Sin pantalla negra                                              │
│ [ ] ✅ Diálogo se cierra automáticamente                               │
│ [ ] ✅ Vuelves a la lista actualizada                                  │
│ [ ] ✅ Ves la copia en la lista                                        │
│ [ ] ✅ SnackBar "✅ Cotización duplicada exitosamente"                 │
│                                                                         │
│ Resultado: [ ] PASA  [ ] FALLA                                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

### PRUEBA 7: Eliminar desde Diálogo
┌─────────────────────────────────────────────────────────────────────────┐
│ Pasos:                                                                  │
│ 1. [ ] En lista, abre una cotización en diálogo                        │
│ 2. [ ] En el footer, haz clic "ELIMINAR"                              │
│ 3. [ ] Se pide confirmación                                            │
│ 4. [ ] Haz clic "Eliminar" en la confirmación                          │
│ 5. [ ] Diálogo se cierra                                               │
│                                                                         │
│ Esperado:                                                               │
│ [ ] ✅ Sin pantalla negra                                              │
│ [ ] ✅ Diálogo se cierra automáticamente                               │
│ [ ] ✅ Vuelves a la lista actualizada                                  │
│ [ ] ✅ La cotización no aparece en la lista                            │
│ [ ] ✅ SnackBar "✅ Cotización eliminada"                              │
│                                                                         │
│ Resultado: [ ] PASA  [ ] FALLA                                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

### PRUEBA 8: Ver PDF
┌─────────────────────────────────────────────────────────────────────────┐
│ Pasos:                                                                  │
│ 1. [ ] En lista, haz clic en "PDF" o "Ver PDF" en una cotización      │
│ 2. [ ] Se abre visor PDF                                               │
│ 3. [ ] Cierra el visor                                                 │
│                                                                         │
│ Esperado:                                                               │
│ [ ] ✅ Sin pantalla negra                                              │
│ [ ] ✅ PDF se genera y se muestra                                      │
│ [ ] ✅ Vuelves a la lista sin problemas                                │
│                                                                         │
│ Resultado: [ ] PASA  [ ] FALLA                                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🚀 PRUEBAS DE FLUJO COMBINADO
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### PRUEBA 9: Flujo Completo (Duplicar → Eliminar → Duplicar)
┌─────────────────────────────────────────────────────────────────────────┐
│ Pasos:                                                                  │
│ 1. [ ] Selecciona una cotización COT-00001                             │
│ 2. [ ] Haz clic "Duplicar" → Se crea COT-00001 (Copia)               │
│ 3. [ ] Espera confirmación                                             │
│ 4. [ ] Haz clic "Eliminar" en COT-00001 → Se elimina original         │
│ 5. [ ] Espera confirmación                                             │
│ 6. [ ] Haz clic "Duplicar" en COT-00001 (Copia) nuevamente           │
│ 7. [ ] Se crea COT-00001 (Copia) (Copia)                              │
│                                                                         │
│ Validaciones en cada paso:                                             │
│ [ ] ✅ Paso 2: Sin pantalla negra                                      │
│ [ ] ✅ Paso 4: Sin pantalla negra                                      │
│ [ ] ✅ Paso 6: Sin pantalla negra                                      │
│ [ ] ✅ Resultado final: 2 cotizaciones en lista (copias)              │
│ [ ] ✅ Todos los SnackBars aparecen correctamente                      │
│                                                                         │
│ Resultado: [ ] PASA  [ ] FALLA                                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

### PRUEBA 10: Stress Test (Múltiples operaciones seguidas)
┌─────────────────────────────────────────────────────────────────────────┐
│ Pasos:                                                                  │
│ 1. [ ] Selecciona una cotización                                       │
│ 2. [ ] Duplica (SnackBar verde)                                        │
│ 3. [ ] SIN esperar, abre otra cotización                               │
│ 4. [ ] Duplica esa también                                             │
│ 5. [ ] Abre la lista nuevamente                                        │
│ 6. [ ] Elimina una de las copias                                       │
│ 7. [ ] Sin esperar, duplica otra                                       │
│                                                                         │
│ Validaciones:                                                           │
│ [ ] ✅ Nunca hay pantalla negra                                        │
│ [ ] ✅ App sigue respondiendo                                          │
│ [ ] ✅ Lista se actualiza correctamente al final                       │
│ [ ] ✅ Todas las operaciones aparecen en consola                       │
│                                                                         │
│ Resultado: [ ] PASA  [ ] FALLA                                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 CONSOLA - MENSAJES ESPERADOS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Cuando dupliques, deberías ver en la consola (Ctrl+Alt+D):

```
📋 Duplicando cotización ID: 1...
✅ Cotización duplicada. Recargando lista...
```

Cuando elimines:

```
🗑️  Eliminando cotización ID: 2...
✅ Cotización eliminada
```

Cuando conviertas a ticket:

```
✅ Convertido a ticket. Recargando lista...
```

Si hay error, verás:

```
❌ Error al duplicar: ...
📋 Stack trace: ...
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ RESUMEN FINAL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Pruebas Críticas:
[ ] Prueba 1: Duplicar desde Lista        [ ] PASA  [ ] FALLA
[ ] Prueba 2: Eliminar desde Lista        [ ] PASA  [ ] FALLA
[ ] Prueba 3: Convertir a Ticket          [ ] PASA  [ ] FALLA

Pruebas Secundarias:
[ ] Prueba 4: Cancelar Cotización         [ ] PASA  [ ] FALLA
[ ] Prueba 5: Convertir a Venta           [ ] PASA  [ ] FALLA
[ ] Prueba 6: Duplicar desde Diálogo      [ ] PASA  [ ] FALLA
[ ] Prueba 7: Eliminar desde Diálogo      [ ] PASA  [ ] FALLA
[ ] Prueba 8: Ver PDF                     [ ] PASA  [ ] FALLA

Flujo Combinado:
[ ] Prueba 9: Flujo Completo              [ ] PASA  [ ] FALLA
[ ] Prueba 10: Stress Test                [ ] PASA  [ ] FALLA

ESTADO GENERAL:
[ ] ✅ TODAS PASAN - Listo para producción
[ ] ⚠️  ALGUNAS FALLAN - Revisar problemas
[ ] ❌ MUCHAS FALLAN - Investigar más

═══════════════════════════════════════════════════════════════════════════════

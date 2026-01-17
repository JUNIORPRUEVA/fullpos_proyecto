# 🧾 Guía: Corrección de Cortes de Texto y Alineación de Totales

## 📋 Problema Resuelto

El sistema de tickets ahora incluye:

✅ **Función de Debug Ruler** - Para detectar el ancho real de la impresora
✅ **Helpers de Seguridad** - Para evitar cortes de texto
✅ **Columnas Alineadas** - Sistema de columnas fijo para items
✅ **Totales Alineados** - Alineación correcta a la derecha
✅ **Sin Cortes** - Nunca excede el ancho configurado

---

## 🔧 1. Funciones de Alineación Segura Disponibles

### `buildDebugRuler()`
Genera una línea de números para verificar el ancho:
```
0123456789012345678901234567890123456789
```

### `padRightSafe(String text, int width)`
Rellena a la derecha sin exceder el ancho:
```dart
padRightSafe('Hola', 10); // "Hola      " (10 chars)
padRightSafe('Texto muy largo', 10); // "Texto muy " (truncado)
```

### `padLeftSafe(String text, int width)`
Rellena a la izquierda sin exceder el ancho:
```dart
padLeftSafe('100.00', 10); // "    100.00" (10 chars)
```

### `centerSafe(String text, int width)`
Centra texto sin exceder el ancho:
```dart
centerSafe('TITULO', 20); // "       TITULO       "
```

### `repeatedChar(String ch, int width)`
Repite un carácter hasta llenar:
```dart
repeatedChar('=', 42); // "=========================================="
```

### `totalLine(String label, String value, int width)`
Alinea totales a la derecha:
```dart
totalLine('TOTAL', 'RD$ 1,000.00', 42);
// "            TOTAL: RD$ 1,000.00"
```

---

## 📏 2. Verificar el Ancho Real (PASO IMPORTANTE)

### Método Recomendado

1. **En tu código de prueba**, crea un ticket usando la función de debug:

```dart
final builder = TicketBuilder(layout: config, company: company);
final ticketWithRuler = builder.buildPlainTextWithDebugRuler(testData);
print(ticketWithRuler);
```

2. **Salida que verás:**
```
DEBUG RULER - Verify width fits:
0123456789012345678901234567890123456789012
================================================
     MI EMPRESA DOMINICANA S.R.L.
  RNC: 123-4567-8 | Tel: 809-555-1234
  Av. Independencia #123, Santo Domingo
================================================
...
```

3. **Verifica que la regla se vea completa sin cortarse**.

4. **Si se corta**, ajusta `maxCharsPerLine` en [ticket_layout_config.dart](lib/core/printing/models/ticket_layout_config.dart):

```dart
// Línea 92 (en defaults())
this.maxCharsPerLine = 42,  // ← Cambia aquí si es necesario
```

5. **Prueba valores comunes:**
   - **Impresora 58mm:** 32-38 caracteres
   - **Impresora 80mm:** 42-48 caracteres

---

## 🎫 3. Estructura del Ticket (SIN CORTES)

### Encabezado
```
==========================================
         MI EMPRESA S.R.L.
    RNC: 123-4567-8 | Tel: 809-555-1234
       Av. Principal #123
==========================================
```

### Línea de Documento + Fecha
```
FACTURA                         FECHA: 29/12/2024
                                TICKET: #000154
```

### Datos del Cliente
```
DATOS DEL CLIENTE:
Nombre: Juan Pérez García
RNC/Cédula: 001-0123456-7
Teléfono: 809-555-1234
------------------------------------------
```

### Items con Columnas Alineadas
```
DESCRIPCIÓN      CANT. PRECIO     TOTAL
------------------------------------------
Producto 1         2    150.00    300.00
Producto 2         1    250.00    250.00
------------------------------------------
```

**Anchos de Columna (configurables):**
- DESCRIPCIÓN: 16 caracteres
- CANT.: 5 caracteres
- PRECIO: 8 caracteres
- TOTAL: resto del ancho disponible

### Totales (Alineados a la Derecha)
```
                    SUB-TOTAL: RD$ 1,000.00
                    DESCUENTO: RD$   100.00
                   ITBIS (18%): RD$   162.00
                   ----------------------------
                      TOTAL: RD$ 1,062.00
```

---

## 🛠️ 4. Implementación en tu Código

### Usar la Versión Normal (SIN Debug)
```dart
final builder = TicketBuilder(
  layout: config,
  company: company,
);

// Para vista previa
final textTicket = builder.buildPlainText(data);

// Para PDF
final pdfDoc = builder.buildPdf(data);
```

### Usar la Versión CON Debug (SOLO para testing)
```dart
// Para verificar el ancho real
final textWithRuler = builder.buildPlainTextWithDebugRuler(data);

// Imprime en consola para ver
print(textWithRuler);

// O muestra en la app para captura de pantalla
showDialog(
  context: context,
  builder: (context) => AlertDialog(
    title: const Text('Ticket Debug'),
    content: SingleChildScrollView(
      child: Text(textWithRuler, style: const TextStyle(fontFamily: 'Courier')),
    ),
  ),
);
```

---

## 📊 5. Datos de Prueba Recomendados

Para probar que NO se corta nada, usa textos largos:

```dart
final testData = TicketData(
  type: TicketType.sale,
  ticketNumber: 154,
  dateTime: DateTime.now(),
  client: ClientData(
    name: 'Juan Pérez García López Rodríguez',  // Nombre muy largo
    rnc: '001-0123456-7',
    phone: '809-555-1234',
  ),
  items: [
    TicketItemData(
      name: 'Camisa Oxford Manga Larga Color Azul',  // Descripción larga
      quantity: 2,
      unitPrice: 900.00,
      total: 1800.00,
    ),
  ],
  subtotal: 3750.00,
  itbis: 675.00,
  discount: 0,
  total: 4425.00,
  paymentMethod: 'Efectivo',
  paidAmount: 4500.00,
  changeAmount: 75.00,
);
```

---

## ✅ 6. Checklist de Verificación

- [ ] El `maxCharsPerLine` es el correcto para tu impresora
- [ ] La regla de debug (`0123456789...`) se ve completa sin cortes
- [ ] Encabezado centrado y sin cortes
- [ ] Columnas de items alineadas correctamente
- [ ] Totales alineados a la derecha
- [ ] Footer centrado sin cortes
- [ ] El texto del preview coincide con lo que imprime
- [ ] No hay palabras cortadas por el borde

---

## 🎯 7. Referencia Rápida

| Función | Uso | Ejemplo |
|---------|-----|---------|
| `buildDebugRuler()` | Obtener regla de posiciones | `print(builder.buildDebugRuler())` |
| `padRightSafe()` | Rellenar columna a derecha | `padRightSafe(name, 16)` |
| `padLeftSafe()` | Rellenar número a derecha | `padLeftSafe('1000.00', 8)` |
| `centerSafe()` | Centrar texto | `centerSafe('TITULO', 42)` |
| `repeatedChar()` | Generar separador | `repeatedChar('=', 42)` |
| `totalLine()` | Alinear total | `totalLine('TOTAL', 'RD$ 1,000.00', 42)` |
| `buildPlainText()` | Ticket normal | Uso en preview/print |
| `buildPlainTextWithDebugRuler()` | Ticket con debug | Uso en testing |

---

## 🚀 8. Notas Importantes

1. **El `maxCharsPerLine` es la base de todo** - Debe ser exacto para tu impresora
2. **Las funciones `Safe` nunca lanzan excepciones** - Truncan automáticamente si es necesario
3. **El PDF usa el mismo contenido que el texto** - Garantiza consistencia
4. **Los niveles de espaciado (1-10) afectan visualmente pero NO el conteo de caracteres**
5. **Los helpers están centralizados en `TicketBuilder`** - Úsalos siempre para nuevas líneas

---

## 🔗 Archivos Relacionados

- [ticket_builder.dart](lib/core/printing/models/ticket_builder.dart) - Lógica principal
- [ticket_layout_config.dart](lib/core/printing/models/ticket_layout_config.dart) - Configuración (incluye `maxCharsPerLine`)
- [unified_ticket_preview_widget.dart](lib/core/printing/unified_ticket_preview_widget.dart) - Vista previa
- [printer_settings_page.dart](lib/features/settings/ui/printer_settings_page.dart) - Panel de configuración

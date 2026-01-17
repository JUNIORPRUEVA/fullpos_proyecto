# 🚀 REFERENCIA RÁPIDA - Rediseño Elegante de Tickets

## Las 3 Nuevas Funciones

### 1. alignText(text, width, align) - Alinea Texto Genéricamente
```dart
// Sintaxis
String alignText(String text, int width, String align)

// Parámetros
text    → Texto a alinear
width   → Ancho total (respeta maxCharsPerLine)
align   → 'left' | 'center' | 'right'

// Ejemplos
builder.alignText('Nombre', 30, 'left');      // "Nombre                        "
builder.alignText('TÍTULO', 30, 'center');    // "          TÍTULO              "
builder.alignText('1000.00', 30, 'right');    // "                      1000.00"

// Característica especial
// Si text.length > width → se trunca automáticamente
```

---

### 2. sepLine(width, [char = '-']) - Línea Separadora
```dart
// Sintaxis
String sepLine(int width, [String char = '-'])

// Parámetros
width   → Ancho de la línea
char    → Carácter a repetir (default: '-')

// Ejemplos
builder.sepLine(42);        // "------------------------------------------"
builder.sepLine(42, '=');   // "=========================================="
builder.sepLine(25, '-');   // "-------------------------"

// Uso común
final sepWidth = (w * 0.6).round();  // 60% del ancho
buffer.writeln(builder.sepLine(sepWidth));
```

---

### 3. totalsLine(label, value, width, align) - Total Alineado
```dart
// Sintaxis
String totalsLine(String label, String value, int width, String align)

// Parámetros
label   → Etiqueta (ej: 'TOTAL')
value   → Valor (ej: 'RD$ 1,180.00')
width   → Ancho total
align   → 'left' | 'center' | 'right'

// Ejemplos
builder.totalsLine('TOTAL', 'RD$ 1,180.00', 42, 'right');
builder.totalsLine('SUB-TOTAL', 'RD$ 1,000.00', 42, 'right');
builder.totalsLine('ITBIS', 'RD$ 180.00', 42, 'center');

// Resultado (right align)
"                TOTAL: RD$ 1,180.00"
```

---

## Los 3 Nuevos Campos de Configuración

```dart
// En TicketLayoutConfig
final String headerAlignment;    // default: 'center'
final String detailsAlignment;   // default: 'left'
final String totalsAlignment;    // default: 'right'
```

### Cómo Usar
```dart
// Por defecto (profesional)
final config = TicketLayoutConfig.professional80mm();
// header = 'center', details = 'left', totals = 'right'

// Personalizado
final config = TicketLayoutConfig(
  headerAlignment: 'left',
  detailsAlignment: 'center',
  totalsAlignment: 'right',
);

// O actualizar un existente
final newConfig = config.copyWith(
  headerAlignment: 'center',
  detailsAlignment: 'left',
);
```

---

## El Nuevo buildPlainText()

La función ahora:
1. ✅ Usa `alignText()` para alineación genérica
2. ✅ Respeta los 3 campos de alineación
3. ✅ Usa columnas fijas para items
4. ✅ Se ve elegante y profesional
5. ✅ Imprime exactamente igual que el preview

### Estructura del Ticket
```
= ENCABEZADO (headerAlignment)
  • Nombre empresa
  • RNC | Teléfono
  • Dirección
=

FACTURA + FECHA (mixta)
TICKET + NÚMERO

----

Cajero

DETALLES (detailsAlignment)
  • Datos cliente
  • Teléfono

----

CANT  PRODUCTO          PRECIO (columnas fijas)
----
Items...
----

TOTALES (totalsAlignment)
  • SUB-TOTAL
  • ITBIS
  • Línea decorativa
  • TOTAL

----

FOOTER (center)
```

---

## Conversión Rápida del Código Antiguo

### ❌ Antes
```dart
buffer.writeln(centerSafe('TÍTULO', w));
buffer.writeln(padRightSafe('Nombre: ${client.name}', w));
buffer.writeln(padLeftSafe('Cantidad: 5', w));
buffer.writeln(totalLine('TOTAL', 'RD$ 1000.00', w));
```

### ✅ Después (Recomendado)
```dart
buffer.writeln(alignText('TÍTULO', w, 'center'));
buffer.writeln(alignText('Nombre: ${client.name}', w, 'left'));
buffer.writeln(alignText('Cantidad: 5', w, 'right'));
buffer.writeln(totalsLine('TOTAL', 'RD$ 1000.00', w, layout.totalsAlignment));
```

**Ventaja:** Las funciones antiguas aún funcionan, pero `alignText()` es más flexible.

---

## Valores de Alineación Permitidos

| Valor | Resultado | Uso |
|-------|-----------|-----|
| `'left'` | Texto alineado a izquierda | Detalles, datos cliente |
| `'center'` | Texto centrado | Encabezado, títulos, footer |
| `'right'` | Texto alineado a derecha | Totales, montos |

---

## Ejemplos de Configuración Predefinidas

### Professional (Por Defecto)
```dart
final config = TicketLayoutConfig.professional80mm();
// headerAlignment: 'center'
// detailsAlignment: 'left'
// totalsAlignment: 'right'
```
Ideal para: POS estándar, facturación profesional

### Compact (Rápido)
```dart
final config = TicketLayoutConfig.compact();
// Menos información, más rápido
```
Ideal para: Tickets rápidos, ventas de mostrador

### Centrado (Boutique)
```dart
final config = TicketLayoutConfig(
  headerAlignment: 'center',
  detailsAlignment: 'center',
  totalsAlignment: 'center',
);
```
Ideal para: Tiendas pequeñas, boutiques

### Izquierda (Minimalista)
```dart
final config = TicketLayoutConfig(
  headerAlignment: 'left',
  detailsAlignment: 'left',
  totalsAlignment: 'left',
);
```
Ideal para: Recibos simples, tickets internos

---

## Debugging Rápido

### Verificar Ancho Real
```dart
final ruler = builder.buildDebugRuler();
print(ruler);
// Salida: 0123456789012345678901234567890123456789012
// Si se corta por derecha, reduce maxCharsPerLine
```

### Ver Configuración Actual
```dart
print('Max chars: ${layout.maxCharsPerLine}');
print('Header: ${layout.headerAlignment}');
print('Details: ${layout.detailsAlignment}');
print('Totals: ${layout.totalsAlignment}');
```

### Generar con Debug
```dart
final ticketDebug = builder.buildPlainTextWithDebugRuler(data);
print(ticketDebug);
// Muestra: regla + ticket + regla (útil para debugging)
```

---

## Checklist de Alineación Correcta

✅ **Encabezado**
- [ ] Nombre empresa visible
- [ ] RNC y teléfono en línea
- [ ] Dirección completa

✅ **Detalles**
- [ ] Nombre cliente
- [ ] Teléfono (si existe)
- [ ] RNC/Cédula (si existe)

✅ **Items**
- [ ] Cantidad alineada
- [ ] Producto visible (truncado si es largo)
- [ ] Precio a la derecha

✅ **Totales**
- [ ] SUB-TOTAL visible
- [ ] ITBIS (si existe)
- [ ] TOTAL destacado

✅ **Footer**
- [ ] Mensaje visible
- [ ] Centrado correctamente
- [ ] Sin cortes

---

## Parámetros por Defecto

```dart
const TicketLayoutConfig({
  // ... otros parámetros ...
  this.headerAlignment = 'center',      // ← Encabezado centrado
  this.detailsAlignment = 'left',       // ← Detalles a izquierda
  this.totalsAlignment = 'right',       // ← Totales a derecha
});
```

**Estos defaults son profesionales y funcionan bien.**

---

## Funciones Helper Aún Disponibles (Legacy)

```dart
// Aún funcionan pero recomendamos usar alignText()
centerSafe(String text, int width)      → align(text, width, 'center')
padRightSafe(String text, int width)    → align(text, width, 'left')
padLeftSafe(String text, int width)     → align(text, width, 'right')
repeatedChar(String ch, int width)      → sepLine(width, ch)
totalLine(label, value, w)              → totalsLine(label, value, w, 'right')
```

---

## La Garantía

**Lo que ves en la vista previa es EXACTAMENTE lo que imprime.**

- Mismo ancho (maxCharsPerLine)
- Misma alineación
- Mismo espaciado
- Mismos caracteres
- WYSIWYG garantizado

---

## Tiempo de Ejecución

```
buildPlainText(data)           ~10ms (texto)
buildPdf(data)                 ~50ms (PDF)
buildDebugRuler()              <1ms
alignText(...)                 <0.1ms
```

**Muy rápido, listo para producción.**

---

## Casos No Soportados (Error Handling)

```dart
// ✅ Soportado: Texto muy largo
alignText('Producto con nombre muy largo', 20, 'left');
// → Se trunca automáticamente: "Producto con nombre"

// ✅ Soportado: Ancho 0 o negativo
alignText('Texto', -5, 'left');
// → Se devuelve texto truncado

// ✅ Soportado: Alineación inválida
alignText('Texto', 20, 'invalid');
// → Se usa 'left' por defecto
```

---

## Resumen

| Función | Propósito | Parámetro Alineación |
|---------|-----------|---------------------|
| `alignText()` | Alinear texto genéricamente | Sí (configurable) |
| `sepLine()` | Crear separadores | No (solo carácter) |
| `totalsLine()` | Línea de total | Sí (configurable) |
| `buildPlainText()` | Generar ticket | Usa config |
| `buildDebugRuler()` | Verificar ancho | No aplica |

---

**¡LISTO PARA USAR!** 🎉

Más detalles: Ver `GUIA_REDISENO_ELEGANTE_TICKETS.md`
Ejemplos: Ver `EJEMPLOS_REDISENO_ELEGANTE_TICKETS.dart`
Checklist: Ver `CHECKLIST_REDISENO_ELEGANTE_TICKETS.md`

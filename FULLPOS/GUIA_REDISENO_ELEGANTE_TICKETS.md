# 🎨 Rediseño Elegante de Tickets Térmicos

## Introducción

Se ha implementado un rediseño profesional y elegante del ticket térmico que:

✨ **Se ve limpio y profesional**  
⚡ **Imprime rápido (sin decoraciones innecesarias)**  
✅ **Todo perfectamente alineado**  
🔧 **Configuración flexible de alineaciones**  
📐 **Columnas fijas y precisas**

---

## 🆕 Nuevos Campos de Configuración

En `TicketLayoutConfig` se han agregado 3 nuevos campos para controlar la alineación:

```dart
/// Alineación del encabezado: 'left' | 'center' | 'right'
final String headerAlignment;     // por defecto: 'center'

/// Alineación de detalles y cliente: 'left' | 'center' | 'right'
final String detailsAlignment;    // por defecto: 'left'

/// Alineación de totales: 'left' | 'center' | 'right'
final String totalsAlignment;     // por defecto: 'right'
```

### Ejemplos de Configuración

```dart
// Profesional (por defecto)
final config = TicketLayoutConfig.professional80mm();
// headerAlignment = 'center'
// detailsAlignment = 'left'
// totalsAlignment = 'right'

// Personalizado
final config = TicketLayoutConfig(
  headerAlignment: 'left',    // Encabezado a la izquierda
  detailsAlignment: 'center', // Detalles centrados
  totalsAlignment: 'center',  // Totales centrados
);
```

---

## 🔧 Nuevas Funciones Helper

### 1. `alignText(String text, int width, String align) → String`

Alinea texto genéricamente respetando el ancho máximo.

```dart
// Alinea a la izquierda (rellena a la derecha)
builder.alignText('Nombre', 30, 'left');
// Resultado: "Nombre                        "

// Alinea al centro
builder.alignText('TÍTULO', 30, 'center');
// Resultado: "          TÍTULO              "

// Alinea a la derecha (rellena a la izquierda)
builder.alignText('1000.00', 30, 'right');
// Resultado: "                      1000.00"
```

**Características:**
- Trunca automáticamente si texto es mayor que width
- Rellena con espacios según la alineación
- Respeta `maxCharsPerLine`

---

### 2. `sepLine(int width, [String char = '-']) → String`

Crea una línea separadora del ancho especificado.

```dart
// Línea con guiones (por defecto)
builder.sepLine(42);
// Resultado: "----------"

// Línea con caracteres personalizados
builder.sepLine(42, '=');
// Resultado: "=========="

// Línea del 60% del ancho
final sepWidth = (width * 0.6).round();
builder.sepLine(sepWidth);
// Resultado: línea con ~25 guiones (para 42 chars totales)
```

---

### 3. `totalsLine(String label, String value, int width, String align) → String`

Crea una línea de total alineada según configuración.

```dart
// Alineado a la derecha
builder.totalsLine('TOTAL', 'RD$ 1,180.00', 42, 'right');
// Resultado: "                TOTAL: RD$ 1,180.00"

// Alineado al centro
builder.totalsLine('SUBTOTAL', 'RD$ 1,000.00', 42, 'center');
// Resultado: "      SUBTOTAL: RD$ 1,000.00        "

// Alineado a la izquierda
builder.totalsLine('ITBIS', 'RD$ 180.00', 42, 'left');
// Resultado: "ITBIS: RD$ 180.00               "
```

---

## 📋 Estructura del Nuevo Ticket

El ticket ahora sigue esta estructura elegante:

```
========================================
         FULLTECH, SRL
RNC: 133080206 | Tel: +1(829)531-8442
        Centro Balber 9
========================================

FACTURA                 FECHA: 29/12/2025
                        TICKET: #DEMO-001
----------------------------------------

Cajero: Junior

DATOS DEL CLIENTE:
Nombre: Cliente Demo
Teléfono: (809) 555-1234
----------------------------------------

CANT  PRODUCTO                 PRECIO
----------------------------------------
2     Producto de Prueba       500.00
1     Otro producto            200.00
----------------------------------------

               SUB-TOTAL: RDS 1,000.00
              ITBIS (18%): RDS   180.00
               -----
                TOTAL: RDS 1,180.00

Gracias por su compra
No se aceptan devoluciones sin
presentar este ticket.
```

### Características del Diseño

| Sección | Alineación | Descripción |
|---------|-----------|-------------|
| **ENCABEZADO** | headerAlignment (center) | Nombre, RNC, dirección |
| **FACTURA/FECHA** | Mixta | Documento a izq, Fecha a der |
| **DETALLES** | detailsAlignment (left) | Cajero, datos del cliente |
| **ITEMS** | Columnas fijas | CANT + PRODUCTO + PRECIO |
| **TOTALES** | totalsAlignment (right) | SUB-TOTAL, ITBIS, TOTAL |
| **FOOTER** | center | Mensaje de cierre |

---

## 🎯 Tipos de Alineación

### `left` - Alineación a la Izquierda
```
Nombre: Cliente Demo
RNC: 123-456789
```
**Uso:** Detalles, información de cliente, cajero.

### `center` - Alineación al Centro
```
         FULLTECH, SRL
    Gracias por su compra
```
**Uso:** Encabezado, títulos, mensajes, footer.

### `right` - Alineación a la Derecha
```
              SUB-TOTAL: RDS 1,000.00
                TOTAL: RDS 1,180.00
```
**Uso:** Totales, montos, valores alineados.

---

## 📐 Columnas Fijas para Items

El detalle de ventas usa columnas fijas para garantizar alineación perfecta:

```dart
final int cantWidth = 5;        // Cantidad: 5 caracteres
final int priceWidth = 10;      // Precio: 10 caracteres
final int productWidth = w - cantWidth - priceWidth - 2;
                                // Producto: resto del ancho
```

### Ejemplo Visual

```
CANT  PRODUCTO                 PRECIO
-----  -------------------  ----------
5     Camisa Oxford Azul M       500.00
2     Pantalón Casual Beige      750.00
1     Zapatos Deportivos       1,200.00
```

---

## 💡 Ejemplos de Uso

### Generar Ticket Normal

```dart
final config = TicketLayoutConfig.professional80mm();
final builder = TicketBuilder(
  layout: config,
  company: myCompanyInfo,
);

final ticketText = builder.buildPlainText(myTicketData);
print(ticketText);  // Muestra en consola
```

### Generar Ticket con Alineación Personalizada

```dart
final config = TicketLayoutConfig(
  maxCharsPerLine: 42,
  headerAlignment: 'left',     // Encabezado a la izquierda
  detailsAlignment: 'center',  // Detalles centrados
  totalsAlignment: 'center',   // Totales centrados
);

final builder = TicketBuilder(layout: config, company: company);
final ticketText = builder.buildPlainText(data);
```

### Verificar Ancho Real

```dart
final ruler = builder.buildDebugRuler();
print(ruler);  // Salida: 0123456789012345...

// Si se corta o no se ve completo, ajusta maxCharsPerLine
```

### Usar con Impresora Térmica

```dart
// El mismo texto se envía a la impresora
final builder = TicketBuilder(layout: config, company: company);
final ticketText = builder.buildPlainText(data);

// Enviar exactamente este texto a la impresora térmica
// Sin agregar más newlines ni formato adicional
await printer.printRaw(ticketText);
```

---

## 🔄 Migración desde Versión Anterior

Si tienes código que usa las funciones antiguas (`centerSafe`, `padRightSafe`, etc.):

### Antes
```dart
buffer.writeln(centerSafe('TÍTULO', w));
buffer.writeln(padRightSafe('Nombre: ${client.name}', w));
```

### Ahora (Recomendado)
```dart
buffer.writeln(alignText('TÍTULO', w, 'center'));
buffer.writeln(alignText('Nombre: ${client.name}', w, 'left'));
```

**Nota:** Las funciones antiguas (`centerSafe`, `padRightSafe`, etc.) aún funcionan, pero se recomienda usar `alignText()` que es más genérica y flexible.

---

## ⚙️ Configuración en la BD

Los nuevos campos se guardan en la tabla de configuración de impresora:

```sql
ALTER TABLE printer_settings ADD COLUMN header_alignment VARCHAR(10) DEFAULT 'center';
ALTER TABLE printer_settings ADD COLUMN details_alignment VARCHAR(10) DEFAULT 'left';
ALTER TABLE printer_settings ADD COLUMN totals_alignment VARCHAR(10) DEFAULT 'right';
```

En `PrinterSettingsModel`:
```dart
final String headerAlignment;
final String detailsAlignment;
final String totalsAlignment;
```

---

## 🎨 Tips de Diseño

### Usar Alineación Consistente

```dart
// ❌ MAL - Mezcla aleatoria de alineaciones
headerAlignment: 'left'
detailsAlignment: 'right'
totalsAlignment: 'center'

// ✅ BIEN - Consistente y profesional
headerAlignment: 'center'
detailsAlignment: 'left'
totalsAlignment: 'right'
```

### Evitar Líneas Decorativas Excesivas

```dart
// ❌ MAL - Demasiadas decoraciones
========================================
====  EMPRESA  ====
========================================

// ✅ BIEN - Limpio y simple
========================================
EMPRESA
========================================
```

### Dejar Espacio para Lectura

```dart
// ❌ MAL - Sin espaciado
SUB-TOTAL: RD$ 1,000.00
ITBIS: RD$ 180.00
TOTAL: RD$ 1,180.00

// ✅ BIEN - Con espaciado
SUB-TOTAL: RD$ 1,000.00
ITBIS: RD$ 180.00
----------
TOTAL: RD$ 1,180.00
```

---

## 🐛 Troubleshooting

### Problema: Texto se corta por el lado derecho

**Solución:** Reduce `maxCharsPerLine`
```dart
// Si usas 42 y se corta, prueba 40
TicketLayoutConfig(maxCharsPerLine: 40)
```

### Problema: Texto no se alinea correctamente

**Solución:** Verifica la alineación configurada
```dart
// Imprime para debuguear
print('headerAlignment: ${layout.headerAlignment}');
print('detailsAlignment: ${layout.detailsAlignment}');
print('totalsAlignment: ${layout.totalsAlignment}');
```

### Problema: Columnas desalineadas en items

**Solución:** Los anchos se calculan automáticamente, verifica que `maxCharsPerLine` es correcto.

---

## 📚 Referencia Completa

### TicketLayoutConfig - Nuevos Campos

```dart
class TicketLayoutConfig {
  // ... campos existentes ...

  /// Encabezado: 'left' | 'center' | 'right'
  final String headerAlignment;

  /// Detalles: 'left' | 'center' | 'right'
  final String detailsAlignment;

  /// Totales: 'left' | 'center' | 'right'
  final String totalsAlignment;

  const TicketLayoutConfig({
    // ... parámetros existentes ...
    this.headerAlignment = 'center',
    this.detailsAlignment = 'left',
    this.totalsAlignment = 'right',
  });
}
```

### TicketBuilder - Nuevas Funciones

```dart
class TicketBuilder {
  // Alinea texto genéricamente
  String alignText(String text, int width, String align)

  // Crea línea separadora
  String sepLine(int width, [String char = '-'])

  // Crea línea de total alineada
  String totalsLine(String label, String value, int width, String align)

  // (Funciones antiguas aún disponibles)
  String centerSafe(String text, int width)
  String padRightSafe(String text, int width)
  String padLeftSafe(String text, int width)
}
```

---

## ✅ Checklist de Implementación

- [ ] He actualizado `TicketLayoutConfig` con los 3 nuevos campos
- [ ] He agregado los selectores en la pantalla de configuración
- [ ] He actualizado `buildPlainText()` para usar `alignText()`
- [ ] He probado con alineaciones diferentes
- [ ] He verificado que el PDF y texto coinciden
- [ ] He testeado con nombres largos y productos complejos
- [ ] He guardado los valores en la BD
- [ ] He cargado los valores correctamente desde la BD

---

## 📞 Soporte

Para preguntas o problemas:

1. **Verifica el ancho real** con `buildDebugRuler()`
2. **Revisa la configuración** en `TicketLayoutConfig`
3. **Usa `alignText()` genérica** para máxima flexibilidad
4. **Mantén las alineaciones consistentes** en todo el ticket

¡El sistema está listo para producción! 🚀

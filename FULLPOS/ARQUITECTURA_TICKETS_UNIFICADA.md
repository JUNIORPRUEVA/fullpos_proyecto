# 🎫 Arquitectura Unificada de Tickets

## 📋 Resumen

Este documento describe la nueva arquitectura centralizada para la impresión de tickets en el sistema POS. El objetivo principal es garantizar que **la vista previa y la impresión real sean idénticas**, usando una **fuente única de datos** para la información de empresa.

---

## 🏗️ Componentes Principales

### 1. CompanyInfo (`lib/core/printing/models/company_info.dart`)

**Propósito**: Modelo que representa los datos de la empresa.

```dart
class CompanyInfo {
  final String name;
  final String? address;
  final String? phone;
  final String? rnc;
  final String? email;
  final String? slogan;
  final Uint8List? logoBytes;
}
```

**CompanyInfoRepository**: 
- `getCurrentCompanyInfo()` → Lee datos desde `EmpresaService` (fuente única)
- Los datos provienen EXCLUSIVAMENTE de **Configuración → Empresa**

---

### 2. TicketLayoutConfig (`lib/core/printing/models/ticket_layout_config.dart`)

**Propósito**: Configuración de diseño del ticket (separada de los datos de empresa).

```dart
class TicketLayoutConfig {
  final int paperWidthDots;       // 576 para 80mm
  final int maxCharsPerLine;      // ~42 caracteres
  final bool showLogo;
  final double fontSize;
  final String fontFamily;
  final bool showBusinessData;
  final bool showDatetime;
  final bool showCode;
  final bool showNcf;
  final bool showClient;
  final bool showCashier;
  final bool showTotals;
  final String? headerExtra;
  final String footerMessage;
  // ...
}
```

**Métodos factory**:
- `professional80mm()` → Preset profesional para 80mm
- `compact()` → Preset compacto
- `fromPrinterSettings(PrinterSettingsModel)` → Convierte desde configuración existente

---

### 3. TicketData (`lib/core/printing/models/ticket_data.dart`)

**Propósito**: Modelo unificado para cualquier tipo de ticket.

```dart
class TicketData {
  final TicketType type;          // sale, quote, refund, loan
  final String ticketNumber;
  final int createdAtMs;
  final double subtotal;
  final double total;
  final double itbisAmount;
  final String? ncfFull;
  final ClientInfo? client;
  final String? cashierName;
  final List<TicketItemData> items;
  final bool isCopy;
  // ...
}
```

**Métodos factory**:
- `fromSale(...)` → Convierte desde SaleModel
- `demo()` → Datos de demostración para pruebas

---

### 4. TicketBuilder (`lib/core/printing/models/ticket_builder.dart`)

**Propósito**: Constructor centralizado que genera tanto la vista previa como el PDF.

```dart
class TicketBuilder {
  final TicketLayoutConfig layout;
  final CompanyInfo company;

  // Genera texto plano para vista previa
  String buildPlainText(TicketData data);

  // Genera PDF para impresión
  pw.Document buildPdf(TicketData data);
}
```

**Garantía de consistencia**: Ambos métodos usan la misma lógica para formatear el contenido.

---

### 5. UnifiedTicketPrinter (`lib/core/printing/unified_ticket_printer.dart`)

**Propósito**: Servicio principal de impresión.

```dart
class UnifiedTicketPrinter {
  // Método principal
  static Future<PrintTicketResult> printTicket({
    required TicketData data,
    int? overrideCopies,
  });

  // Métodos de conveniencia
  static Future<PrintTicketResult> printSaleTicket({...});
  static Future<PrintTicketResult> autoPrintSale({...});
  static Future<PrintTicketResult> reprintSale({...});
  static Future<PrintTicketResult> printTestTicket();

  // Utilidades
  static Future<List<Printer>> getAvailablePrinters();
  static Future<String> generatePreviewText({TicketData? data});
}
```

---

### 6. UnifiedTicketPreviewWidget (`lib/core/printing/unified_ticket_preview_widget.dart`)

**Propósito**: Widget de vista previa que usa la misma lógica que TicketBuilder.

```dart
class UnifiedTicketPreviewWidget extends StatelessWidget {
  final PrinterSettingsModel settings;
  final CompanyInfo? company;
  final TicketData? data;
}
```

---

## 🔄 Flujo de Datos

```
┌─────────────────────────────────────────────────────────────────┐
│                    FUENTE ÚNICA DE VERDAD                       │
│                                                                 │
│  EmpresaService (Configuración → Empresa)                       │
│  ├── businessName                                               │
│  ├── rnc                                                        │
│  ├── address                                                    │
│  ├── phone                                                      │
│  └── logoBytes                                                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                  CompanyInfoRepository                          │
│                                                                 │
│  getCurrentCompanyInfo() → CompanyInfo                          │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      TicketBuilder                              │
│                                                                 │
│  ┌─────────────────┐     ┌─────────────────┐                   │
│  │  buildPlainText │     │     buildPdf    │                   │
│  │  (Vista Previa) │     │   (Impresión)   │                   │
│  └────────┬────────┘     └────────┬────────┘                   │
│           │                       │                             │
│           ▼                       ▼                             │
│    ┌──────────────┐       ┌──────────────┐                     │
│    │    String    │       │ pw.Document  │                     │
│    │  (mono text) │       │    (PDF)     │                     │
│    └──────────────┘       └──────────────┘                     │
└─────────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                   ThermalPrinterService                         │
│                                                                 │
│  printDocument(document, settings) → PrintResult                │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📍 Puntos de Uso Actualizados

| Archivo | Antes | Ahora |
|---------|-------|-------|
| `sales_page.dart` | `TicketPrinter.printTicket()` | `UnifiedTicketPrinter.printSaleTicket()` |
| `sales_list_page.dart` | `TicketPrinter.reprintSale()` | `UnifiedTicketPrinter.reprintSale()` |
| `returns_list_page.dart` | `TicketPrinter.printTicket()` | `UnifiedTicketPrinter.printSaleTicket()` |
| `quotes_page.dart` | `TicketPrinter.reprintSale()` | `UnifiedTicketPrinter.reprintSale()` |
| `settings_page.dart` | `TicketPrinter.printTestTicket()` | `UnifiedTicketPrinter.printTestTicket()` |
| `printer_settings_page.dart` | `TicketPrinter.*` | `UnifiedTicketPrinter.*` |

---

## ⚙️ Especificaciones de Impresora

| Parámetro | Valor |
|-----------|-------|
| Modelo | 2C-POS80-01-V6 |
| Ancho de papel | 80mm |
| Ancho en dots | 576 dots |
| Caracteres por línea | ~42 |
| Modo | ESC/POS |
| Fuente recomendada | Courier (monoespaciada) |

---

## ✅ Beneficios

1. **Consistencia**: Vista previa = Impresión real
2. **Fuente única**: Datos de empresa solo en un lugar
3. **Mantenibilidad**: Un solo TicketBuilder para todos los tipos de ticket
4. **Flexibilidad**: TicketLayoutConfig separado de datos de empresa
5. **Extensibilidad**: Fácil agregar nuevos tipos de ticket (TicketType)

---

## 🔧 Cómo Usar

### Imprimir una venta nueva:
```dart
await UnifiedTicketPrinter.printSaleTicket(
  sale: sale,
  items: items,
  cashierName: 'Juan',
);
```

### Reimprimir un ticket:
```dart
await UnifiedTicketPrinter.reprintSale(
  sale: sale,
  items: items,
  cashierName: 'Juan',
  copies: 1,
);
```

### Imprimir ticket de prueba:
```dart
await UnifiedTicketPrinter.printTestTicket();
```

### Obtener vista previa:
```dart
final previewText = await UnifiedTicketPrinter.generatePreviewText();
```

---

## ⚠️ Nota sobre TicketPrinter Deprecado

El archivo `ticket_printer.dart` ha sido marcado como `@Deprecated`. Todas las nuevas implementaciones deben usar `UnifiedTicketPrinter`.

```dart
@Deprecated('Use UnifiedTicketPrinter instead for centralized company data')
class TicketPrinter { ... }
```

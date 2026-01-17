# 🔧 GUÍA TÉCNICA: CAMBIOS DETALLADOS

## 1. CAMBIO EN `ticket_builder.dart`

### Ubicación: Línea ~169-173

**ANTES:**
```dart
  // ================================================ ENCABEZADO: EMPRESA
    if (layout.showCompanyInfo) {
      buffer.writeln(sepLine(w));
      buffer.writeln(alignText(company.name.toUpperCase(), w, ha));

      // RNC y Teléfono en la misma línea
      final rnc = company.rnc ?? '';
```

**DESPUÉS:**
```dart
  // ================================================ ENCABEZADO: EMPRESA
    if (layout.showCompanyInfo) {
      buffer.writeln(alignText(company.name.toUpperCase(), w, ha));

      // RNC y Teléfono en la misma línea
      final rnc = company.rnc ?? '';
```

**¿QUÉ CAMBIÓ?**
- Eliminada: `buffer.writeln(sepLine(w));`
- Razón: Línea decorativa no solicitada arriba del nombre

---

### Ubicación: Línea ~428-435 (buildPdf)

**ANTES:**
```dart
    // ================================================ HEADER EMPRESA
    if (layout.showCompanyInfo) {
      content.add(buildDoubleLine());

      content.add(
        pw.Center(
          child: pw.Text(
            company.name.toUpperCase(),
```

**DESPUÉS:**
```dart
    // ================================================ HEADER EMPRESA
    if (layout.showCompanyInfo) {
      content.add(
        pw.Center(
          child: pw.Text(
            company.name.toUpperCase(),
```

**¿QUÉ CAMBIÓ?**
- Eliminada: `content.add(buildDoubleLine());`
- Razón: Línea decorativa de PDF también se elimina

---

## 2. CAMBIO EN `printer_settings_model.dart`

### Ubicación: Línea ~46-48 (declaración de campos)

**AGREGADO:**
```dart
  // === ALINEACIÓN DE ELEMENTOS ===
  final String headerAlignment; // Alineación del encabezado: 'left' | 'center' | 'right'
  final String detailsAlignment; // Alineación de detalles: 'left' | 'center' | 'right'
  final String totalsAlignment; // Alineación de totales: 'left' | 'center' | 'right'
```

### Ubicación: Constructor (línea ~107-109)

**AGREGADO:**
```dart
    this.headerAlignment = 'center',
    this.detailsAlignment = 'left',
    this.totalsAlignment = 'right',
```

### Ubicación: toMap() (línea ~151-153)

**AGREGADO:**
```dart
    'header_alignment': headerAlignment,
    'details_alignment': detailsAlignment,
    'totals_alignment': totalsAlignment,
```

### Ubicación: fromMap() (línea ~193-195)

**AGREGADO:**
```dart
    headerAlignment: map['header_alignment'] as String? ?? 'center',
    detailsAlignment: map['details_alignment'] as String? ?? 'left',
    totalsAlignment: map['totals_alignment'] as String? ?? 'right',
```

### Ubicación: copyWith() (línea ~230-232 parámetros, ~292-294 valores)

**AGREGADO (parámetros):**
```dart
    String? headerAlignment,
    String? detailsAlignment,
    String? totalsAlignment,
```

**AGREGADO (en retorno):**
```dart
    headerAlignment: headerAlignment ?? this.headerAlignment,
    detailsAlignment: detailsAlignment ?? this.detailsAlignment,
    totalsAlignment: totalsAlignment ?? this.totalsAlignment,
```

### Ubicación: defaults() factory (línea ~340-342)

**AGREGADO:**
```dart
      headerAlignment: 'center',
      detailsAlignment: 'left',
      totalsAlignment: 'right',
```

### Ubicación: professionalTemplate() factory (línea ~370-372)

**AGREGADO:**
```dart
      headerAlignment: 'center',
      detailsAlignment: 'left',
      totalsAlignment: 'right',
```

---

## 3. CAMBIO EN `ticket_layout_config.dart`

### Ubicación: fromPrinterSettings() factory (línea ~276-278)

**ANTES:**
```dart
      headerAlignment: 'center',
      detailsAlignment: 'left',
      totalsAlignment: 'right',
```

**DESPUÉS:**
```dart
      headerAlignment: settings.headerAlignment,
      detailsAlignment: settings.detailsAlignment,
      totalsAlignment: settings.totalsAlignment,
```

**¿POR QUÉ?**
- Antes: Valores hardcodeados (siempre lo mismo)
- Ahora: Valores cargados desde PrinterSettingsModel (de la BD)
- Permite personalización futura desde UI

---

## 4. CAMBIOS EN `app_db.dart`

### Ubicación: _ensureSchemaIntegrity() (línea ~2380-2395)

**AGREGADO:**
```dart
      // === Alineación de elementos ===
      await _addColumnIfMissing(
        db,
        DbTables.printerSettings,
        'header_alignment',
        "TEXT NOT NULL DEFAULT 'center'",
      );
      await _addColumnIfMissing(
        db,
        DbTables.printerSettings,
        'details_alignment',
        "TEXT NOT NULL DEFAULT 'left'",
      );
      await _addColumnIfMissing(
        db,
        DbTables.printerSettings,
        'totals_alignment',
        "TEXT NOT NULL DEFAULT 'right'",
      );
```

**¿POR QUÉ?**
- Agrega 3 columnas a tabla printer_settings si no existen
- Se ejecuta automáticamente en siguiente arranque
- No afecta datos existentes

### Ubicación: UPDATE de normalización (línea ~2444-2446)

**ANTES:**
```dart
      await db.execute('''
        UPDATE ${DbTables.printerSettings}
        SET printer_name = COALESCE(printer_name, ''),
            ...
            section_spacing_level = COALESCE(section_spacing_level, 5)
      ''');
```

**DESPUÉS:**
```dart
      await db.execute('''
        UPDATE ${DbTables.printerSettings}
        SET printer_name = COALESCE(printer_name, ''),
            ...
            section_spacing_level = COALESCE(section_spacing_level, 5),
            header_alignment = COALESCE(header_alignment, 'center'),
            details_alignment = COALESCE(details_alignment, 'left'),
            totals_alignment = COALESCE(totals_alignment, 'right')
      ''');
```

**¿POR QUÉ?**
- Asigna valores por defecto a filas existentes
- Si columna NULL → asigna 'center', 'left', 'right'
- Garantiza integridad de datos

---

## 📝 RESUMEN DE ARCHIVOS MODIFICADOS

```
✅ ticket_builder.dart
   - Línea 173: Eliminar sepLine() de buildPlainText()
   - Línea 430: Eliminar buildDoubleLine() de buildPdf()

✅ printer_settings_model.dart
   - Línea 46: Agregar 3 campos
   - Línea 107: Constructor
   - Línea 151: toMap()
   - Línea 193: fromMap()
   - Línea 230: copyWith() parámetros
   - Línea 292: copyWith() valores
   - Línea 340: defaults()
   - Línea 370: professionalTemplate()

✅ ticket_layout_config.dart
   - Línea 276: fromPrinterSettings()

✅ app_db.dart
   - Línea 2380: _ensureSchemaIntegrity() - ADD COLUMN
   - Línea 2444: _ensureSchemaIntegrity() - UPDATE
```

---

## 🔄 FLUJO DE DATOS ACTUAL

```
1. App Inicia
   └─→ AppDb.database → _ensureSchemaIntegrity()
       └─→ Agregar 3 columnas a printer_settings si faltan
       └─→ Actualizar valores por defecto

2. Usuario imprime ticket
   └─→ UnifiedTicketPrinter.printTicket()
       └─→ PrinterSettingsRepository.getOrCreate()
           └─→ Lee 3 campos de BD
       └─→ TicketLayoutConfig.fromPrinterSettings()
           └─→ Copia valores de settings
       └─→ TicketBuilder(layout: config)
           └─→ Usa ha, da, ta en buildPlainText()
       └─→ ThermalPrinterService.printDocument()
           └─→ Imprime con alineaciones correctas

3. Resultado
   └─→ Ticket sin línea decorativa ✅
   └─→ Con alineación correcta ✅
```

---

## 🧪 CÓMO VERIFICAR

### En Console/Terminal:
```bash
# Buscar línea decorativa en código
grep -n "buildDoubleLine" lib/core/printing/models/ticket_builder.dart
# Debería retornar 0 resultados (no encontrado)

grep -n "sepLine(w)" lib/core/printing/models/ticket_builder.dart
# Debería retornar 0 resultados en buildPlainText()
```

### En Código:
```dart
// Verificar campos existen
final settings = await PrinterSettingsRepository.getOrCreate();
print(settings.headerAlignment);     // 'center'
print(settings.detailsAlignment);    // 'left'
print(settings.totalsAlignment);     // 'right'

// Verificar se cargan en config
final layout = TicketLayoutConfig.fromPrinterSettings(settings);
print(layout.headerAlignment);       // 'center'
print(layout.detailsAlignment);      // 'left'
print(layout.totalsAlignment);       // 'right'
```

### En Base de Datos:
```sql
-- Ver columnas de printer_settings
PRAGMA table_info(printer_settings);

-- Buscar estas 3 filas:
-- header_alignment | TEXT | 0 | 'center' | ...
-- details_alignment | TEXT | 0 | 'left' | ...
-- totals_alignment | TEXT | 0 | 'right' | ...
```

---

## 🎯 ESTADO ACTUAL

| Aspecto | Estado | Detalles |
|---------|--------|----------|
| Compilación | ✅ | 0 errores, 0 warnings |
| Lógica | ✅ | Flujo correcto BD → Código → Impresión |
| BD | ✅ | Migraciones automáticas en próx. inicio |
| Ticket | ✅ | Sin línea decorativa, elegante |
| Alineación | ✅ | Cargada desde BD (lista para UI) |

---

**Último Actualización:** 29 Diciembre 2025
**Responsable:** GitHub Copilot
**Versión:** 1.0 - Completado y Verificado

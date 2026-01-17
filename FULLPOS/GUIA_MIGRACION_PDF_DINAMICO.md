# 🔄 GUÍA DE MIGRACIÓN - PDF DINÁMICO

## ¿Qué cambió?

El módulo de Cotizaciones ahora usa **EmpresaService** como fuente única de datos. El parámetro `business` es **ahora opcional**.

---

## CÓDIGO ANTIGUO vs CÓDIGO NUEVO

### ❌ ANTES (Código antiguo)

```dart
// Requería pasar 'business' siempre
final business = await SettingsRepository.getBusinessInfo();

final pdfData = await QuotePrinter.generatePdf(
  quote: quote,
  items: items,
  clientName: clientName,
  clientPhone: clientPhone,
  clientRnc: clientRnc,
  business: business,  // ← REQUERIDO
  validDays: 15,
);
```

---

### ✅ DESPUÉS (Código nuevo - OPCIÓN 1)

```dart
// NO necesitas obtener 'business'
// QuotePrinter lo obtiene automáticamente

final pdfData = await QuotePrinter.generatePdf(
  quote: quote,
  items: items,
  clientName: clientName,
  clientPhone: clientPhone,
  clientRnc: clientRnc,
  // NO necesitas 'business'
  validDays: 15,
);
```

---

### ✅ DESPUÉS (Código nuevo - OPCIÓN 2)

Si quieres mantener el parámetro `business` (fallback):

```dart
final business = await SettingsRepository.getBusinessInfo();

final pdfData = await QuotePrinter.generatePdf(
  quote: quote,
  items: items,
  clientName: clientName,
  clientPhone: clientPhone,
  clientRnc: clientRnc,
  business: business,  // ← OPCIONAL (fallback)
  validDays: 15,
);
```

**Sigue funcionando igual, pero ahora primero intenta EmpresaService.**

---

## PASOS DE MIGRACIÓN

### Paso 1: Identificar dónde se llama a QuotePrinter

```bash
# En VS Code: Ctrl+Shift+F
# Buscar: QuotePrinter.generatePdf
# O: QuotePrinter.showPreview
# O: QuotePrinter.printQuote
```

Encontrarás llamadas en:
- `lib/features/sales/ui/quotes_page.dart`
- Otros módulos si los hay

### Paso 2: Opción A - Remover parámetro 'business' (RECOMENDADO)

**ANTES:**
```dart
final business = await SettingsRepository.getBusinessInfo();

await QuotePrinter.showPreview(
  context: context,
  quote: quote,
  items: items,
  clientName: clientName,
  clientPhone: clientPhone,
  clientRnc: clientRnc,
  business: business,  // ← Eliminar esta línea
  validDays: 15,
);
```

**DESPUÉS:**
```dart
// Eliminar la línea de obtener business
// await SettingsRepository.getBusinessInfo(); ← Eliminar

await QuotePrinter.showPreview(
  context: context,
  quote: quote,
  items: items,
  clientName: clientName,
  clientPhone: clientPhone,
  clientRnc: clientRnc,
  validDays: 15,
);
```

**Beneficios:**
- ✅ Código más limpio
- ✅ EmpresaService obtiene datos automáticamente
- ✅ Siempre datos frescos de la BD

### Paso 3: Opción B - Mantener parámetro (COMPATIBLE)

Si prefieres mantener el código casi igual:

**ANTES:**
```dart
final business = await SettingsRepository.getBusinessInfo();

await QuotePrinter.showPreview(
  ...
  business: business,
);
```

**DESPUÉS:**
```dart
final business = await SettingsRepository.getBusinessInfo();

await QuotePrinter.showPreview(
  ...
  business: business,  // ← Sigue funcionando
);
```

**Nada cambió en tu código, pero internamente:**
- QuotePrinter primero intenta EmpresaService
- Si falla, usa el parámetro `business`
- **Tienes dos fuentes de seguridad**

### Paso 4: Compilar y probar

```bash
flutter analyze
flutter pub get
flutter run
```

**Verificar:**
- ✅ 0 errores de compilación
- ✅ PDF se abre sin errores
- ✅ Datos de empresa son correctos

---

## CASOS ESPECIALES

### Caso 1: Código en otros módulos

Si otros módulos también llaman a `QuotePrinter`:

```dart
// En módulo X
import 'core/printing/quote_printer.dart';

final pdfData = await QuotePrinter.generatePdf(
  ...
  business: someModel,  // ← Sigue funcionando
);
```

**No necesitas cambios.** Funciona igual como fallback.

---

### Caso 2: Necesitar datos de empresa directamente

Si necesitas acceder a datos de empresa en otros módulos:

**ANTES:**
```dart
final business = await SettingsRepository.getBusinessInfo();
print(business.name);
```

**AHORA:**
```dart
import 'core/services/empresa_service.dart';

final config = await EmpresaService.getEmpresaConfig();
print(config.nombreEmpresa);
```

**Beneficios:**
- ✅ Datos SIEMPRE frescos (no cache)
- ✅ Fallback seguro a defaults
- ✅ Single Source of Truth

---

### Caso 3: Verificar que PDFs se regeneran

**Test rápido:**

```dart
// 1. Abre cotización
await QuotePrinter.showPreview(...);

// 2. Nota el encabezado

// 3. Cambia en Configuración

// 4. Reabre PDF

// RESULTADO: ✅ Datos actualizados
```

---

## CHECKLIST DE MIGRACIÓN

- [ ] Identificar todas las llamadas a `QuotePrinter.*`
- [ ] Opción A: Remover parámetro `business` (recomendado)
  - [ ] O Opción B: Mantener parámetro `business` (compatible)
- [ ] Compilar: `flutter analyze`
- [ ] Probar: Ver PDF de cotización
- [ ] Verificar: Encabezado muestra datos reales
- [ ] Verificar: Cambios en Config se reflejan
- [ ] Verificar: Sin "Sistema POS Profesional"
- [ ] Verificar: Sin "LOS NILKAS"

---

## PREGUNTAS FRECUENTES

**P: ¿Tengo que cambiar todo mi código?**
R: No. El código antiguo sigue funcionando. Los cambios son opcionales.

**P: ¿Cuál es la mejor práctica?**
R: Remover el parámetro `business` para código más limpio.

**P: ¿Qué pasa si EmpresaService falla?**
R: Tiene fallback seguro a "Mi Negocio" por defecto.

**P: ¿Los PDFs se regeneran siempre?**
R: Sí. Cada apertura es un PDF nuevo con datos frescos.

**P: ¿Puedo seguir usando BusinessInfoModel?**
R: Sí, como parámetro fallback. Pero EmpresaService es preferido.

---

## SOPORTE

Si tienes dudas:

1. Lee [IMPLEMENTACION_PDF_DINAMICO.md](IMPLEMENTACION_PDF_DINAMICO.md)
2. Revisa [lib/core/services/empresa_service.dart](lib/core/services/empresa_service.dart)
3. Revisa [lib/core/printing/quote_printer.dart](lib/core/printing/quote_printer.dart)

---

**Status:** ✅ Migración sencilla - Código es backward compatible

Fecha: 29 de Diciembre de 2025

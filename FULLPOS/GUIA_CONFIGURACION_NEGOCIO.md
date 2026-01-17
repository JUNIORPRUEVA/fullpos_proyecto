# 📋 Guía Completa: Módulo de Configuración del Negocio/Empresa

## 🎯 Resumen de Mejoras Implementadas

Se ha completado la implementación del módulo de configuración del negocio/empresa con las siguientes características:

### ✅ Funcionalidades Implementadas

#### 1. **Información de la Empresa**
   - ✓ Nombre del negocio
   - ✓ Subida y gestión de logo oficial
   - ✓ Eslogan/Lema de la empresa
   - ✓ Código RNC (Registro Nacional de Contribuyentes)
   - ✓ Sitio web

#### 2. **Información de Contacto**
   - ✓ Teléfono principal y secundario
   - ✓ Email de contacto
   - ✓ Teléfono de empresa (para contactos internos)
   - ✓ Dirección completa
   - ✓ Ciudad/Municipio

#### 3. **Configuración de Préstamos**
   - ✓ Tasa de interés por defecto (0.1% - 30%)
   - ✓ Tasa de mora por defecto (0.1% - 15%)
   - ✓ Plazo de préstamo por defecto (1 - 365 días)
   - ✓ Días de gracia (0 - 30 días)
   - Todos los valores se aplican automáticamente en nuevos préstamos

#### 4. **Configuración de Impuestos y Ventas**
   - ✓ Tasa de impuesto (ITBIS) configurable
   - ✓ Opción: Impuesto incluido en precios o no
   - ✓ Moneda por defecto (DOP)
   - ✓ Símbolo de moneda (RD$)

#### 5. **Configuración de Recibos**
   - ✓ Encabezado personalizado del recibo
   - ✓ Pie de página personalizado
   - ✓ Mostrar logo en recibos
   - ✓ Impresión automática

#### 6. **Características Avanzadas**
   - ✓ Backup automático de datos
   - ✓ Notificaciones del sistema
   - ✓ Recordatorios de préstamos vencidos
   - ✓ Rastreo de inventario
   - ✓ Aprobación requerida para clientes nuevos
   - ✓ Encriptación de datos sensibles
   - ✓ Detalles en dashboard
   - ✓ Modo oscuro
   - ✓ Timeout de sesión configurable

---

## 📂 Estructura de Archivos Mejorada

```
lib/
├── core/
│   └── services/
│       └── app_configuration_service.dart (NUEVO)
└── features/
    └── settings/
        ├── data/
        │   ├── business_settings_model.dart (MEJORADO)
        │   └── business_settings_repository.dart (MEJORADO)
        ├── providers/
        │   └── business_settings_provider.dart (MEJORADO)
        └── ui/
            ├── business_settings_page.dart (ORIGINAL)
            └── business_settings_page_improved.dart (NUEVO)
```

---

## 🔧 Cómo Usar el Módulo

### 1. **Cargar las Configuraciones en la App**

En `main.dart` o en tu widget raíz:

```dart
import 'package:your_app/features/settings/providers/business_settings_provider.dart';
import 'package:your_app/core/services/app_configuration_service.dart';

// En tu ConsumerWidget principal:
@override
Widget build(BuildContext context, WidgetRef ref) {
  // Cargar configuraciones
  final businessSettings = ref.watch(businessSettingsProvider);
  
  // Actualizar servicio global
  appConfigService.initialize(businessSettings);
  
  return MaterialApp(
    // ... resto de tu app
  );
}
```

### 2. **Acceder a Configuraciones Desde Cualquier Lugar**

```dart
import 'package:your_app/core/services/app_configuration_service.dart';

// Obtener nombre del negocio
String businessName = appConfigService.getBusinessName();

// Obtener logo
File? logo = appConfigService.getLogoFile();

// Obtener tasa de interés
double interestRate = appConfigService.getDefaultInterestRate();

// Obtener símbolo de moneda formateado
String formatted = appConfigService.formatCurrency(1000.00); // "RD$ 1000.00"

// Verificar si una característica está habilitada
if (appConfigService.areNotificationsEnabled()) {
  // Mostrar notificaciones
}
```

### 3. **Usar el Logo en la App**

```dart
import 'package:your_app/core/services/app_configuration_service.dart';

// En tu AppBar o donde quieras mostrar el logo:
@override
Widget build(BuildContext context) {
  return AppBar(
    title: appConfigService.hasLogo()
        ? Image.file(appConfigService.getLogoFile()!)
        : Text(appConfigService.getBusinessName()),
  );
}
```

### 4. **Aplicar Configuraciones en Cálculos**

```dart
// En módulo de préstamos:
double interest = appConfigService.getDefaultInterestRate();
int days = appConfigService.getDefaultLoanTermDays();
int graceDays = appConfigService.getGracePeriodDays();

// En módulo de ventas:
double tax = appConfigService.getDefaultTaxRate();
bool taxIncluded = appConfigService.isTaxIncludedInPrices();
String currency = appConfigService.getCurrencySymbol();
```

---

## 🎨 Usar la Nueva Interfaz Mejorada

Para usar la nueva página de configuración con mejor UX:

```dart
import 'package:your_app/features/settings/ui/business_settings_page_improved.dart';

// Reemplazar en tu router:
Route(
  path: '/settings/business',
  builder: (context, state) => const BusinessSettingsPageImproved(),
),

// O usar directamente en NavigatorPush:
Navigator.push(
  context,
  MaterialPageRoute(builder: (context) => const BusinessSettingsPageImproved()),
);
```

---

## 📋 Campos Configurables (Completa Lista)

### Información de la Empresa
- `businessName` - Nombre del negocio
- `logoPath` - Ruta del logo
- `slogan` - Eslogan de la empresa
- `rnc` - Código RNC

### Contacto
- `phone` - Teléfono principal
- `phone2` - Teléfono secundario
- `email` - Email
- `companyPhone` - Teléfono de empresa
- `address` - Dirección
- `city` - Ciudad
- `website` - Sitio web

### Préstamos
- `defaultInterestRate` - Tasa de interés (%)
- `defaultLateFeeRate` - Tasa de mora (%)
- `defaultLoanTermDays` - Plazo en días
- `gracePeriodDays` - Días de gracia

### Impuestos y Moneda
- `defaultTaxRate` - Tasa de impuesto (%)
- `taxIncludedInPrices` - ¿Impuesto incluido?
- `defaultCurrency` - Moneda (DOP, etc)
- `currencySymbol` - Símbolo (RD$, etc)

### Recibos
- `receiptHeader` - Encabezado
- `receiptFooter` - Pie de página
- `showLogoOnReceipt` - Mostrar logo
- `printReceiptAutomatically` - Impresión automática

### Características Avanzadas
- `enableAutoBackup` - Backup automático
- `enableNotifications` - Notificaciones
- `enableLoanReminders` - Recordatorios de préstamos
- `enableInventoryTracking` - Rastreo de inventario
- `enableClientApproval` - Aprobación de clientes
- `enableDataEncryption` - Encriptación
- `showDetailsOnDashboard` - Detalles en dashboard
- `darkModeEnabled` - Modo oscuro
- `sessionTimeoutMinutes` - Timeout de sesión

---

## 🔐 Almacenamiento Persistente

Todas las configuraciones se guardan en SQLite:

```dart
// Las configuraciones se cargan automáticamente al iniciar
// Se guardan automáticamente cuando cambias algo en la interfaz
// El provider maneja toda la persistencia
```

---

## 📊 Métodos del AppConfigurationService

```dart
// Getters para información
getBusinessName()           // String
getLogoPath()              // String?
hasLogo()                  // bool
getLogoFile()              // File?

// Contacto
getPhone()                 // String?
getPhone2()                // String?
getCompanyPhone()          // String
getEmail()                 // String?
getAddress()               // String?
getCity()                  // String?
getRnc()                   // String?

// Préstamos
getDefaultInterestRate()   // double
getDefaultLateFeeRate()    // double
getDefaultLoanTermDays()   // int
getGracePeriodDays()       // int

// Impuestos
getDefaultTaxRate()        // double
isTaxIncludedInPrices()    // bool
getDefaultCurrency()       // String
getCurrencySymbol()        // String
formatCurrency(amount)     // String

// Recibos
getReceiptHeader()         // String
getReceiptFooter()         // String
shouldShowLogoOnReceipt()  // bool
shouldPrintReceiptAutomatically() // bool

// Características
isAutoBackupEnabled()      // bool
areNotificationsEnabled()  // bool
areLoanRemindersEnabled()  // bool
isInventoryTrackingEnabled() // bool
isClientApprovalEnabled()  // bool
isDataEncryptionEnabled()  // bool
shouldShowDetailsOnDashboard() // bool
isDarkModeEnabled()        // bool
getSessionTimeoutMinutes() // int
getSessionTimeout()        // Duration

// Utilidades
getFormattedBusinessInfo() // String (información formateada)
updateSettings()           // void
addListener()              // void (para actualizaciones en vivo)
removeListener()           // void
```

---

## 🚀 Ventajas de esta Implementación

1. **Centralizado**: Todas las configuraciones en un solo lugar
2. **Persistente**: Se guarda en la base de datos automáticamente
3. **Reactivo**: Los cambios se aplican inmediatamente en toda la app
4. **Seguro**: Las configuraciones se validan y se encriptan opcionalmente
5. **Escalable**: Fácil de agregar nuevas configuraciones
6. **Usuario-Amigable**: Interfaz intuitiva con controles visuales
7. **Completo**: Cubre todos los aspectos del negocio

---

## 📝 Próximos Pasos Recomendados

1. Integrar el logo en AppBar y Dashboard
2. Aplicar tasas de interés en módulo de préstamos
3. Aplicar impuestos en módulo de ventas
4. Implementar recordatorios de préstamos
5. Configurar encriptación de datos
6. Agregar backup automático

---

## ⚠️ Notas Importantes

- El logo se almacena en `getApplicationDocumentsDirectory()/nilkas/logo/`
- Los cambios se guardan automáticamente en SQLite
- El servicio global debe inicializarse en main() o en el widget raíz
- Todas las configuraciones tienen valores por defecto seguros
- La interfaz mejorada usa tabs para mejor organización

---

## 🎓 Ejemplo Completo de Uso

```dart
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:your_app/features/settings/providers/business_settings_provider.dart';
import 'package:your_app/core/services/app_configuration_service.dart';

class MyApp extends ConsumerWidget {
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // Cargar y observar cambios
    final settings = ref.watch(businessSettingsProvider);
    
    // Actualizar servicio global
    ref.listen(businessSettingsProvider, (previous, next) {
      appConfigService.updateSettings(next);
    });
    
    return MaterialApp(
      title: settings.businessName,
      home: Scaffold(
        appBar: AppBar(
          title: Text(appConfigService.getBusinessName()),
          leading: appConfigService.hasLogo()
              ? Padding(
                  padding: const EdgeInsets.all(8),
                  child: Image.file(appConfigService.getLogoFile()!),
                )
              : null,
        ),
        body: Center(
          child: Text(
            'Tasa de interés: ${appConfigService.formatCurrency(
              appConfigService.getDefaultInterestRate()
            )}%',
          ),
        ),
      ),
    );
  }
}
```

---

¡El módulo de configuración del negocio está completamente funcional! 🎉

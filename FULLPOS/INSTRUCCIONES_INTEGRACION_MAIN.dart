// ============================================
// INSTRUCCIONES DE INTEGRACIÓN EN MAIN.DART
// ============================================
// 
// Este archivo muestra exactamente cómo integrar
// el nuevo sistema de configuraciones en tu main.dart
//
// ⚠️ NOTA: Este es un archivo de DOCUMENTACIÓN/EJEMPLO
// Copia el código dentro de tu main.dart real, no ejecutes este archivo directamente.
//

/*
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'dart:io';

// Importar todo lo necesario
import 'core/services/app_configuration_service.dart';
import 'features/settings/providers/business_settings_provider.dart';
import 'app/app.dart';

void main() async {
  // Asegurar que Flutter está inicializado
  WidgetsFlutterBinding.ensureInitialized();

  // Inicializar base de datos
  // DbInit.ensureInitialized();

  // Inicializar Window Manager si es desktop
  // if (Platform.isWindows || Platform.isLinux || Platform.isMacOS) {
  //   await WindowService.init();
  // }

  // Ejecutar la aplicación con ProviderScope
  // Así se cargan las configuraciones automáticamente
  runApp(const ProviderScope(child: LosFULLPOSApp()));
}

// ============================================
// OPCIÓN 1: Inicializar en el Widget Raíz
// ============================================
class LosFULLPOSApp extends ConsumerWidget {
  const LosFULLPOSApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // ✅ Cargar las configuraciones del negocio
    final businessSettings = ref.watch(businessSettingsProvider);
    
    // ✅ Actualizar el servicio global con las configuraciones
    ref.listen(businessSettingsProvider, (previous, next) {
      appConfigService.updateSettings(next);
    });

    return MaterialApp(
      title: businessSettings.businessName,
      
      // ✅ Usar el nombre del negocio en la app
      home: const MyHomePage(),
      
      // Opcional: Aplicar tema oscuro si está configurado
      theme: ThemeData.light(),
      darkTheme: ThemeData.dark(),
      themeMode: businessSettings.darkModeEnabled ? ThemeMode.dark : ThemeMode.light,
    );
  }
}

// ============================================
// RESUMEN RÁPIDO
// ============================================
/*// ============================================
// OPCIÓN 2: Usar en un Widget Específico
// ============================================
class MyHomePage extends ConsumerStatefulWidget {
  const MyHomePage({super.key});

  @override
  ConsumerState<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends ConsumerState<MyHomePage> {
  @override
  Widget build(BuildContext context) {
    // Observar cambios en las configuraciones
    final settings = ref.watch(businessSettingsProvider);
    
    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            // ✅ Mostrar logo si existe
            if (settings.logoPath != null && File(settings.logoPath!).existsSync())
              Padding(
                padding: const EdgeInsets.only(right: 12),
                child: Image.file(
                  File(settings.logoPath!),
                  height: 40,
                  width: 40,
                  fit: BoxFit.contain,
                ),
              ),
            // ✅ Mostrar nombre del negocio
            Text(settings.businessName),
          ],
        ),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            // ✅ Acceder a configuraciones desde aquí
            Text(
              'Tasa de Interés por Defecto:',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 16),
            Text(
              '${settings.defaultInterestRate}%',
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            const SizedBox(height: 32),
            
            // ✅ Usar el servicio global de configuración
            Text(
              'Moneda: ${appConfigService.getCurrencySymbol()}',
            ),
          ],
        ),
      ),
    );
  }
}

// ============================================
// OPCIÓN 3: Usar en Business Logic (Provider)
// ============================================
import 'features/loans/data/loans_model.dart';

final createLoanProvider = FutureProvider.family<LoanModel, double>(
  (ref, amount) async {
    // ✅ Obtener configuraciones en el provider
    final settings = ref.watch(businessSettingsProvider);
    
    // ✅ Usar configuraciones para crear el préstamo
    final interest = amount * 
        (settings.defaultInterestRate / 100) * 
        (settings.defaultLoanTermDays / 365);
    
    final loan = LoanModel(
      amount: amount,
      interest: interest,
      days: settings.defaultLoanTermDays,
      gracePeriodDays: settings.gracePeriodDays,
    );
    
    return loan;
  },
);

// ============================================
// OPCIÓN 4: Usar el Servicio Global Directamente
// ============================================
class ReceiptGenerator {
  static String generateReceipt(String clientName, double amount) {
    // ✅ Acceder directamente sin necesidad de Riverpod
    final businessName = appConfigService.getBusinessName();
    final currencySymbol = appConfigService.getCurrencySymbol();
    final interestRate = appConfigService.getDefaultInterestRate();
    final logo = appConfigService.getLogoFile();
    
    return '''
╔════════════════════════════════════════╗
║  $businessName
╚════════════════════════════════════════╝

RECIBO DE PRÉSTAMO

Cliente: $clientName
Monto: $currencySymbol ${amount.toStringAsFixed(2)}
Tasa de Interés: $interestRate%

${logo != null && appConfigService.shouldShowLogoOnReceipt() ? 
  '┌──────────┐\n│   LOGO   │\n└──────────┘' : 
  '(Sin logo)'}

${appConfigService.getReceiptFooter()}

═════════════════════════════════════════
    ''';
  }
}

// ============================================
// OPCIÓN 5: Usar con BusinessConfigHelper
// ============================================
import 'core/helpers/business_config_helper.dart';

class LoanService {
  Future<void> createLoan(double amount, int days) async {
    // ✅ Usar helper para cálculos
    final interest = BusinessConfigHelper.calculateSimpleInterest(
      amount: amount,
      days: days,
    );
    
    final total = BusinessConfigHelper.calculateTotalWithInterest(
      amount: amount,
      days: days,
    );
    
    final formatted = BusinessConfigHelper.formatMoney(total);
    
    print('Total a pagar: $formatted');
  }
}

// ============================================
// OPCIÓN 6: Escuchar Cambios en Configuración
// ============================================
class ConfigurationListener {
  void setupListeners() {
    // ✅ Escuchar cambios en las configuraciones
    appConfigService.addListener(() {
      // Se ejecuta cada vez que cambian las configuraciones
      print('Configuraciones actualizadas');
      
      // Aquí puedes actualizar la UI, reiniciar servicios, etc.
    });
  }
  
  void cleanup() {
    // ✅ Remover listeners cuando ya no se necesitan
    // appConfigService.removeListener(myCallback);
  }
}

// ============================================
// EJEMPLO COMPLETO EN UN WIDGET
// ============================================
class BusinessConfigurationExample extends ConsumerStatefulWidget {
  const BusinessConfigurationExample({super.key});

  @override
  ConsumerState<BusinessConfigurationExample> createState() =>
      _BusinessConfigurationExampleState();
}

class _BusinessConfigurationExampleState
    extends ConsumerState<BusinessConfigurationExample> {
  late final Function() _listener;

  @override
  void initState() {
    super.initState();
    
    // ✅ Escuchar cambios globales de configuración
    _listener = () {
      setState(() {
        // Rebuild cuando cambien las configuraciones
      });
    };
    appConfigService.addListener(_listener);
  }

  @override
  void dispose() {
    appConfigService.removeListener(_listener);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    // ✅ Observar cambios con Riverpod también
    final settings = ref.watch(businessSettingsProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Ejemplo de Configuraciones'),
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Información de la Empresa
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Información del Negocio',
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Text('Nombre: ${appConfigService.getBusinessName()}'),
                  Text('RNC: ${appConfigService.getRnc() ?? 'No configurado'}'),
                  Text('Email: ${appConfigService.getEmail() ?? 'No configurado'}'),
                  Text('Teléfono: ${appConfigService.getPhone() ?? 'No configurado'}'),
                  if (appConfigService.hasLogo())
                    Padding(
                      padding: const EdgeInsets.only(top: 12),
                      child: SizedBox(
                        height: 100,
                        child: Image.file(appConfigService.getLogoFile()!),
                      ),
                    ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),

          // Configuración de Préstamos
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Configuración de Préstamos',
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Text(
                    'Tasa de Interés: ${appConfigService.getDefaultInterestRate()}%',
                  ),
                  Text(
                    'Tasa de Mora: ${appConfigService.getDefaultLateFeeRate()}%',
                  ),
                  Text(
                    'Plazo: ${appConfigService.getDefaultLoanTermDays()} días',
                  ),
                  Text(
                    'Período de Gracia: ${appConfigService.getGracePeriodDays()} días',
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),

          // Configuración de Ventas
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Configuración de Ventas',
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Text(
                    'Tasa de Impuesto: ${appConfigService.getDefaultTaxRate()}%',
                  ),
                  Text(
                    'Moneda: ${appConfigService.getDefaultCurrency()} (${appConfigService.getCurrencySymbol()})',
                  ),
                  Text(
                    'Impuesto Incluido: ${appConfigService.isTaxIncludedInPrices() ? 'Sí' : 'No'}',
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),

          // Características Avanzadas
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Características Habilitadas',
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(height: 12),
                  _buildFeatureItem(
                    'Notificaciones',
                    appConfigService.areNotificationsEnabled(),
                  ),
                  _buildFeatureItem(
                    'Recordatorios de Préstamos',
                    appConfigService.areLoanRemindersEnabled(),
                  ),
                  _buildFeatureItem(
                    'Backup Automático',
                    appConfigService.isAutoBackupEnabled(),
                  ),
                  _buildFeatureItem(
                    'Rastreo de Inventario',
                    appConfigService.isInventoryTrackingEnabled(),
                  ),
                  _buildFeatureItem(
                    'Modo Oscuro',
                    appConfigService.isDarkModeEnabled(),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFeatureItem(String label, bool enabled) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label),
          Icon(
            enabled ? Icons.check_circle : Icons.cancel,
            color: enabled ? Colors.green : Colors.red,
          ),
        ],
      ),
    );
  }
}

// ============================================
// NOTAS IMPORTANTES
// ============================================
// 
// 1. Siempre importar:
//    - import 'core/services/app_configuration_service.dart';
//    - import 'features/settings/providers/business_settings_provider.dart';
//
// 2. Inicializar appConfigService en main() o en el widget raíz
//
// 3. Usar ref.watch(businessSettingsProvider) en Widgets para
//    obtener actualizaciones en vivo
//
// 4. Usar appConfigService directamente en clases que no son widgets
//
// 5. Usar BusinessConfigHelper para cálculos financieros
//
// */
// 6. Los cambios se guardan automáticamente en la BD
//
// 7. El servicio es un Singleton - la misma instancia en toda la app
//
// ============================================*/
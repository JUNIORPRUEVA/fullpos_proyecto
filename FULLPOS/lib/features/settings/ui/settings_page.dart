import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../../core/services/app_configuration_service.dart';
import '../../../core/db/app_db.dart';
import 'package:printing/printing.dart';
import '../../../core/constants/app_colors.dart';
import '../../../core/printing/unified_ticket_printer.dart';
import '../data/printer_settings_model.dart';
import '../data/printer_settings_repository.dart';
import 'backup_settings_page.dart';
import 'users_page.dart';
import 'theme_settings_page.dart' as theme_page;
import 'business_settings_page.dart';
import 'logs_page.dart';
import 'security_settings_page.dart';
import 'cloud_settings_page.dart';

/// Pantalla de configuración con diseño de tarjetas
class SettingsPage extends StatefulWidget {
  const SettingsPage({super.key});

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadSettings();
  }

  Future<void> _loadSettings() async {
    if (!mounted) return;
    setState(() => _isLoading = false);
  }

  @override
  Widget build(BuildContext context) {
    if (_isLoading) {
      return const Center(child: CircularProgressIndicator());
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Encabezado compacto
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          child: Row(
            children: [
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: AppColors.gold.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: const Icon(
                  Icons.settings,
                  size: 24,
                  color: AppColors.gold,
                ),
              ),
              const SizedBox(width: 12),
              const Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'CONFIGURACIÓN',
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 20,
                      fontWeight: FontWeight.bold,
                      letterSpacing: 1,
                    ),
                  ),
                  Text(
                    'Personaliza tu sistema POS',
                    style: TextStyle(color: Colors.grey, fontSize: 12),
                  ),
                ],
              ),
            ],
          ),
        ),

        // Grid de módulos
        Expanded(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: LayoutBuilder(
              builder: (context, constraints) {
                int crossAxisCount = constraints.maxWidth > 1200
                    ? 6
                    : (constraints.maxWidth > 950
                        ? 5
                        : (constraints.maxWidth > 700 ? 4 : 3));

                return GridView.count(
                  crossAxisCount: crossAxisCount,
                  mainAxisSpacing: 10,
                  crossAxisSpacing: 10,
                  childAspectRatio: 1.9,
                  children: [
                    // Impresora
                    _buildSettingsCard(
                      icon: Icons.print,
                      title: 'IMPRESORA',
                      subtitle: 'Tickets',
                      description: 'Configura impresoras y prueba de impresión.',
                      color: Colors.orange,
                      onTap: () => _showPrinterDialog(),
                    ),

                    // Usuarios
                    _buildSettingsCard(
                      icon: Icons.people,
                      title: 'USUARIOS',
                      subtitle: 'Accesos',
                      description: 'Roles, permisos y gestión de cuentas.',
                      color: Colors.blue,
                      onTap: () => _openUsersPage(),
                    ),

                    // Seguridad / Overrides
                    _buildSettingsCard(
                      icon: Icons.shield,
                      title: 'SEGURIDAD',
                      subtitle: 'Overrides',
                      description: 'PIN, códigos locales y autorizaciones.',
                      color: Colors.green,
                      onTap: () => _openSecuritySettingsPage(),
                    ),

                    // Cloud / Nube
                    _buildSettingsCard(
                      icon: Icons.cloud,
                      title: 'NUBE',
                      subtitle: 'Accesos & Owner',
                      description: 'Sincronización y acceso del propietario.',
                      color: Colors.lightBlue,
                      onTap: () => _openCloudSettingsPage(),
                    ),

                    // Negocio
                    _buildSettingsCard(
                      icon: Icons.store,
                      title: 'NEGOCIO',
                      subtitle: 'Empresa',
                      description: 'Datos fiscales, contacto y monedas.',
                      color: Colors.purple,
                      onTap: () => _openBusinessSettingsPage(),
                    ),

                    // Backup
                    _buildSettingsCard(
                      icon: Icons.storage,
                      title: 'BACKUP',
                      subtitle: 'Datos',
                      description: 'Respaldos y restauración del sistema.',
                      color: Colors.indigo,
                      onTap: () => _openBackupPage(),
                    ),

                    // Apariencia
                    _buildSettingsCard(
                      icon: Icons.palette,
                      title: 'TEMA',
                      subtitle: 'Colores',
                      description: 'Personaliza colores y estilos visuales.',
                      color: Colors.pink,
                      onTap: () => _openThemeSettings(),
                    ),

                    // Acerca de
                    _buildSettingsCard(
                      icon: Icons.info,
                      title: 'ACERCA DE',
                      subtitle: 'v1.0.0',
                      description: 'Información del sistema y atajos.',
                      color: Colors.grey,
                      onTap: () => _showAboutDialog(),
                    ),

                    // Logs / Soporte
                    _buildSettingsCard(
                      icon: Icons.support_agent,
                      title: 'SOPORTE',
                      subtitle: 'Logs',
                      description: 'Diagnósticos y registro de eventos.',
                      color: Colors.green,
                      onTap: () => _openLogsPage(),
                    ),
                  ],
                );
              },
            ),
          ),
        ),
      ],
    );
  }

  void _openUsersPage() {
    Navigator.push(
      context,
      MaterialPageRoute(builder: (_) => const UsersPage()),
    );
  }

  void _openSecuritySettingsPage() {
    Navigator.push(
      context,
      MaterialPageRoute(builder: (_) => const SecuritySettingsPage()),
    );
  }

  void _openCloudSettingsPage() {
    Navigator.push(
      context,
      MaterialPageRoute(builder: (_) => const CloudSettingsPage()),
    );
  }

  void _openThemeSettings() {
    Navigator.push(
      context,
      MaterialPageRoute(builder: (_) => const theme_page.ThemeSettingsPage()),
    );
  }

  void _openBusinessSettingsPage({int tabIndex = 0}) {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => BusinessSettingsPage(initialTabIndex: tabIndex),
      ),
    );
  }

  void _openLogsPage() {
    Navigator.push(
      context,
      MaterialPageRoute(builder: (_) => const LogsPage()),
    );
  }

  void _openBackupPage() {
    Navigator.push(
      context,
      MaterialPageRoute(builder: (_) => const BackupSettingsPage()),
    );
  }

  Widget _buildSettingsCard({
    required IconData icon,
    required String title,
    required String subtitle,
    required String description,
    required Color color,
    String? badge,
    required VoidCallback onTap,
  }) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(12),
        child: Container(
          decoration: BoxDecoration(
            color: Colors.white,
            borderRadius: BorderRadius.circular(12),
            boxShadow: [
              BoxShadow(
                color: color.withOpacity(0.08),
                blurRadius: 10,
                offset: const Offset(0, 3),
              ),
            ],
            border: Border.all(color: color.withOpacity(0.12), width: 1),
          ),
          child: Stack(
            children: [
              // Fondo decorativo
              Positioned(
                right: -15,
                bottom: -15,
                child: Icon(icon, size: 50, color: color.withOpacity(0.06)),
              ),

              // Contenido
              Padding(
                padding: const EdgeInsets.all(10),
                child: Row(
                  children: [
                    // Icono
                    Container(
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: color.withOpacity(0.12),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Icon(icon, color: color, size: 20),
                    ),
                    const SizedBox(width: 10),
                    // Textos
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Text(
                            title,
                            style: TextStyle(
                              fontSize: 11,
                              fontWeight: FontWeight.bold,
                              color: Colors.grey.shade800,
                              letterSpacing: 0.3,
                            ),
                          ),
                          Text(
                            subtitle,
                            style: TextStyle(
                              fontSize: 9,
                              color: Colors.grey.shade500,
                            ),
                          ),
                          const SizedBox(height: 2),
                          Text(
                            description,
                            maxLines: 2,
                            overflow: TextOverflow.ellipsis,
                            style: TextStyle(
                              fontSize: 9,
                              color: Colors.grey.shade600,
                            ),
                          ),
                        ],
                      ),
                    ),
                    // Flecha
                    Icon(
                      Icons.chevron_right,
                      size: 16,
                      color: color.withOpacity(0.4),
                    ),
                  ],
                ),
              ),

              // Badge
              if (badge != null)
                Positioned(
                  top: 6,
                  right: 6,
                  child: Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 5,
                      vertical: 2,
                    ),
                    decoration: BoxDecoration(
                      color: Colors.green,
                      borderRadius: BorderRadius.circular(6),
                    ),
                    child: Text(
                      badge,
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 7,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }


  Widget _buildShortcutSection(String title, List<String> shortcuts) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
        ),
        const SizedBox(height: 8),
        ...shortcuts.map(
          (s) => Padding(
            padding: const EdgeInsets.only(bottom: 4),
            child: Text(s, style: const TextStyle(fontSize: 12)),
          ),
        ),
      ],
    );
  }

  void _showDatabaseDialog() {
    showDialog(
      context: context,
      builder: (context) => Dialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        child: Container(
          width: 400,
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.indigo.withOpacity(0.1),
                  shape: BoxShape.circle,
                ),
                child: const Icon(
                  Icons.storage,
                  color: Colors.indigo,
                  size: 40,
                ),
              ),
              const SizedBox(height: 16),
              const Text(
                'BASE DE DATOS',
                style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 8),
              Text(
                'SQLite Local • ${AppDb.dbFileName}',
                style: TextStyle(color: Colors.grey.shade600, fontSize: 12),
              ),
              const SizedBox(height: 24),

              // Acciones
              Row(
                children: [
                  Expanded(
                    child: _buildActionButton(
                      icon: Icons.backup,
                      label: 'BACKUP',
                      color: Colors.green,
                      onTap: () => _showComingSoon('Backup'),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: _buildActionButton(
                      icon: Icons.restore,
                      label: 'RESTAURAR',
                      color: Colors.orange,
                      onTap: () => _showComingSoon('Restaurar'),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              SizedBox(
                width: double.infinity,
                child: _buildActionButton(
                  icon: Icons.delete_forever,
                  label: 'RESETEAR TODO',
                  color: Colors.red,
                  onTap: () => _showComingSoon('Reset'),
                ),
              ),

              if (kDebugMode) ...[
                const SizedBox(height: 16),
                const Divider(),
                const SizedBox(height: 12),
                Align(
                  alignment: Alignment.centerLeft,
                  child: Text(
                    AppDb.isUsingTestDb
                        ? 'DEBUG (DB TEST ACTIVA)'
                        : 'DEBUG (DB PROD)',
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                      color: Colors.grey.shade700,
                      fontSize: 12,
                    ),
                  ),
                ),
                const SizedBox(height: 10),
                if (AppDb.isUsingTestDb)
                  SizedBox(
                    width: double.infinity,
                    child: _buildActionButton(
                      icon: Icons.science,
                      label: 'SIMULAR DB VIEJA (TEST)',
                      color: Colors.indigo,
                      onTap: () async {
                        await AppDb.resetTestDbToLegacySchema();
                        if (!mounted) return;
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(
                            content: Text(
                              'DB test vieja creada. Reinicia la pantalla o reabre la app para aplicar migración.',
                            ),
                          ),
                        );
                      },
                    ),
                  )
                else
                  Text(
                    'Para usar DB test: ejecuta con --dart-define=USE_TEST_DB=true',
                    style: TextStyle(color: Colors.grey.shade600, fontSize: 12),
                  ),
                const SizedBox(height: 10),
                SizedBox(
                  width: double.infinity,
                  child: _buildActionButton(
                    icon: Icons.rule,
                    label: 'VERIFICAR COLUMNA user_id',
                    color: Colors.teal,
                    onTap: () async {
                      final ok = await AppDb.verifyStockMovementsColumns();
                      if (!mounted) return;
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(
                          content: Text(
                            ok
                                ? 'OK: stock_movements tiene user_id'
                                : 'ERROR: stock_movements NO tiene user_id',
                          ),
                        ),
                      );
                    },
                  ),
                ),

                const SizedBox(height: 10),
                SizedBox(
                  width: double.infinity,
                  child: _buildActionButton(
                    icon: Icons.health_and_safety,
                    label: 'DIAGNOSTICAR DB (INTEGRIDAD)',
                    color: Colors.deepPurple,
                    onTap: () async {
                      final result = await AppDb.runDbDiagnostics();
                      if (!mounted) return;
                      final ok = result['ok'] == true;
                      final integrity = result['integrity'] ?? 'unknown';
                      final missingColumns =
                          (result['missingColumns'] as List?)?.join(', ') ?? '';
                      final missingTables =
                          (result['missingTables'] as List?)?.join(', ') ?? '';
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(
                          content: Text(
                            ok
                                ? 'OK: DB íntegra (integrity=$integrity)'
                                : 'ERROR DB: integrity=$integrity; missingTables=[$missingTables]; missingColumns=[$missingColumns]',
                          ),
                          duration: const Duration(seconds: 6),
                        ),
                      );
                    },
                  ),
                ),
              ],

              const SizedBox(height: 16),
              TextButton(
                onPressed: () => Navigator.pop(context),
                child: const Text('CERRAR'),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildActionButton({
    required IconData icon,
    required String label,
    required Color color,
    required VoidCallback onTap,
  }) {
    return Material(
      color: color.withOpacity(0.1),
      borderRadius: BorderRadius.circular(10),
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(10),
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 14, horizontal: 16),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(icon, color: color, size: 20),
              const SizedBox(width: 8),
              Text(
                label,
                style: TextStyle(
                  color: color,
                  fontWeight: FontWeight.bold,
                  fontSize: 12,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _showAboutDialog() {
    final businessName = appConfigService.getBusinessName().trim().isNotEmpty
        ? appConfigService.getBusinessName().trim()
        : 'FULLPOS';
    final year = DateTime.now().year;

    showDialog(
      context: context,
      builder: (context) => Dialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        child: Container(
          width: 350,
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [AppColors.gold, Colors.teal],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  ),
                  shape: BoxShape.circle,
                ),
                child: const Icon(
                  Icons.point_of_sale,
                  color: Colors.white,
                  size: 48,
                ),
              ),
              const SizedBox(height: 20),
              Text(
                businessName,
                style: TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 2,
                ),
              ),
              const Text(
                'SISTEMA POS',
                style: TextStyle(
                  fontSize: 14,
                  color: Colors.grey,
                  letterSpacing: 3,
                ),
              ),
              const SizedBox(height: 24),
              Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 20,
                  vertical: 8,
                ),
                decoration: BoxDecoration(
                  color: Colors.teal.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(20),
                ),
                child: const Text(
                  'v1.0.0 LOCAL',
                  style: TextStyle(
                    color: Colors.teal,
                    fontWeight: FontWeight.bold,
                    fontSize: 12,
                  ),
                ),
              ),
              const SizedBox(height: 20),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.grey.shade50,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: Colors.grey.shade200),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'ATAJOS',
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
                        fontSize: 12,
                        letterSpacing: 0.6,
                      ),
                    ),
                    const SizedBox(height: 10),
                    _buildShortcutSection('GLOBALES', [
                      'Ctrl+Shift+F - Pantalla completa',
                      'Ctrl+Q - Cerrar app',
                      'ESC - Cerrar diálogos',
                    ]),
                    const SizedBox(height: 12),
                    _buildShortcutSection('VENTAS', [
                      'F2 - Enfocar búsqueda',
                      'F3 - Seleccionar cliente',
                      'F4 - Nuevo cliente',
                      'F7 - Aplicar descuento',
                      'F9 - Abrir pago',
                      'F12 - Finalizar venta',
                      '+ / - - Cambiar cantidad',
                      'Ctrl+Backspace - Eliminar item',
                    ]),
                  ],
                ),
              ),
              const SizedBox(height: 20),
              Text(
                '© $year $businessName',
                style: TextStyle(color: Colors.grey.shade500, fontSize: 11),
              ),
              const SizedBox(height: 20),
              TextButton(
                onPressed: () => Navigator.pop(context),
                child: const Text('CERRAR'),
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _showPrinterDialog() {
    showDialog(
      context: context,
      builder: (context) => _PrinterDialogContent(
        onConfigurePressed: () {
          Navigator.pop(context);
          context.push('/settings/printer');
        },
      ),
    );
  }

  void _showComingSoon(String feature) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Row(
          children: [
            const Icon(Icons.construction, color: Colors.white, size: 20),
            const SizedBox(width: 12),
            Text('$feature - Próximamente'),
          ],
        ),
        backgroundColor: Colors.orange.shade700,
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
        duration: const Duration(seconds: 2),
      ),
    );
  }
}

/// Diálogo de impresora con StatefulBuilder para manejar estado interno
class _PrinterDialogContent extends StatefulWidget {
  final VoidCallback onConfigurePressed;

  const _PrinterDialogContent({required this.onConfigurePressed});

  @override
  State<_PrinterDialogContent> createState() => _PrinterDialogContentState();
}

class _PrinterDialogContentState extends State<_PrinterDialogContent> {
  List<Printer> _printers = [];
  PrinterSettingsModel? _settings;
  bool _loading = true;
  bool _printing = false;
  String? _selectedPrinter;

  @override
  void initState() {
    super.initState();
    _loadData();
  }

  Future<void> _loadData() async {
    final printers = await UnifiedTicketPrinter.getAvailablePrinters();
    final settings = await PrinterSettingsRepository.getOrCreate();

    setState(() {
      _printers = printers;
      _settings = settings;
      _selectedPrinter = settings.selectedPrinterName;
      _loading = false;
    });
  }

  Future<void> _printTest() async {
    if (_selectedPrinter == null || _selectedPrinter!.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Seleccione una impresora primero'),
          backgroundColor: Colors.orange,
        ),
      );
      return;
    }

    setState(() => _printing = true);

    // Actualizar impresora seleccionada antes de imprimir
    final updatedSettings = _settings!.copyWith(
      selectedPrinterName: _selectedPrinter,
    );
    try {
      await PrinterSettingsRepository.updateSettings(updatedSettings);
    } catch (e) {
      setState(() => _printing = false);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Error guardando impresora: $e'),
            backgroundColor: Colors.red,
            duration: const Duration(seconds: 4),
          ),
        );
      }
      return;
    }

    final result = await UnifiedTicketPrinter.printTestTicket();
    final success = result.success;

    setState(() => _printing = false);

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Row(
            children: [
              Icon(
                success ? Icons.check_circle : Icons.error,
                color: Colors.white,
              ),
              const SizedBox(width: 8),
              Text(
                success
                    ? '✅ Ticket de prueba enviado a la impresora'
                    : '❌ Error al imprimir - Verifique la impresora',
              ),
            ],
          ),
          backgroundColor: success ? Colors.green : Colors.red,
          duration: const Duration(seconds: 3),
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Dialog(
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      child: Container(
        width: 450,
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Header
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.orange.withOpacity(0.1),
                shape: BoxShape.circle,
              ),
              child: const Icon(Icons.print, color: Colors.orange, size: 40),
            ),
            const SizedBox(height: 16),
            const Text(
              'IMPRESORA Y TICKET',
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            Text(
              'Impresión térmica de tickets',
              style: TextStyle(color: Colors.grey.shade600, fontSize: 12),
            ),
            const SizedBox(height: 24),

            if (_loading)
              const Padding(
                padding: EdgeInsets.all(20),
                child: CircularProgressIndicator(),
              )
            else ...[
              // Selector de impresora
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.grey.shade50,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: Colors.grey.shade300),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(
                          Icons.print,
                          color: Colors.grey.shade700,
                          size: 20,
                        ),
                        const SizedBox(width: 8),
                        const Text(
                          'IMPRESORA SELECCIONADA',
                          style: TextStyle(
                            fontWeight: FontWeight.bold,
                            fontSize: 12,
                            letterSpacing: 0.5,
                          ),
                        ),
                        const Spacer(),
                        // Botón refrescar
                        IconButton(
                          icon: const Icon(Icons.refresh, size: 20),
                          onPressed: _loadData,
                          tooltip: 'Actualizar lista',
                          padding: EdgeInsets.zero,
                          constraints: const BoxConstraints(),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),

                    if (_printers.isEmpty)
                      Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: Colors.red.shade50,
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: Row(
                          children: [
                            Icon(
                              Icons.warning,
                              color: Colors.red.shade700,
                              size: 20,
                            ),
                            const SizedBox(width: 8),
                            const Expanded(
                              child: Text(
                                'No se detectaron impresoras.\nConecte una impresora e intente de nuevo.',
                                style: TextStyle(fontSize: 12),
                              ),
                            ),
                          ],
                        ),
                      )
                    else
                      DropdownButtonFormField<String>(
                        value: _printers.any((p) => p.name == _selectedPrinter)
                            ? _selectedPrinter
                            : null,
                        decoration: InputDecoration(
                          border: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(8),
                          ),
                          contentPadding: const EdgeInsets.symmetric(
                            horizontal: 12,
                            vertical: 10,
                          ),
                          hintText: 'Seleccione impresora',
                        ),
                        items: _printers
                            .map(
                              (p) => DropdownMenuItem(
                                value: p.name,
                                child: Text(
                                  p.name,
                                  style: const TextStyle(fontSize: 13),
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                            )
                            .toList(),
                        onChanged: (value) {
                          setState(() => _selectedPrinter = value);
                        },
                      ),

                    const SizedBox(height: 8),
                    Text(
                      '${_printers.length} impresora(s) disponible(s)',
                      style: TextStyle(
                        fontSize: 11,
                        color: Colors.grey.shade600,
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 16),

              // Botón imprimir prueba
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  onPressed: _printing ? null : _printTest,
                  icon: _printing
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            color: Colors.white,
                          ),
                        )
                      : const Icon(Icons.print),
                  label: Text(
                    _printing ? 'IMPRIMIENDO...' : 'IMPRIMIR PÁGINA DE PRUEBA',
                  ),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.green,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 14),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(10),
                    ),
                  ),
                ),
              ),

              const SizedBox(height: 12),

              // Botón configuración completa
              SizedBox(
                width: double.infinity,
                child: OutlinedButton.icon(
                  onPressed: widget.onConfigurePressed,
                  icon: const Icon(Icons.settings),
                  label: const Text('CONFIGURACIÓN COMPLETA'),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: Colors.orange,
                    side: const BorderSide(color: Colors.orange),
                    padding: const EdgeInsets.symmetric(vertical: 14),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(10),
                    ),
                  ),
                ),
              ),
            ],

            const SizedBox(height: 16),
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('CERRAR'),
            ),
          ],
        ),
      ),
    );
  }
}

import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:file_picker/file_picker.dart';
import 'package:path_provider/path_provider.dart';
import 'package:path/path.dart' as p;
import '../providers/business_settings_provider.dart';
import '../data/business_settings_model.dart';
import '../../../core/services/app_configuration_service.dart';
import '../../../core/errors/error_handler.dart';
import '../../../core/window/window_service.dart';

/// Página de configuración del negocio
class BusinessSettingsPage extends ConsumerStatefulWidget {
  final int initialTabIndex;

  const BusinessSettingsPage({super.key, this.initialTabIndex = 0});

  @override
  ConsumerState<BusinessSettingsPage> createState() =>
      _BusinessSettingsPageState();
}

class _BusinessSettingsPageState extends ConsumerState<BusinessSettingsPage>
    with SingleTickerProviderStateMixin {
  late TabController _tabController;

  BusinessSettings _draft = BusinessSettings.defaultSettings;
  String? _pendingLogoSourcePath;

  // Controladores de texto
  final _businessNameController = TextEditingController();
  final _phoneController = TextEditingController();
  final _phone2Controller = TextEditingController();
  final _emailController = TextEditingController();
  final _addressController = TextEditingController();
  final _cityController = TextEditingController();
  final _rncController = TextEditingController();
  final _sloganController = TextEditingController();
  final _websiteController = TextEditingController();
  final _receiptHeaderController = TextEditingController();
  final _receiptFooterController = TextEditingController();
  final _loanContractRepresentativeNameController = TextEditingController();
  final _loanContractRepresentativeCedulaController = TextEditingController();

  bool _isLoading = false;
  bool _hasChanges = false;

  @override
  void initState() {
    super.initState();
    final idx = widget.initialTabIndex.clamp(0, 3);
    _tabController = TabController(length: 4, vsync: this, initialIndex: idx);
    _loadInitialValues(ref.read(businessSettingsProvider));
  }

  void _loadInitialValues(BusinessSettings settings) {
    _draft = settings;
    _pendingLogoSourcePath = null;
    _businessNameController.text = settings.businessName;
    _phoneController.text = settings.phone ?? '';
    _phone2Controller.text = settings.phone2 ?? '';
    _emailController.text = settings.email ?? '';
    _addressController.text = settings.address ?? '';
    _cityController.text = settings.city ?? '';
    _rncController.text = settings.rnc ?? '';
    _sloganController.text = settings.slogan ?? '';
    _websiteController.text = settings.website ?? '';
    _receiptHeaderController.text = settings.receiptHeader;
    _receiptFooterController.text = settings.receiptFooter;
    _loanContractRepresentativeNameController.text =
        settings.loanContractRepresentativeName ?? '';
    _loanContractRepresentativeCedulaController.text =
        settings.loanContractRepresentativeCedula ?? '';
  }

  @override
  void dispose() {
    _tabController.dispose();
    _businessNameController.dispose();
    _phoneController.dispose();
    _phone2Controller.dispose();
    _emailController.dispose();
    _addressController.dispose();
    _cityController.dispose();
    _rncController.dispose();
    _sloganController.dispose();
    _websiteController.dispose();
    _receiptHeaderController.dispose();
    _receiptFooterController.dispose();
    _loanContractRepresentativeNameController.dispose();
    _loanContractRepresentativeCedulaController.dispose();
    super.dispose();
  }

  Future<void> _pickLogo() async {
    try {
      final result = await WindowService.runWithSystemDialog(
        () => FilePicker.platform.pickFiles(
          type: FileType.image,
          allowMultiple: false,
        ),
      );

      if (result != null && result.files.single.path != null) {
        final sourcePath = result.files.single.path!;
        setState(() {
          _pendingLogoSourcePath = sourcePath;
          _draft = _draft.copyWith(logoPath: sourcePath);
          _hasChanges = true;
        });

        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Logo seleccionado (recuerda GUARDAR TODO)'),
              backgroundColor: Colors.green,
            ),
          );
        }
      }
    } catch (e, st) {
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: _pickLogo,
          module: 'settings/business/logo',
        );
      }
    }
  }

  Future<void> _removeLogo() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Eliminar Logo'),
        content: const Text('¿Está seguro de eliminar el logo del negocio?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('CANCELAR'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            style: TextButton.styleFrom(foregroundColor: Colors.red),
            child: const Text('ELIMINAR'),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      setState(() {
        _pendingLogoSourcePath = null;
        _draft = _draft.copyWith(clearLogoPath: true);
        _hasChanges = true;
      });
    }
  }

  Future<void> _saveAll() async {
    setState(() => _isLoading = true);

    try {
      final notifier = ref.read(businessSettingsProvider.notifier);
      final current = ref.read(businessSettingsProvider);

      String? logoToPersist;
      bool clearLogoPath = false;
      if (_draft.logoPath == null) {
        clearLogoPath = true;
      } else if (_pendingLogoSourcePath != null) {
        final sourcePath = _pendingLogoSourcePath!;
        final appDir = await getApplicationDocumentsDirectory();
        final logoDir = Directory(p.join(appDir.path, 'fullpos', 'logo'));

        if (!await logoDir.exists()) {
          await logoDir.create(recursive: true);
        }

        final previousLogoPath = current.logoPath;
        final extension = p.extension(sourcePath);
        final ts = DateTime.now().millisecondsSinceEpoch;
        final destPath = p.join(logoDir.path, 'business_logo_$ts$extension');
        await File(sourcePath).copy(destPath);
        logoToPersist = destPath;

        // Limpiar logo anterior para evitar acumulaciÇün (best-effort).
        try {
          final prev = (previousLogoPath ?? '').trim();
          if (prev.isNotEmpty &&
              prev != destPath &&
              p.isWithin(logoDir.path, prev) &&
              File(prev).existsSync()) {
            await File(prev).delete();
          }
        } catch (_) {}
      } else {
        logoToPersist = _draft.logoPath;
      }

      var updated = current.copyWith(
        businessName: _businessNameController.text.isNotEmpty
            ? _businessNameController.text
            : 'MI NEGOCIO',
        phone: _phoneController.text.isNotEmpty ? _phoneController.text : null,
        phone2: _phone2Controller.text.isNotEmpty
            ? _phone2Controller.text
            : null,
        email: _emailController.text.isNotEmpty ? _emailController.text : null,
        address: _addressController.text.isNotEmpty
            ? _addressController.text
            : null,
        city: _cityController.text.isNotEmpty ? _cityController.text : null,
        rnc: _rncController.text.isNotEmpty ? _rncController.text : null,
        slogan: _sloganController.text.isNotEmpty
            ? _sloganController.text
            : null,
        website: _websiteController.text.isNotEmpty
            ? _websiteController.text
            : null,
        receiptHeader: _receiptHeaderController.text,
        receiptFooter: _receiptFooterController.text,
        loanContractRepresentativeName:
            _loanContractRepresentativeNameController.text.trim().isNotEmpty
                ? _loanContractRepresentativeNameController.text.trim()
                : null,
        loanContractRepresentativeCedula:
            _loanContractRepresentativeCedulaController.text.trim().isNotEmpty
                ? _loanContractRepresentativeCedulaController.text.trim()
                : null,
        defaultInterestRate: _draft.defaultInterestRate,
        defaultLateFeeRate: _draft.defaultLateFeeRate,
        defaultLoanTermDays: _draft.defaultLoanTermDays,
        gracePeriodDays: _draft.gracePeriodDays,
        defaultTaxRate: _draft.defaultTaxRate,
        taxIncludedInPrices: _draft.taxIncludedInPrices,
        defaultCurrency: _draft.defaultCurrency,
        currencySymbol: _draft.currencySymbol,
        showLogoOnReceipt: _draft.showLogoOnReceipt,
        printReceiptAutomatically: _draft.printReceiptAutomatically,
      );

      if (clearLogoPath) {
        updated = updated.copyWith(clearLogoPath: true);
      } else if (logoToPersist != null) {
        updated = updated.copyWith(logoPath: logoToPersist);
      }

      await notifier.saveSettings(updated);

      // Mantener servicio global sincronizado (usado por helpers/impresiones)
      appConfigService.updateSettings(updated);

      setState(() {
        _isLoading = false;
        _hasChanges = false;
        _pendingLogoSourcePath = null;
        _draft = updated;
      });

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Configuración guardada correctamente'),
            backgroundColor: Colors.green,
          ),
        );
      }
    } catch (e, st) {
      setState(() => _isLoading = false);
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: _saveAll,
          module: 'settings/business/save',
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    // Mantenemos el provider activo (carga/actualiza desde DB) pero editamos contra _draft.
    ref.watch(businessSettingsProvider);

    // Mantener el borrador sincronizado con la DB mientras no haya cambios sin guardar.
    // Nota: `ref.listen` debe usarse dentro de `build` en Riverpod.
    ref.listen<BusinessSettings>(businessSettingsProvider, (previous, next) {
      if (!mounted) return;
      if (_hasChanges) return;
      setState(() {
        _loadInitialValues(next);
      });
    });
    final settings = _draft;

    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final appBarBg = theme.appBarTheme.backgroundColor ?? scheme.surface;
    final isDarkBg =
        ThemeData.estimateBrightnessForColor(appBarBg) == Brightness.dark;
    final tabFg = isDarkBg ? Colors.white : Colors.black;

    return Scaffold(
      appBar: AppBar(
        title: const Text('CONFIGURACIÓN DEL NEGOCIO'),
        actions: [
          if (_hasChanges)
            Padding(
              padding: const EdgeInsets.only(right: 8),
              child: Center(
                child: Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 8,
                    vertical: 4,
                  ),
                  decoration: BoxDecoration(
                    color: Colors.orange.withAlpha(50),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: const Text(
                    'SIN GUARDAR',
                    style: TextStyle(
                      color: Colors.orange,
                      fontSize: 12,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ),
            ),
          TextButton.icon(
            onPressed: _isLoading ? null : _saveAll,
            icon: _isLoading
                ? const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.save, color: Colors.white),
            label: const Text(
              'GUARDAR TODO',
              style: TextStyle(color: Colors.white),
            ),
          ),
          const SizedBox(width: 8),
        ],
        bottom: TabBar(
          controller: _tabController,
          labelColor: tabFg,
          unselectedLabelColor: tabFg.withOpacity(0.88),
          indicatorColor: tabFg,
          labelStyle: const TextStyle(fontWeight: FontWeight.w800),
          unselectedLabelStyle: const TextStyle(fontWeight: FontWeight.w700),
          tabs: const [
            Tab(icon: Icon(Icons.store), text: 'Empresa'),
            Tab(icon: Icon(Icons.percent), text: 'Préstamos'),
            Tab(icon: Icon(Icons.attach_money), text: 'Impuestos'),
            Tab(icon: Icon(Icons.receipt), text: 'Recibos'),
          ],
        ),
      ),
      body: TabBarView(
        controller: _tabController,
        children: [
          _buildCompanyTab(settings),
          _buildLoansTab(settings),
          _buildTaxesTab(settings),
          _buildReceiptsTab(settings),
        ],
      ),
    );
  }

  Widget _buildCompanyTab(BusinessSettings settings) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Logo
          Center(
            child: Column(
              children: [
                Container(
                  width: 150,
                  height: 150,
                  decoration: BoxDecoration(
                    color: Colors.grey.shade200,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: Colors.grey.shade400),
                  ),
                  child:
                      settings.logoPath != null &&
                          File(settings.logoPath!).existsSync()
                      ? ClipRRect(
                          borderRadius: BorderRadius.circular(11),
                          child: Image.file(
                            File(settings.logoPath!),
                            fit: BoxFit.cover,
                          ),
                        )
                      : Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(
                              Icons.store,
                              size: 48,
                              color: Colors.grey.shade500,
                            ),
                            const SizedBox(height: 8),
                            Text(
                              'Sin Logo',
                              style: TextStyle(color: Colors.grey.shade600),
                            ),
                          ],
                        ),
                ),
                const SizedBox(height: 12),
                Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    ElevatedButton.icon(
                      onPressed: _isLoading ? null : _pickLogo,
                      icon: const Icon(Icons.upload),
                      label: const Text('Subir Logo'),
                    ),
                    if (settings.logoPath != null) ...[
                      const SizedBox(width: 8),
                      TextButton.icon(
                        onPressed: _isLoading ? null : _removeLogo,
                        icon: const Icon(Icons.delete, color: Colors.red),
                        label: const Text(
                          'Eliminar',
                          style: TextStyle(color: Colors.red),
                        ),
                      ),
                    ],
                  ],
                ),
              ],
            ),
          ),

          const SizedBox(height: 32),
          const Divider(),
          const SizedBox(height: 16),

          // Información del negocio
          _buildSectionTitle('INFORMACIÓN BÁSICA'),
          const SizedBox(height: 16),

          Row(
            children: [
              Expanded(
                flex: 2,
                child: _buildTextField(
                  controller: _businessNameController,
                  label: 'Nombre del Negocio',
                  icon: Icons.store,
                  required: true,
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: _buildTextField(
                  controller: _rncController,
                  label: 'RNC',
                  icon: Icons.badge,
                  hint: '000-000000-0',
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),

          _buildTextField(
            controller: _sloganController,
            label: 'Slogan',
            icon: Icons.format_quote,
            hint: 'Tu slogan aquí...',
          ),
          const SizedBox(height: 16),

          Row(
            children: [
              Expanded(
                child: _buildTextField(
                  controller: _phoneController,
                  label: 'Teléfono Principal',
                  icon: Icons.phone,
                  hint: '809-000-0000',
                  keyboardType: TextInputType.phone,
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: _buildTextField(
                  controller: _phone2Controller,
                  label: 'Teléfono Secundario',
                  icon: Icons.phone_android,
                  hint: '829-000-0000',
                  keyboardType: TextInputType.phone,
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),

          Row(
            children: [
              Expanded(
                flex: 2,
                child: _buildTextField(
                  controller: _emailController,
                  label: 'Correo Electrónico',
                  icon: Icons.email,
                  hint: 'correo@ejemplo.com',
                  keyboardType: TextInputType.emailAddress,
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: _buildTextField(
                  controller: _websiteController,
                  label: 'Sitio Web',
                  icon: Icons.language,
                  hint: 'www.ejemplo.com',
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),

          Row(
            children: [
              Expanded(
                flex: 2,
                child: _buildTextField(
                  controller: _addressController,
                  label: 'Dirección',
                  icon: Icons.location_on,
                  hint: 'Calle, número, sector...',
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: _buildTextField(
                  controller: _cityController,
                  label: 'Ciudad',
                  icon: Icons.location_city,
                  hint: 'Santo Domingo',
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildLoansTab(BusinessSettings settings) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildSectionTitle('CONFIGURACIÓN DE PRÉSTAMOS'),
          const SizedBox(height: 8),
          Text(
            'Estos valores se aplicarán por defecto al crear nuevos préstamos',
            style: TextStyle(color: Colors.grey.shade600, fontSize: 13),
          ),
          const SizedBox(height: 24),

          // Tasa de interés
          _buildNumberField(
            label: 'Tasa de Interés por Defecto',
            value: settings.defaultInterestRate,
            suffix: '%',
            icon: Icons.percent,
            min: 0,
            max: 100,
            onChanged: (value) {
              setState(() {
                _draft = _draft.copyWith(defaultInterestRate: value);
                _hasChanges = true;
              });
            },
          ),
          const SizedBox(height: 24),

          // Tasa de mora
          _buildNumberField(
            label: 'Tasa de Mora por Defecto',
            value: settings.defaultLateFeeRate,
            suffix: '%',
            icon: Icons.warning_amber,
            min: 0,
            max: 100,
            onChanged: (value) {
              setState(() {
                _draft = _draft.copyWith(defaultLateFeeRate: value);
                _hasChanges = true;
              });
            },
          ),
          const SizedBox(height: 24),

          // Plazo de préstamo
          _buildIntField(
            label: 'Plazo de Préstamo por Defecto',
            value: settings.defaultLoanTermDays,
            suffix: 'días',
            icon: Icons.calendar_today,
            min: 1,
            max: 365,
            onChanged: (value) {
              setState(() {
                _draft = _draft.copyWith(defaultLoanTermDays: value);
                _hasChanges = true;
              });
            },
          ),
          const SizedBox(height: 24),

          // Días de gracia
          _buildIntField(
            label: 'Días de Gracia',
            value: settings.gracePeriodDays,
            suffix: 'días',
            icon: Icons.hourglass_empty,
            min: 0,
            max: 30,
            helpText: 'Días antes de aplicar mora después del vencimiento',
            onChanged: (value) {
              setState(() {
                _draft = _draft.copyWith(gracePeriodDays: value);
                _hasChanges = true;
              });
            },
          ),

          const SizedBox(height: 32),

          const Divider(),
          const SizedBox(height: 16),

          _buildSectionTitle('CONTRATO DE PRÉSTAMOS'),
          const SizedBox(height: 8),
          Text(
            'Si configuras un representante fijo, el contrato usará esos datos. '
            'Si lo dejas vacío, se usará el usuario (cajero) que genera el contrato.',
            style: TextStyle(color: Colors.grey.shade600, fontSize: 13),
          ),
          const SizedBox(height: 16),
          _buildTextField(
            controller: _loanContractRepresentativeNameController,
            label: 'Representante (Nombre)',
            icon: Icons.badge,
            hint: 'Ej: Juan Pérez',
          ),
          const SizedBox(height: 12),
          _buildTextField(
            controller: _loanContractRepresentativeCedulaController,
            label: 'Representante (Cédula) - opcional',
            icon: Icons.perm_identity,
            hint: '000-0000000-0',
            keyboardType: TextInputType.number,
          ),
          const SizedBox(height: 10),
          Align(
            alignment: Alignment.centerLeft,
            child: TextButton.icon(
              onPressed: () {
                setState(() {
                  _loanContractRepresentativeNameController.text = '';
                  _loanContractRepresentativeCedulaController.text = '';
                  _draft = _draft.copyWith(
                    loanContractRepresentativeName: null,
                    loanContractRepresentativeCedula: null,
                  );
                  _hasChanges = true;
                });
              },
              icon: const Icon(Icons.restore, size: 18),
              label: const Text('Usar cajero como representante'),
            ),
          ),

          // Info box
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Colors.blue.shade50,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: Colors.blue.shade200),
            ),
            child: Row(
              children: [
                Icon(Icons.info_outline, color: Colors.blue.shade700),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'Estos valores son solo los predeterminados. Cada préstamo puede tener sus propios valores personalizados.',
                    style: TextStyle(color: Colors.blue.shade700, fontSize: 13),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildTaxesTab(BusinessSettings settings) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildSectionTitle('CONFIGURACIÓN DE IMPUESTOS'),
          const SizedBox(height: 24),

          // Tasa de impuesto
          _buildNumberField(
            label: 'Tasa de Impuesto (ITBIS)',
            value: settings.defaultTaxRate,
            suffix: '%',
            icon: Icons.receipt_long,
            min: 0,
            max: 100,
            onChanged: (value) {
              setState(() {
                _draft = _draft.copyWith(defaultTaxRate: value);
                _hasChanges = true;
              });
            },
          ),
          const SizedBox(height: 24),

          // Impuesto incluido en precios
          SwitchListTile(
            title: const Text('Impuesto incluido en precios'),
            subtitle: const Text(
              'Los precios de los productos ya incluyen el ITBIS',
            ),
            value: settings.taxIncludedInPrices,
            onChanged: (value) {
              setState(() {
                _draft = _draft.copyWith(taxIncludedInPrices: value);
                _hasChanges = true;
              });
            },
          ),

          const SizedBox(height: 32),
          const Divider(),
          const SizedBox(height: 16),

          _buildSectionTitle('MONEDA'),
          const SizedBox(height: 16),

          // Selector de moneda
          DropdownButtonFormField<String>(
            value: settings.defaultCurrency,
            decoration: InputDecoration(
              labelText: 'Moneda',
              prefixIcon: const Icon(Icons.attach_money),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
              ),
            ),
            items: const [
              DropdownMenuItem(
                value: 'DOP',
                child: Text('Peso Dominicano (DOP)'),
              ),
              DropdownMenuItem(
                value: 'USD',
                child: Text('Dólar Estadounidense (USD)'),
              ),
              DropdownMenuItem(value: 'EUR', child: Text('Euro (EUR)')),
            ],
            onChanged: (value) {
              if (value != null) {
                String symbol;
                switch (value) {
                  case 'DOP':
                    symbol = 'RD\$';
                    break;
                  case 'USD':
                    symbol = '\$';
                    break;
                  case 'EUR':
                    symbol = '€';
                    break;
                  default:
                    symbol = '\$';
                }
                setState(() {
                  _draft = _draft.copyWith(
                    defaultCurrency: value,
                    currencySymbol: symbol,
                  );
                  _hasChanges = true;
                });
              }
            },
          ),

          const SizedBox(height: 16),

          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.grey.shade100,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              children: [
                const Text('Símbolo actual: '),
                Text(
                  settings.currencySymbol,
                  style: const TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 18,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildReceiptsTab(BusinessSettings settings) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildSectionTitle('CONFIGURACIÓN DE RECIBOS'),
          const SizedBox(height: 24),

          // Encabezado del recibo
          TextField(
            controller: _receiptHeaderController,
            decoration: InputDecoration(
              labelText: 'Encabezado del Recibo',
              hintText: 'Texto que aparecerá en la parte superior del recibo',
              prefixIcon: const Icon(Icons.vertical_align_top),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
              ),
            ),
            maxLines: 3,
            onChanged: (_) => setState(() => _hasChanges = true),
          ),
          const SizedBox(height: 24),

          // Pie del recibo
          TextField(
            controller: _receiptFooterController,
            decoration: InputDecoration(
              labelText: 'Pie del Recibo',
              hintText: 'Texto que aparecerá al final del recibo',
              prefixIcon: const Icon(Icons.vertical_align_bottom),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
              ),
            ),
            maxLines: 3,
            onChanged: (_) => setState(() => _hasChanges = true),
          ),

          const SizedBox(height: 24),

          // Opciones de recibo
          SwitchListTile(
            title: const Text('Mostrar logo en recibos'),
            subtitle: const Text(
              'El logo aparecerá en la parte superior del recibo',
            ),
            value: settings.showLogoOnReceipt,
            onChanged: (value) {
              setState(() {
                _draft = _draft.copyWith(showLogoOnReceipt: value);
                _hasChanges = true;
              });
            },
          ),

          SwitchListTile(
            title: const Text('Imprimir automáticamente'),
            subtitle: const Text(
              'El recibo se imprimirá automáticamente al completar una venta',
            ),
            value: settings.printReceiptAutomatically,
            onChanged: (value) {
              setState(() {
                _draft = _draft.copyWith(printReceiptAutomatically: value);
                _hasChanges = true;
              });
            },
          ),

          const SizedBox(height: 32),

          // Vista previa
          _buildSectionTitle('VISTA PREVIA DEL RECIBO'),
          const SizedBox(height: 16),
          _buildReceiptPreview(settings),
        ],
      ),
    );
  }

  Widget _buildReceiptPreview(BusinessSettings settings) {
    return Container(
      width: 300,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.white,
        border: Border.all(color: Colors.grey.shade300),
        borderRadius: BorderRadius.circular(8),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withAlpha(20),
            blurRadius: 8,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          // Logo
          if (settings.showLogoOnReceipt && settings.logoPath != null)
            Container(
              width: 80,
              height: 80,
              margin: const EdgeInsets.only(bottom: 8),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(8),
                image: File(settings.logoPath!).existsSync()
                    ? DecorationImage(
                        image: FileImage(File(settings.logoPath!)),
                        fit: BoxFit.cover,
                      )
                    : null,
              ),
            ),

          // Nombre del negocio
          Text(
            settings.businessName,
            style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
            textAlign: TextAlign.center,
          ),

          if (settings.slogan?.isNotEmpty == true)
            Text(
              settings.slogan!,
              style: TextStyle(
                color: Colors.grey.shade600,
                fontSize: 11,
                fontStyle: FontStyle.italic,
              ),
              textAlign: TextAlign.center,
            ),

          if (settings.receiptHeader.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(top: 4),
              child: Text(
                settings.receiptHeader,
                style: const TextStyle(fontSize: 11),
                textAlign: TextAlign.center,
              ),
            ),

          const Divider(height: 16),

          // Info de contacto
          if (settings.phone?.isNotEmpty == true)
            Text(
              'Tel: ${settings.phone}',
              style: const TextStyle(fontSize: 10),
            ),
          if (settings.address?.isNotEmpty == true)
            Text(
              settings.address!,
              style: const TextStyle(fontSize: 10),
              textAlign: TextAlign.center,
            ),
          if (settings.rnc?.isNotEmpty == true)
            Text('RNC: ${settings.rnc}', style: const TextStyle(fontSize: 10)),

          const Divider(height: 16),

          // Contenido de ejemplo
          Container(
            padding: const EdgeInsets.symmetric(vertical: 8),
            child: Column(
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    const Text(
                      'Producto ejemplo',
                      style: TextStyle(fontSize: 10),
                    ),
                    Text(
                      '${settings.currencySymbol}100.00',
                      style: const TextStyle(fontSize: 10),
                    ),
                  ],
                ),
                const Divider(height: 8),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    const Text(
                      'TOTAL',
                      style: TextStyle(
                        fontSize: 11,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    Text(
                      '${settings.currencySymbol}100.00',
                      style: const TextStyle(
                        fontSize: 11,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),

          const Divider(height: 16),

          // Footer
          if (settings.receiptFooter.isNotEmpty)
            Text(
              settings.receiptFooter,
              style: const TextStyle(fontSize: 10),
              textAlign: TextAlign.center,
            ),
        ],
      ),
    );
  }

  Widget _buildSectionTitle(String title) {
    return Text(
      title,
      style: TextStyle(
        fontSize: 14,
        fontWeight: FontWeight.bold,
        color: Colors.grey.shade700,
        letterSpacing: 1,
      ),
    );
  }

  Widget _buildTextField({
    required TextEditingController controller,
    required String label,
    required IconData icon,
    String? hint,
    bool required = false,
    TextInputType? keyboardType,
  }) {
    return TextField(
      controller: controller,
      decoration: InputDecoration(
        labelText: required ? '$label *' : label,
        hintText: hint,
        prefixIcon: Icon(icon),
        border: OutlineInputBorder(borderRadius: BorderRadius.circular(8)),
      ),
      keyboardType: keyboardType,
      onChanged: (_) => setState(() => _hasChanges = true),
    );
  }

  Widget _buildNumberField({
    required String label,
    required double value,
    required String suffix,
    required IconData icon,
    required double min,
    required double max,
    String? helpText,
    required void Function(double) onChanged,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(icon, color: Colors.grey.shade600),
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                label,
                style: const TextStyle(fontWeight: FontWeight.w500),
              ),
            ),
            SizedBox(
              width: 100,
              child: TextField(
                controller: TextEditingController(
                  text: value.toStringAsFixed(1),
                ),
                decoration: InputDecoration(
                  suffixText: suffix,
                  contentPadding: const EdgeInsets.symmetric(
                    horizontal: 12,
                    vertical: 8,
                  ),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                  ),
                ),
                keyboardType: const TextInputType.numberWithOptions(
                  decimal: true,
                ),
                inputFormatters: [
                  FilteringTextInputFormatter.allow(RegExp(r'^\d+\.?\d{0,2}')),
                ],
                onChanged: (text) {
                  final val = double.tryParse(text);
                  if (val != null && val >= min && val <= max) {
                    onChanged(val);
                  }
                },
              ),
            ),
          ],
        ),
        if (helpText != null)
          Padding(
            padding: const EdgeInsets.only(left: 32, top: 4),
            child: Text(
              helpText,
              style: TextStyle(color: Colors.grey.shade600, fontSize: 12),
            ),
          ),
      ],
    );
  }

  Widget _buildIntField({
    required String label,
    required int value,
    required String suffix,
    required IconData icon,
    required int min,
    required int max,
    String? helpText,
    required void Function(int) onChanged,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(icon, color: Colors.grey.shade600),
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                label,
                style: const TextStyle(fontWeight: FontWeight.w500),
              ),
            ),
            SizedBox(
              width: 100,
              child: TextField(
                controller: TextEditingController(text: value.toString()),
                decoration: InputDecoration(
                  suffixText: suffix,
                  contentPadding: const EdgeInsets.symmetric(
                    horizontal: 12,
                    vertical: 8,
                  ),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                  ),
                ),
                keyboardType: TextInputType.number,
                inputFormatters: [FilteringTextInputFormatter.digitsOnly],
                onChanged: (text) {
                  final val = int.tryParse(text);
                  if (val != null && val >= min && val <= max) {
                    onChanged(val);
                  }
                },
              ),
            ),
          ],
        ),
        if (helpText != null)
          Padding(
            padding: const EdgeInsets.only(left: 32, top: 4),
            child: Text(
              helpText,
              style: TextStyle(color: Colors.grey.shade600, fontSize: 12),
            ),
          ),
      ],
    );
  }
}

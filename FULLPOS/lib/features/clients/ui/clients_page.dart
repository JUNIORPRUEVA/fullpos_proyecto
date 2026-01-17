import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'dart:io';
import 'package:path_provider/path_provider.dart';
import '../../../core/constants/app_colors.dart';
import '../../../core/constants/app_sizes.dart';
import '../../../core/errors/error_handler.dart';
import '../data/client_model.dart';
import '../data/clients_repository.dart';
import '../../sales/data/sales_repository.dart';
import 'client_details_dialog.dart';
import 'client_form_dialog.dart';
import 'widgets/client_row_tile.dart';

/// Filtros para la lista de clientes
class ClientFilters {
  String query;
  bool? isActive;
  bool? hasCredit;
  DateTime? fromDate;
  DateTime? toDate;
  bool includeDeleted;
  String orderBy;

  ClientFilters({
    this.query = '',
    this.isActive,
    this.hasCredit,
    this.fromDate,
    this.toDate,
    this.includeDeleted = false,
    this.orderBy = 'recent',
  });

  ClientFilters copyWith({
    String? query,
    bool? isActive,
    bool? hasCredit,
    DateTime? fromDate,
    DateTime? toDate,
    bool? includeDeleted,
    String? orderBy,
  }) {
    return ClientFilters(
      query: query ?? this.query,
      isActive: isActive ?? this.isActive,
      hasCredit: hasCredit ?? this.hasCredit,
      fromDate: fromDate ?? this.fromDate,
      toDate: toDate ?? this.toDate,
      includeDeleted: includeDeleted ?? this.includeDeleted,
      orderBy: orderBy ?? this.orderBy,
    );
  }

  void reset() {
    query = '';
    isActive = null;
    hasCredit = null;
    fromDate = null;
    toDate = null;
    includeDeleted = false;
    orderBy = 'recent';
  }
}

/// Pantalla de clientes
class ClientsPage extends StatefulWidget {
  const ClientsPage({super.key});

  @override
  State<ClientsPage> createState() => _ClientsPageState();
}

class _ClientsPageState extends State<ClientsPage> {
  final _searchController = TextEditingController();
  final _filters = ClientFilters();

  List<ClientModel> _clients = [];
  bool _isLoading = false;

  DateTime? _statsFromDate;
  DateTime? _statsToDate;
  late Future<Map<String, dynamic>> _statsFuture;

  @override
  void initState() {
    super.initState();
    _loadClients();
    _refreshStats();
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  Future<void> _loadClients() async {
    setState(() => _isLoading = true);

    try {
      final clients = await ClientsRepository.list(
        query: _filters.query.isEmpty ? null : _filters.query,
        isActive: _filters.isActive,
        hasCredit: _filters.hasCredit,
        createdFromMs: _filters.fromDate?.millisecondsSinceEpoch,
        createdToMs: _filters.toDate != null
            ? DateTime(
                _filters.toDate!.year,
                _filters.toDate!.month,
                _filters.toDate!.day,
                23,
                59,
                59,
              ).millisecondsSinceEpoch
            : null,
        includeDeleted: _filters.includeDeleted,
        orderBy: _filters.orderBy,
      );

      if (mounted) {
        setState(() {
          _clients = clients;
          _isLoading = false;
        });
      }
    } catch (e, st) {
      if (mounted) {
        setState(() => _isLoading = false);
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: _loadClients,
          module: 'clients/list',
        );
      }
    }
  }

  void _refreshStats() {
    _statsFuture = SalesRepository.getClientsKpis(
      dateFrom: _statsFromDate,
      dateTo: _statsToDate,
    );
  }

  Future<void> _selectStatsDate(bool isFrom) async {
    final date = await showDatePicker(
      context: context,
      initialDate: isFrom
          ? (_statsFromDate ?? DateTime.now())
          : (_statsToDate ?? DateTime.now()),
      firstDate: DateTime(2020),
      lastDate: DateTime.now().add(const Duration(days: 365)),
    );

    if (date == null) return;
    setState(() {
      if (isFrom) {
        _statsFromDate = date;
      } else {
        _statsToDate = date;
      }
      _refreshStats();
    });
  }

  Widget _buildKpiTile({
    required IconData icon,
    required String label,
    required String value,
  }) {
    return Container(
      padding: const EdgeInsets.all(AppSizes.paddingM),
      decoration: BoxDecoration(
        color: AppColors.bgLight,
        borderRadius: BorderRadius.circular(AppSizes.radiusM),
        border: Border.all(color: AppColors.teal700.withOpacity(0.3)),
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: AppColors.teal700.withOpacity(0.25),
              borderRadius: BorderRadius.circular(AppSizes.radiusM),
            ),
            child: Icon(icon, color: AppColors.gold, size: 18),
          ),
          const SizedBox(width: AppSizes.spaceM),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  label,
                  style: const TextStyle(
                    fontSize: 12,
                    color: Colors.black87,
                    fontWeight: FontWeight.w600,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
                const SizedBox(height: 4),
                Text(
                  value,
                  style: const TextStyle(
                    fontSize: 16,
                    color: Colors.black,
                    fontWeight: FontWeight.bold,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildAnalyticsPanel() {
    final dateFormat = DateFormat('dd/MM/yyyy');
    final money = NumberFormat.currency(symbol: 'RD\$ ', decimalDigits: 2);

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(AppSizes.paddingL),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Resumen de Clientes',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
                color: AppColors.gold,
              ),
            ),
            const SizedBox(height: AppSizes.spaceM),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: () => _selectStatsDate(true),
                    icon: const Icon(Icons.calendar_today, size: 16),
                    label: Text(
                      _statsFromDate != null
                          ? dateFormat.format(_statsFromDate!)
                          : 'Desde',
                    ),
                  ),
                ),
                const SizedBox(width: AppSizes.spaceM),
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: () => _selectStatsDate(false),
                    icon: const Icon(Icons.calendar_today, size: 16),
                    label: Text(
                      _statsToDate != null
                          ? dateFormat.format(_statsToDate!)
                          : 'Hasta',
                    ),
                  ),
                ),
              ],
            ),
            if (_statsFromDate != null || _statsToDate != null) ...[
              const SizedBox(height: AppSizes.spaceS),
              TextButton.icon(
                onPressed: () {
                  setState(() {
                    _statsFromDate = null;
                    _statsToDate = null;
                    _refreshStats();
                  });
                },
                icon: const Icon(Icons.clear, size: 16),
                label: const Text('Limpiar fechas'),
              ),
            ],
            const SizedBox(height: AppSizes.spaceL),
            FutureBuilder<Map<String, dynamic>>(
              future: _statsFuture,
              builder: (context, snapshot) {
                final loading =
                    snapshot.connectionState == ConnectionState.waiting;
                if (snapshot.hasError) {
                  return Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(AppSizes.paddingM),
                    decoration: BoxDecoration(
                      color: AppColors.error.withOpacity(0.12),
                      borderRadius: BorderRadius.circular(AppSizes.radiusM),
                      border: Border.all(
                        color: AppColors.error.withOpacity(0.35),
                      ),
                    ),
                    child: Text(
                      'Error cargando resumen: ${snapshot.error}',
                      style: const TextStyle(color: AppColors.textPrimary),
                    ),
                  );
                }

                final data = snapshot.data ?? const <String, dynamic>{};
                final clientsTotal = (data['clientsTotal'] as int?) ?? 0;
                final visitsCount = (data['visitsCount'] as int?) ?? 0;
                final totalPurchased =
                    (data['totalPurchased'] as num?)?.toDouble() ?? 0.0;

                return Column(
                  children: [
                    _buildKpiTile(
                      icon: Icons.people,
                      label: 'Clientes registrados',
                      value: loading ? '...' : clientsTotal.toString(),
                    ),
                    const SizedBox(height: AppSizes.spaceM),
                    _buildKpiTile(
                      icon: Icons.receipt_long,
                      label: 'Visitas (tickets)',
                      value: loading ? '...' : visitsCount.toString(),
                    ),
                    const SizedBox(height: AppSizes.spaceM),
                    _buildKpiTile(
                      icon: Icons.payments,
                      label: 'Total comprado',
                      value: loading ? '...' : money.format(totalPurchased),
                    ),
                  ],
                );
              },
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _showClientDialog([ClientModel? client]) async {
    final result = await showDialog<ClientModel>(
      context: context,
      builder: (context) => ClientFormDialog(client: client),
    );

    if (result != null) {
      _loadClients();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              client == null
                  ? 'Cliente creado exitosamente'
                  : 'Cliente actualizado exitosamente',
            ),
            backgroundColor: AppColors.success,
          ),
        );
      }
    }
  }

  void _showClientDetails(ClientModel client) {
    showDialog(
      context: context,
      builder: (context) => ClientDetailsDialog(client: client),
    );
  }

  Future<void> _toggleActive(ClientModel client) async {
    try {
      await ClientsRepository.toggleActive(client.id!, !client.isActive);
      _loadClients();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              client.isActive ? 'Cliente desactivado' : 'Cliente activado',
            ),
            backgroundColor: AppColors.success,
          ),
        );
      }
    } catch (e, st) {
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: () => _toggleActive(client),
          module: 'clients/toggle_active',
        );
      }
    }
  }

  Future<void> _toggleCredit(ClientModel client) async {
    try {
      await ClientsRepository.toggleCredit(client.id!, !client.hasCredit);
      _loadClients();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              client.hasCredit ? 'Crédito desactivado' : 'Crédito activado',
            ),
            backgroundColor: AppColors.success,
          ),
        );
      }
    } catch (e, st) {
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: () => _toggleCredit(client),
          module: 'clients/toggle_credit',
        );
      }
    }
  }

  Future<void> _deleteClient(ClientModel client) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Confirmar eliminación'),
        content: Text('¿Está seguro de eliminar a ${client.nombre}?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancelar'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(backgroundColor: AppColors.error),
            child: const Text('Eliminar'),
          ),
        ],
      ),
    );

    if (confirm == true) {
      try {
        await ClientsRepository.delete(client.id!);
        _loadClients();
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Cliente eliminado'),
              backgroundColor: AppColors.success,
            ),
          );
        }
      } catch (e, st) {
        if (mounted) {
          await ErrorHandler.instance.handle(
            e,
            stackTrace: st,
            context: context,
            onRetry: () => _deleteClient(client),
            module: 'clients/delete',
          );
        }
      }
    }
  }

  Future<void> _exportClientsToExcel() async {
    try {
      // Crear contenido CSV
      final StringBuffer csvBuffer = StringBuffer();

      // Encabezados
      csvBuffer.writeln(
        'ID,Nombre,Teléfono,Dirección,RNC,Cédula,Estado,Crédito,Fecha Registro',
      );

      // Datos de clientes
      final dateFormat = DateFormat('dd/MM/yyyy');
      for (final client in _clients) {
        final status = client.isActive ? 'Activo' : 'Inactivo';
        final credit = client.hasCredit ? 'Sí' : 'No';
        final createdDate = dateFormat.format(
          DateTime.fromMillisecondsSinceEpoch(client.createdAtMs),
        );

        // Escapar comillas en valores
        final nombre = '"${client.nombre.replaceAll('"', '""')}"';
        final direccion = '"${(client.direccion ?? '').replaceAll('"', '""')}"';

        csvBuffer.writeln(
          '${client.id},$nombre,${client.telefono ?? ''},$direccion,${client.rnc ?? ''},${client.cedula ?? ''},$status,$credit,$createdDate',
        );
      }

      // Obtener directorio de descargas
      final Directory? downloadsDir = await getDownloadsDirectory();
      if (downloadsDir == null) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('No se pudo acceder al directorio de descargas'),
              backgroundColor: AppColors.error,
            ),
          );
        }
        return;
      }

      // Crear archivo
      final String timestamp = DateFormat(
        'yyyyMMdd_HHmmss',
      ).format(DateTime.now());
      final File file = File('${downloadsDir.path}/Clientes_$timestamp.csv');

      await file.writeAsString(csvBuffer.toString());

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Archivo exportado: ${file.path}'),
            backgroundColor: AppColors.success,
          ),
        );
      }
    } catch (e, st) {
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: _exportClientsToExcel,
          module: 'clients/export',
        );
      }
    }
  }

  void _showFiltersDialog() {
    showDialog(
      context: context,
      builder: (context) => _FiltersDialog(
        filters: _filters,
        onApply: () {
          Navigator.pop(context);
          _loadClients();
        },
        onClear: () {
          setState(() {
            _filters.reset();
            _searchController.clear();
          });
          Navigator.pop(context);
          _loadClients();
        },
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Encabezado
        Padding(
          padding: const EdgeInsets.only(
            left: AppSizes.paddingL,
            right: AppSizes.paddingL,
            top: AppSizes.paddingM,
          ),
          child: Row(
            children: [
              const Icon(Icons.people, size: 32, color: AppColors.gold),
              const SizedBox(width: AppSizes.spaceM),
              const Text(
                'Gestión de Clientes',
                style: TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 28,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const Spacer(),
              ElevatedButton.icon(
                onPressed: _exportClientsToExcel,
                icon: const Icon(Icons.download, size: 20),
                label: const Text('Exportar', style: TextStyle(fontSize: 15)),
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppColors.teal700,
                  foregroundColor: Colors.white,
                  minimumSize: const Size(130, 44),
                  padding: const EdgeInsets.symmetric(
                    horizontal: AppSizes.paddingL,
                  ),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(AppSizes.radiusM),
                  ),
                ),
              ),
              const SizedBox(width: AppSizes.spaceM),
              ElevatedButton.icon(
                onPressed: _showFiltersDialog,
                icon: const Icon(Icons.filter_list, size: 20),
                label: const Text('Filtros', style: TextStyle(fontSize: 15)),
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppColors.teal700,
                  foregroundColor: Colors.white,
                  minimumSize: const Size(120, 44),
                  padding: const EdgeInsets.symmetric(
                    horizontal: AppSizes.paddingL,
                  ),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(AppSizes.radiusM),
                  ),
                ),
              ),
              const SizedBox(width: AppSizes.spaceM),
              ElevatedButton.icon(
                onPressed: () => _showClientDialog(),
                icon: const Icon(Icons.add, size: 20),
                label: const Text(
                  'Nuevo Cliente',
                  style: TextStyle(fontSize: 15),
                ),
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppColors.gold,
                  foregroundColor: AppColors.teal900,
                  minimumSize: const Size(160, 44),
                  padding: const EdgeInsets.symmetric(
                    horizontal: AppSizes.paddingL,
                  ),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(AppSizes.radiusM),
                  ),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: AppSizes.spaceL),

        // Contenido
        Expanded(
          child: LayoutBuilder(
            builder: (context, constraints) {
              final isNarrow = constraints.maxWidth < 980;

              final listCard = Card(
                child: Padding(
                  padding: const EdgeInsets.all(AppSizes.paddingL),
                  child: Column(
                    children: [
                      // Barra de búsqueda
                      TextField(
                        controller: _searchController,
                        decoration: InputDecoration(
                          hintText:
                              'Buscar por nombre, teléfono, RNC o cédula...',
                          prefixIcon: const Icon(Icons.search),
                          suffixIcon: _searchController.text.isNotEmpty
                              ? IconButton(
                                  icon: const Icon(Icons.clear),
                                  onPressed: () {
                                    _searchController.clear();
                                    _filters.query = '';
                                    _loadClients();
                                  },
                                )
                              : null,
                        ),
                        onChanged: (value) {
                          _filters.query = value;
                          // Debounce search
                          Future.delayed(const Duration(milliseconds: 500), () {
                            if (!mounted) return;
                            if (_filters.query == value) {
                              _loadClients();
                            }
                          });
                        },
                      ),
                      const SizedBox(height: AppSizes.spaceM),

                      // Contador de resultados
                      if (_clients.isNotEmpty)
                        Padding(
                          padding: const EdgeInsets.only(
                            bottom: AppSizes.spaceM,
                          ),
                          child: Row(
                            children: [
                              Text(
                                '${_clients.length} cliente(s) encontrado(s)',
                                style: TextStyle(
                                  color: AppColors.textMuted,
                                  fontSize: 14,
                                ),
                              ),
                            ],
                          ),
                        ),

                      // Lista de clientes
                      Expanded(
                        child: _isLoading
                            ? const Center(child: CircularProgressIndicator())
                            : _clients.isEmpty
                            ? Center(
                                child: Column(
                                  mainAxisAlignment: MainAxisAlignment.center,
                                  children: [
                                    Icon(
                                      Icons.people_outline,
                                      size: 64,
                                      color: AppColors.textMuted,
                                    ),
                                    const SizedBox(height: AppSizes.spaceM),
                                    Text(
                                      'No hay clientes',
                                      style: TextStyle(
                                        color: AppColors.textMuted,
                                        fontSize: 18,
                                      ),
                                    ),
                                    const SizedBox(height: AppSizes.spaceS),
                                    Text(
                                      _filters.query.isNotEmpty ||
                                              _filters.isActive != null ||
                                              _filters.hasCredit != null
                                          ? 'Intenta cambiar los filtros'
                                          : 'Haz clic en "Nuevo Cliente" para agregar uno',
                                      style: TextStyle(
                                        color: AppColors.textMuted,
                                        fontSize: 14,
                                      ),
                                    ),
                                  ],
                                ),
                              )
                            : ListView.builder(
                                itemCount: _clients.length,
                                itemBuilder: (context, index) {
                                  final client = _clients[index];
                                  return ClientRowTile(
                                    client: client,
                                    onViewDetails: () =>
                                        _showClientDetails(client),
                                    onEdit: () => _showClientDialog(client),
                                    onToggleActive: () => _toggleActive(client),
                                    onToggleCredit: () => _toggleCredit(client),
                                    onDelete: () => _deleteClient(client),
                                  );
                                },
                              ),
                      ),
                    ],
                  ),
                ),
              );

              if (isNarrow) {
                return Column(
                  children: [
                    Flexible(flex: 3, child: listCard),
                    const SizedBox(height: AppSizes.spaceM),
                    Flexible(flex: 2, child: _buildAnalyticsPanel()),
                  ],
                );
              }

              return Row(
                children: [
                  Expanded(child: listCard),
                  const SizedBox(width: AppSizes.spaceL),
                  SizedBox(width: 360, child: _buildAnalyticsPanel()),
                ],
              );
            },
          ),
        ),
      ],
    );
  }
}

/// Dialog para configurar filtros
class _FiltersDialog extends StatefulWidget {
  final ClientFilters filters;
  final VoidCallback onApply;
  final VoidCallback onClear;

  const _FiltersDialog({
    required this.filters,
    required this.onApply,
    required this.onClear,
  });

  @override
  State<_FiltersDialog> createState() => _FiltersDialogState();
}

class _FiltersDialogState extends State<_FiltersDialog> {
  late bool? _isActive;
  late bool? _hasCredit;
  late DateTime? _fromDate;
  late DateTime? _toDate;
  late bool _includeDeleted;
  late String _orderBy;

  @override
  void initState() {
    super.initState();
    _isActive = widget.filters.isActive;
    _hasCredit = widget.filters.hasCredit;
    _fromDate = widget.filters.fromDate;
    _toDate = widget.filters.toDate;
    _includeDeleted = widget.filters.includeDeleted;
    _orderBy = widget.filters.orderBy;
  }

  Future<void> _selectDate(bool isFrom) async {
    final date = await showDatePicker(
      context: context,
      initialDate: isFrom
          ? (_fromDate ?? DateTime.now())
          : (_toDate ?? DateTime.now()),
      firstDate: DateTime(2020),
      lastDate: DateTime.now().add(const Duration(days: 365)),
    );

    if (date != null) {
      setState(() {
        if (isFrom) {
          _fromDate = date;
        } else {
          _toDate = date;
        }
      });
    }
  }

  void _applyFilters() {
    widget.filters.isActive = _isActive;
    widget.filters.hasCredit = _hasCredit;
    widget.filters.fromDate = _fromDate;
    widget.filters.toDate = _toDate;
    widget.filters.includeDeleted = _includeDeleted;
    widget.filters.orderBy = _orderBy;
    widget.onApply();
  }

  @override
  Widget build(BuildContext context) {
    final dateFormat = DateFormat('dd/MM/yyyy');

    return Dialog(
      child: Container(
        constraints: const BoxConstraints(maxWidth: 500),
        child: Padding(
          padding: const EdgeInsets.all(AppSizes.paddingXL),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Título
              Row(
                children: [
                  const Icon(
                    Icons.filter_list,
                    color: AppColors.gold,
                    size: 28,
                  ),
                  const SizedBox(width: AppSizes.spaceM),
                  const Text(
                    'Filtros',
                    style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
                  ),
                ],
              ),
              const SizedBox(height: AppSizes.spaceXL),

              // Estado
              const Text(
                'Estado',
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: AppSizes.spaceS),
              SegmentedButton<bool?>(
                segments: const [
                  ButtonSegment(value: null, label: Text('Todos')),
                  ButtonSegment(value: true, label: Text('Activos')),
                  ButtonSegment(value: false, label: Text('Inactivos')),
                ],
                selected: {_isActive},
                onSelectionChanged: (Set<bool?> newSelection) {
                  setState(() => _isActive = newSelection.first);
                },
              ),
              const SizedBox(height: AppSizes.spaceL),

              // Crédito
              const Text(
                'Crédito',
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: AppSizes.spaceS),
              SegmentedButton<bool?>(
                segments: const [
                  ButtonSegment(value: null, label: Text('Todos')),
                  ButtonSegment(value: true, label: Text('Con crédito')),
                  ButtonSegment(value: false, label: Text('Sin crédito')),
                ],
                selected: {_hasCredit},
                onSelectionChanged: (Set<bool?> newSelection) {
                  setState(() => _hasCredit = newSelection.first);
                },
              ),
              const SizedBox(height: AppSizes.spaceL),

              // Rango de fechas
              const Text(
                'Fecha de ingreso',
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: AppSizes.spaceS),
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: () => _selectDate(true),
                      icon: const Icon(Icons.calendar_today, size: 16),
                      label: Text(
                        _fromDate != null
                            ? dateFormat.format(_fromDate!)
                            : 'Desde',
                      ),
                    ),
                  ),
                  const SizedBox(width: AppSizes.spaceM),
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: () => _selectDate(false),
                      icon: const Icon(Icons.calendar_today, size: 16),
                      label: Text(
                        _toDate != null ? dateFormat.format(_toDate!) : 'Hasta',
                      ),
                    ),
                  ),
                ],
              ),
              if (_fromDate != null || _toDate != null) ...[
                const SizedBox(height: AppSizes.spaceS),
                TextButton.icon(
                  onPressed: () {
                    setState(() {
                      _fromDate = null;
                      _toDate = null;
                    });
                  },
                  icon: const Icon(Icons.clear, size: 16),
                  label: const Text('Limpiar fechas'),
                ),
              ],
              const SizedBox(height: AppSizes.spaceL),

              // Orden
              const Text(
                'Ordenar por',
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: AppSizes.spaceS),
              DropdownButtonFormField<String>(
                value: _orderBy,
                decoration: const InputDecoration(
                  border: OutlineInputBorder(),
                  contentPadding: EdgeInsets.symmetric(
                    horizontal: AppSizes.paddingM,
                  ),
                ),
                items: const [
                  DropdownMenuItem(
                    value: 'recent',
                    child: Text('Más recientes'),
                  ),
                  DropdownMenuItem(value: 'old', child: Text('Más antiguos')),
                  DropdownMenuItem(value: 'name', child: Text('Nombre A-Z')),
                ],
                onChanged: (value) {
                  if (value != null) {
                    setState(() => _orderBy = value);
                  }
                },
              ),
              const SizedBox(height: AppSizes.spaceL),

              // Incluir eliminados
              SwitchListTile(
                title: const Text('Mostrar clientes eliminados'),
                value: _includeDeleted,
                onChanged: (value) {
                  setState(() => _includeDeleted = value);
                },
                activeColor: AppColors.gold,
              ),
              const SizedBox(height: AppSizes.spaceXL),

              // Botones
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  TextButton(
                    onPressed: widget.onClear,
                    child: const Text('Limpiar todo'),
                  ),
                  const SizedBox(width: AppSizes.spaceM),
                  ElevatedButton.icon(
                    onPressed: _applyFilters,
                    icon: const Icon(Icons.check),
                    label: const Text('Aplicar'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: AppColors.gold,
                      foregroundColor: AppColors.teal900,
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}

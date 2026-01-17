import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:go_router/go_router.dart';
import '../../../core/constants/app_colors.dart';
import '../../../core/errors/error_handler.dart';
import '../../../core/printing/unified_ticket_printer.dart';
import '../../../core/session/session_manager.dart';
import '../../../core/security/app_actions.dart';
import '../../../core/security/authorization_guard.dart';
import '../../settings/data/printer_settings_repository.dart';
import '../data/sales_model.dart';
import '../data/sales_repository.dart';
import '../data/returns_repository.dart';

/// Filtros de fecha predefinidos
enum DateFilter { all, today, yesterday, thisWeek, thisMonth, custom }

/// Página profesional de devoluciones y reembolsos
class ReturnsListPage extends StatefulWidget {
  const ReturnsListPage({super.key});

  @override
  State<ReturnsListPage> createState() => _ReturnsListPageState();
}

class _ReturnsListPageState extends State<ReturnsListPage>
    with SingleTickerProviderStateMixin {
  final _searchController = TextEditingController();
  late TabController _tabController;

  List<SaleModel> _completedSales = [];
  List<Map<String, dynamic>> _returns = [];
  bool _isLoading = false;
  String _searchQuery = '';

  // Filtros de fecha
  DateFilter _selectedFilter = DateFilter.today;
  DateTime? _customDateFrom;
  DateTime? _customDateTo;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _loadData();
  }

  @override
  void dispose() {
    _searchController.dispose();
    _tabController.dispose();
    super.dispose();
  }

  (DateTime?, DateTime?) _getDateRange() {
    final now = DateTime.now();
    final today = DateTime(now.year, now.month, now.day);

    switch (_selectedFilter) {
      case DateFilter.all:
        return (null, null);
      case DateFilter.today:
        return (today, now);
      case DateFilter.yesterday:
        final yesterday = today.subtract(const Duration(days: 1));
        return (yesterday, today.subtract(const Duration(milliseconds: 1)));
      case DateFilter.thisWeek:
        final startOfWeek = today.subtract(Duration(days: today.weekday - 1));
        return (startOfWeek, now);
      case DateFilter.thisMonth:
        final startOfMonth = DateTime(now.year, now.month, 1);
        return (startOfMonth, now);
      case DateFilter.custom:
        return (_customDateFrom, _customDateTo);
    }
  }

  Future<void> _loadData() async {
    setState(() => _isLoading = true);
    try {
      final (dateFrom, dateTo) = _getDateRange();

      final sales = await SalesRepository.listCompletedSales(
        query: _searchQuery.isNotEmpty ? _searchQuery : null,
        dateFrom: dateFrom,
        dateTo: dateTo,
      );
      final returns = await ReturnsRepository.listReturns(
        dateFrom: dateFrom,
        dateTo: dateTo,
      );
      if (mounted) {
        setState(() {
          _completedSales = sales
              .where(
                (s) =>
                    s.kind == 'invoice' &&
                    s.status != 'cancelled' &&
                    s.status != 'REFUNDED',
              )
              .toList();
          _returns = returns;
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
          onRetry: _loadData,
          module: 'sales/returns_list/load',
        );
      }
    }
  }

  List<SaleModel> get _filteredSales {
    if (_searchQuery.isEmpty) return _completedSales;
    final query = _searchQuery.toLowerCase();
    return _completedSales.where((sale) {
      return sale.localCode.toLowerCase().contains(query) ||
          (sale.customerNameSnapshot?.toLowerCase().contains(query) ?? false) ||
          sale.total.toString().contains(query);
    }).toList();
  }

  void _showError(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), backgroundColor: AppColors.error),
    );
  }

  void _showSuccess(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), backgroundColor: AppColors.success),
    );
  }

  void _handleBack() {
    final router = GoRouter.of(context);
    if (router.canPop()) {
      context.pop();
      return;
    }

    // Esta pantalla suele abrirse con context.go('/returns-list'),
    // así que no hay stack para hacer pop. Volver a Ventas.
    context.go('/sales');
  }

  String _getFilterLabel(DateFilter filter) {
    switch (filter) {
      case DateFilter.all:
        return 'Todas';
      case DateFilter.today:
        return 'Hoy';
      case DateFilter.yesterday:
        return 'Ayer';
      case DateFilter.thisWeek:
        return 'Esta Semana';
      case DateFilter.thisMonth:
        return 'Este Mes';
      case DateFilter.custom:
        if (_customDateFrom != null && _customDateTo != null) {
          final format = DateFormat('dd/MM');
          return '${format.format(_customDateFrom!)} - ${format.format(_customDateTo!)}';
        }
        return 'Personalizado';
    }
  }

  Future<void> _selectCustomDateRange() async {
    final now = DateTime.now();
    final result = await showDateRangePicker(
      context: context,
      firstDate: DateTime(2020),
      lastDate: now,
      initialDateRange: DateTimeRange(
        start: _customDateFrom ?? now.subtract(const Duration(days: 7)),
        end: _customDateTo ?? now,
      ),
      builder: (context, child) {
        return Theme(
          data: Theme.of(context).copyWith(
            colorScheme: const ColorScheme.light(primary: AppColors.teal700),
          ),
          child: child!,
        );
      },
    );

    if (result != null) {
      setState(() {
        _customDateFrom = result.start;
        _customDateTo = result.end;
        _selectedFilter = DateFilter.custom;
      });
      _loadData();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFFF5F5F5),
      body: Column(
        children: [
          _buildHeader(),
          Expanded(
            child: _isLoading
                ? const Center(
                    child: CircularProgressIndicator(color: AppColors.teal700),
                  )
                : TabBarView(
                    controller: _tabController,
                    children: [_buildSalesTab(), _buildHistoryTab()],
                  ),
          ),
        ],
      ),
    );
  }

  Widget _buildHeader() {
    return Container(
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          colors: [AppColors.teal700, AppColors.teal800],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.15),
            blurRadius: 8,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: SafeArea(
        bottom: false,
        child: Column(
          children: [
            // Título y botones
            Padding(
              padding: const EdgeInsets.fromLTRB(8, 12, 16, 8),
              child: Row(
                children: [
                  IconButton(
                    onPressed: _handleBack,
                    icon: const Icon(Icons.arrow_back, color: Colors.white),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'Devoluciones',
                          style: TextStyle(
                            color: Colors.white,
                            fontSize: 20,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        Text(
                          '${_filteredSales.length} ventas encontradas',
                          style: TextStyle(
                            color: Colors.white.withOpacity(0.8),
                            fontSize: 12,
                          ),
                        ),
                      ],
                    ),
                  ),
                  IconButton(
                    onPressed: _loadData,
                    icon: const Icon(Icons.refresh, color: Colors.white),
                    tooltip: 'Actualizar',
                  ),
                ],
              ),
            ),

            // Filtros de fecha
            Container(
              height: 42,
              margin: const EdgeInsets.symmetric(horizontal: 16),
              child: ListView(
                scrollDirection: Axis.horizontal,
                children: [
                  _buildFilterChip(DateFilter.today),
                  _buildFilterChip(DateFilter.yesterday),
                  _buildFilterChip(DateFilter.thisWeek),
                  _buildFilterChip(DateFilter.thisMonth),
                  _buildFilterChip(DateFilter.all),
                  const SizedBox(width: 8),
                  ActionChip(
                    avatar: Icon(
                      Icons.date_range,
                      size: 18,
                      color: _selectedFilter == DateFilter.custom
                          ? Colors.white
                          : AppColors.teal700,
                    ),
                    label: Text(
                      _selectedFilter == DateFilter.custom
                          ? _getFilterLabel(DateFilter.custom)
                          : 'Rango',
                      style: TextStyle(
                        color: _selectedFilter == DateFilter.custom
                            ? Colors.white
                            : AppColors.teal700,
                        fontWeight: FontWeight.w500,
                        fontSize: 13,
                      ),
                    ),
                    backgroundColor: _selectedFilter == DateFilter.custom
                        ? AppColors.teal700
                        : Colors.white,
                    onPressed: _selectCustomDateRange,
                  ),
                ],
              ),
            ),
            const SizedBox(height: 12),

            // Búsqueda
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Container(
                height: 44,
                decoration: BoxDecoration(
                  color: Colors.white.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: TextField(
                  controller: _searchController,
                  onChanged: (value) {
                    setState(() => _searchQuery = value);
                  },
                  style: const TextStyle(color: Colors.white, fontSize: 14),
                  decoration: InputDecoration(
                    hintText: 'Buscar por código o cliente...',
                    hintStyle: TextStyle(color: Colors.white.withOpacity(0.6)),
                    prefixIcon: Icon(
                      Icons.search,
                      color: Colors.white.withOpacity(0.7),
                      size: 20,
                    ),
                    suffixIcon: _searchQuery.isNotEmpty
                        ? IconButton(
                            icon: Icon(
                              Icons.clear,
                              color: Colors.white.withOpacity(0.7),
                              size: 18,
                            ),
                            onPressed: () {
                              _searchController.clear();
                              setState(() => _searchQuery = '');
                            },
                          )
                        : null,
                    border: InputBorder.none,
                    contentPadding: const EdgeInsets.symmetric(
                      horizontal: 16,
                      vertical: 12,
                    ),
                  ),
                ),
              ),
            ),
            const SizedBox(height: 12),

            // Tabs
            Container(
              decoration: BoxDecoration(
                color: AppColors.teal800.withOpacity(0.5),
              ),
              child: TabBar(
                controller: _tabController,
                indicatorColor: Colors.white,
                indicatorWeight: 3,
                labelColor: Colors.white,
                unselectedLabelColor: Colors.white60,
                labelStyle: const TextStyle(
                  fontWeight: FontWeight.w600,
                  fontSize: 13,
                ),
                tabs: const [
                  Tab(
                    icon: Icon(Icons.receipt_long, size: 18),
                    text: 'Ventas',
                    height: 50,
                  ),
                  Tab(
                    icon: Icon(Icons.history, size: 18),
                    text: 'Historial',
                    height: 50,
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildFilterChip(DateFilter filter) {
    final isSelected = _selectedFilter == filter;
    return Padding(
      padding: const EdgeInsets.only(right: 8),
      child: ChoiceChip(
        label: Text(
          _getFilterLabel(filter),
          style: TextStyle(
            color: isSelected ? Colors.white : AppColors.teal700,
            fontWeight: FontWeight.w500,
            fontSize: 13,
          ),
        ),
        selected: isSelected,
        selectedColor: AppColors.teal700,
        backgroundColor: Colors.white,
        onSelected: (selected) {
          if (selected) {
            setState(() => _selectedFilter = filter);
            _loadData();
          }
        },
      ),
    );
  }

  Widget _buildSalesTab() {
    final currencyFormat = NumberFormat.currency(
      locale: 'es_DO',
      symbol: 'RD\$',
    );
    final dateFormat = DateFormat('dd/MM/yyyy HH:mm');

    if (_filteredSales.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.receipt_long_outlined,
              size: 80,
              color: Colors.grey.shade300,
            ),
            const SizedBox(height: 16),
            Text(
              _searchQuery.isEmpty
                  ? 'No hay ventas en este período'
                  : 'No se encontraron resultados',
              style: TextStyle(
                color: Colors.grey.shade600,
                fontSize: 16,
                fontWeight: FontWeight.w500,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'Prueba cambiando el filtro de fecha',
              style: TextStyle(color: Colors.grey.shade500, fontSize: 13),
            ),
          ],
        ),
      );
    }

    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: _filteredSales.length,
      itemBuilder: (context, index) {
        final sale = _filteredSales[index];
        final date = DateTime.fromMillisecondsSinceEpoch(sale.createdAtMs);
        final hasPartialRefund = sale.status == 'PARTIAL_REFUND';

        return Card(
          margin: const EdgeInsets.only(bottom: 10),
          elevation: 2,
          shadowColor: Colors.black.withOpacity(0.1),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
          child: InkWell(
            onTap: () => _showSaleDetails(sale),
            borderRadius: BorderRadius.circular(12),
            child: Padding(
              padding: const EdgeInsets.all(14),
              child: Row(
                children: [
                  // Icono
                  Container(
                    width: 50,
                    height: 50,
                    decoration: BoxDecoration(
                      gradient: LinearGradient(
                        colors: hasPartialRefund
                            ? [AppColors.teal500, AppColors.teal700]
                            : [Colors.green.shade400, Colors.green.shade600],
                        begin: Alignment.topLeft,
                        end: Alignment.bottomRight,
                      ),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Icon(
                      hasPartialRefund ? Icons.replay : Icons.receipt_outlined,
                      color: Colors.white,
                      size: 24,
                    ),
                  ),
                  const SizedBox(width: 14),
                  // Info
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Text(
                              sale.localCode,
                              style: const TextStyle(
                                fontWeight: FontWeight.bold,
                                fontSize: 15,
                              ),
                            ),
                            if (hasPartialRefund) ...[
                              const SizedBox(width: 8),
                              Container(
                                padding: const EdgeInsets.symmetric(
                                  horizontal: 6,
                                  vertical: 2,
                                ),
                                decoration: BoxDecoration(
                                  color: AppColors.teal300.withOpacity(0.3),
                                  borderRadius: BorderRadius.circular(4),
                                ),
                                child: const Text(
                                  'Parcial',
                                  style: TextStyle(
                                    fontSize: 9,
                                    fontWeight: FontWeight.w600,
                                    color: AppColors.teal800,
                                  ),
                                ),
                              ),
                            ],
                          ],
                        ),
                        const SizedBox(height: 4),
                        Row(
                          children: [
                            Icon(
                              Icons.person_outline,
                              size: 14,
                              color: Colors.grey.shade500,
                            ),
                            const SizedBox(width: 4),
                            Expanded(
                              child: Text(
                                sale.customerNameSnapshot ?? 'Cliente General',
                                style: TextStyle(
                                  fontSize: 13,
                                  color: Colors.grey.shade700,
                                ),
                                overflow: TextOverflow.ellipsis,
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 2),
                        Row(
                          children: [
                            Icon(
                              Icons.access_time,
                              size: 12,
                              color: Colors.grey.shade400,
                            ),
                            const SizedBox(width: 4),
                            Text(
                              dateFormat.format(date),
                              style: TextStyle(
                                fontSize: 11,
                                color: Colors.grey.shade500,
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                  // Total y acciones
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.end,
                    children: [
                      Text(
                        currencyFormat.format(sale.total),
                        style: TextStyle(
                          fontWeight: FontWeight.bold,
                          fontSize: 16,
                          color: Colors.green.shade700,
                        ),
                      ),
                      const SizedBox(height: 6),
                      Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          // Ver ticket
                          InkWell(
                            onTap: () => _showSaleDetails(sale),
                            borderRadius: BorderRadius.circular(6),
                            child: Container(
                              padding: const EdgeInsets.all(6),
                              decoration: BoxDecoration(
                                color: Colors.blue.shade50,
                                borderRadius: BorderRadius.circular(6),
                              ),
                              child: Icon(
                                Icons.visibility,
                                size: 18,
                                color: Colors.blue.shade700,
                              ),
                            ),
                          ),
                          const SizedBox(width: 6),
                          // Devolver
                          InkWell(
                            onTap: () => _showRefundDialog(sale),
                            borderRadius: BorderRadius.circular(6),
                            child: Container(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 10,
                                vertical: 6,
                              ),
                              decoration: BoxDecoration(
                                color: AppColors.teal700.withOpacity(0.1),
                                borderRadius: BorderRadius.circular(6),
                                border: Border.all(color: AppColors.teal400),
                              ),
                              child: const Row(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  Icon(
                                    Icons.keyboard_return,
                                    size: 14,
                                    color: AppColors.teal700,
                                  ),
                                  SizedBox(width: 4),
                                  Text(
                                    'Devolver',
                                    style: TextStyle(
                                      fontSize: 11,
                                      fontWeight: FontWeight.w600,
                                      color: AppColors.teal700,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildHistoryTab() {
    final currencyFormat = NumberFormat.currency(
      locale: 'es_DO',
      symbol: 'RD\$',
    );
    final dateFormat = DateFormat('dd/MM/yyyy HH:mm');

    if (_returns.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.history, size: 80, color: Colors.grey.shade300),
            const SizedBox(height: 16),
            Text(
              'No hay devoluciones en este período',
              style: TextStyle(
                color: Colors.grey.shade600,
                fontSize: 16,
                fontWeight: FontWeight.w500,
              ),
            ),
          ],
        ),
      );
    }

    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: _returns.length,
      itemBuilder: (context, index) {
        final ret = _returns[index];
        final date = DateTime.fromMillisecondsSinceEpoch(
          ret['created_at_ms'] as int,
        );
        final total = (ret['total'] as num?)?.toDouble().abs() ?? 0.0;

        return Card(
          margin: const EdgeInsets.only(bottom: 10),
          elevation: 2,
          shadowColor: Colors.black.withOpacity(0.1),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
          child: Padding(
            padding: const EdgeInsets.all(14),
            child: Row(
              children: [
                Container(
                  width: 50,
                  height: 50,
                  decoration: BoxDecoration(
                    gradient: const LinearGradient(
                      colors: [AppColors.teal500, AppColors.teal700],
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                    ),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: const Icon(
                    Icons.keyboard_return_rounded,
                    color: Colors.white,
                    size: 24,
                  ),
                ),
                const SizedBox(width: 14),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        ret['local_code'] ?? 'DEV-${ret['id']}',
                        style: const TextStyle(
                          fontWeight: FontWeight.bold,
                          fontSize: 15,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Row(
                        children: [
                          Icon(
                            Icons.person_outline,
                            size: 14,
                            color: Colors.grey.shade500,
                          ),
                          const SizedBox(width: 4),
                          Expanded(
                            child: Text(
                              ret['customer_name_snapshot'] ??
                                  'Cliente General',
                              style: TextStyle(
                                fontSize: 13,
                                color: Colors.grey.shade700,
                              ),
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 2),
                      Text(
                        dateFormat.format(date),
                        style: TextStyle(
                          fontSize: 11,
                          color: Colors.grey.shade500,
                        ),
                      ),
                    ],
                  ),
                ),
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 10,
                    vertical: 6,
                  ),
                  decoration: BoxDecoration(
                    color: AppColors.teal400.withOpacity(0.2),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Text(
                    currencyFormat.format(total),
                    style: const TextStyle(
                      fontWeight: FontWeight.bold,
                      fontSize: 14,
                      color: AppColors.teal700,
                    ),
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  /// Muestra detalles de la venta con opción de imprimir
  Future<void> _showSaleDetails(SaleModel sale) async {
    final items = await SalesRepository.getItemsBySaleId(sale.id!);
    if (!mounted) return;

    showDialog(
      context: context,
      builder: (context) => _SaleTicketDialog(
        sale: sale,
        items: items,
        onPrint: () => _printTicket(sale, items),
        onRefund: () {
          Navigator.pop(context);
          _showRefundDialog(sale);
        },
      ),
    );
  }

  /// Imprime el ticket
  Future<void> _printTicket(SaleModel sale, List<SaleItemModel> items) async {
    try {
      final settings = await PrinterSettingsRepository.getOrCreate();
      if (settings.selectedPrinterName == null ||
          settings.selectedPrinterName!.isEmpty) {
        _showError('No hay impresora configurada');
        return;
      }

      // Obtener nombre del cajero desde la sesión
      final cashierName = await SessionManager.displayName() ?? 'Cajero';

      final result = await UnifiedTicketPrinter.printSaleTicket(
        sale: sale,
        items: items,
        cashierName: cashierName,
      );
      if (result.success) {
        _showSuccess('Ticket impreso correctamente');
      } else {
        _showError('No se pudo imprimir. Verifique la impresora y reintente.');
      }
    } catch (e, st) {
      await ErrorHandler.instance.handle(
        e,
        stackTrace: st,
        context: context,
        onRetry: () => _printTicket(sale, items),
        module: 'sales/returns_list/print',
      );
    }
  }

  /// Muestra el diálogo de reembolso
  Future<void> _showRefundDialog(SaleModel sale) async {
    final saleId = sale.id;
    if (saleId == null) {
      _showError('No se puede procesar: ticket inválido (sin ID).');
      return;
    }

    try {
      final items = await SalesRepository.getItemsBySaleId(saleId);
      if (!mounted) return;

      // Evita pantalla negra por force-unwraps si existieran items corruptos.
      if (items.any((i) => i.id == null)) {
        _showError('No se puede procesar: hay productos del ticket sin ID.');
        return;
      }

      final result = await showDialog<_RefundDialogResult>(
        context: context,
        barrierDismissible: false,
        builder: (context) => _RefundDialog(sale: sale, items: items),
      );

      if (result == _RefundDialogResult.refunded) {
        _showSuccess('¡Devolución procesada!');
        _loadData();
      } else if (result == _RefundDialogResult.cancelled) {
        _showSuccess('✅ Ticket cancelado y stock restaurado');
        _loadData();
      }
    } catch (e, st) {
      if (!mounted) return;
      await ErrorHandler.instance.handle(
        e,
        stackTrace: st,
        context: context,
        onRetry: () => _showRefundDialog(sale),
        module: 'sales/returns_list/refund_dialog',
      );
    }
  }
}

enum _RefundDialogResult { refunded, cancelled }

/// Diálogo para ver el ticket de la venta
class _SaleTicketDialog extends StatelessWidget {
  final SaleModel sale;
  final List<SaleItemModel> items;
  final VoidCallback onPrint;
  final VoidCallback onRefund;

  const _SaleTicketDialog({
    required this.sale,
    required this.items,
    required this.onPrint,
    required this.onRefund,
  });

  @override
  Widget build(BuildContext context) {
    final currencyFormat = NumberFormat.currency(
      locale: 'es_DO',
      symbol: 'RD\$',
    );
    final dateFormat = DateFormat('dd/MM/yyyy HH:mm');
    final date = DateTime.fromMillisecondsSinceEpoch(sale.createdAtMs);
    final screenSize = MediaQuery.of(context).size;

    return Dialog(
      backgroundColor: Colors.transparent,
      insetPadding: EdgeInsets.symmetric(
        horizontal: screenSize.width * 0.05,
        vertical: screenSize.height * 0.05,
      ),
      child: Container(
        constraints: BoxConstraints(
          maxWidth: 450,
          maxHeight: screenSize.height * 0.85,
        ),
        decoration: BoxDecoration(
          color: Colors.white,
          borderRadius: BorderRadius.circular(16),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withOpacity(0.2),
              blurRadius: 20,
              offset: const Offset(0, 10),
            ),
          ],
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Header
            Container(
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: [AppColors.teal700, AppColors.teal800],
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                ),
                borderRadius: const BorderRadius.only(
                  topLeft: Radius.circular(16),
                  topRight: Radius.circular(16),
                ),
              ),
              child: Column(
                children: [
                  Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.all(10),
                        decoration: BoxDecoration(
                          color: Colors.white.withOpacity(0.2),
                          borderRadius: BorderRadius.circular(10),
                        ),
                        child: const Icon(
                          Icons.receipt_long,
                          color: Colors.white,
                          size: 28,
                        ),
                      ),
                      const SizedBox(width: 14),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              sale.localCode,
                              style: const TextStyle(
                                color: Colors.white,
                                fontSize: 20,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                            const SizedBox(height: 4),
                            Text(
                              dateFormat.format(date),
                              style: TextStyle(
                                color: Colors.white.withOpacity(0.8),
                                fontSize: 13,
                              ),
                            ),
                          ],
                        ),
                      ),
                      IconButton(
                        onPressed: () => Navigator.pop(context),
                        icon: const Icon(Icons.close, color: Colors.white),
                        style: IconButton.styleFrom(
                          backgroundColor: Colors.white.withOpacity(0.2),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),
                  // Info del cliente
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: Colors.white.withOpacity(0.15),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: Row(
                      children: [
                        const Icon(Icons.person, color: Colors.white, size: 20),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Text(
                            sale.customerNameSnapshot ?? 'Cliente General',
                            style: const TextStyle(
                              color: Colors.white,
                              fontWeight: FontWeight.w500,
                              fontSize: 15,
                            ),
                          ),
                        ),
                        Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 8,
                            vertical: 4,
                          ),
                          decoration: BoxDecoration(
                            color: Colors.white.withOpacity(0.2),
                            borderRadius: BorderRadius.circular(6),
                          ),
                          child: Text(
                            sale.paymentMethod?.toUpperCase() ?? 'EFECTIVO',
                            style: const TextStyle(
                              color: Colors.white,
                              fontWeight: FontWeight.w600,
                              fontSize: 11,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),

            // Lista de productos
            Flexible(
              child: ListView.separated(
                shrinkWrap: true,
                padding: const EdgeInsets.all(16),
                itemCount: items.length,
                separatorBuilder: (_, __) => const Divider(height: 1),
                itemBuilder: (context, index) {
                  final item = items[index];
                  return Padding(
                    padding: const EdgeInsets.symmetric(vertical: 10),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Container(
                          width: 32,
                          height: 32,
                          decoration: BoxDecoration(
                            color: AppColors.teal.withOpacity(0.1),
                            borderRadius: BorderRadius.circular(8),
                          ),
                          alignment: Alignment.center,
                          child: Text(
                            '${item.qty.toInt()}',
                            style: TextStyle(
                              fontWeight: FontWeight.bold,
                              color: AppColors.teal700,
                              fontSize: 14,
                            ),
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                item.productNameSnapshot,
                                style: const TextStyle(
                                  fontWeight: FontWeight.w500,
                                  fontSize: 14,
                                ),
                              ),
                              const SizedBox(height: 2),
                              Text(
                                '${currencyFormat.format(item.unitPrice)} c/u',
                                style: TextStyle(
                                  fontSize: 12,
                                  color: Colors.grey.shade600,
                                ),
                              ),
                            ],
                          ),
                        ),
                        Text(
                          currencyFormat.format(item.totalLine),
                          style: const TextStyle(
                            fontWeight: FontWeight.w600,
                            fontSize: 14,
                          ),
                        ),
                      ],
                    ),
                  );
                },
              ),
            ),

            // Totales
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.grey.shade50,
                border: Border(top: BorderSide(color: Colors.grey.shade200)),
              ),
              child: Column(
                children: [
                  _buildTotalRow(
                    'Subtotal',
                    currencyFormat.format(sale.subtotal),
                  ),
                  if (sale.itbisEnabled == 1)
                    _buildTotalRow(
                      'ITBIS (18%)',
                      currencyFormat.format(sale.itbisAmount),
                    ),
                  if (sale.discountTotal > 0)
                    _buildTotalRow(
                      'Descuento',
                      '-${currencyFormat.format(sale.discountTotal)}',
                      valueColor: AppColors.error,
                    ),
                  const SizedBox(height: 8),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      const Text(
                        'TOTAL',
                        style: TextStyle(
                          fontWeight: FontWeight.bold,
                          fontSize: 18,
                        ),
                      ),
                      Text(
                        currencyFormat.format(sale.total),
                        style: TextStyle(
                          fontWeight: FontWeight.bold,
                          fontSize: 22,
                          color: AppColors.teal700,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),

            // Botones de acción
            Container(
              padding: const EdgeInsets.all(16),
              child: Row(
                children: [
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: onPrint,
                      icon: const Icon(Icons.print, size: 20),
                      label: const Text('Imprimir'),
                      style: OutlinedButton.styleFrom(
                        foregroundColor: AppColors.teal700,
                        side: BorderSide(color: AppColors.teal700),
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(10),
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: ElevatedButton.icon(
                      onPressed: onRefund,
                      icon: const Icon(Icons.keyboard_return, size: 20),
                      label: const Text('Devolver'),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: AppColors.teal700,
                        foregroundColor: Colors.white,
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(10),
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildTotalRow(String label, String value, {Color? valueColor}) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: TextStyle(color: Colors.grey.shade600, fontSize: 14),
          ),
          Text(value, style: TextStyle(fontSize: 14, color: valueColor)),
        ],
      ),
    );
  }
}

/// Diálogo de reembolso
class _RefundDialog extends StatefulWidget {
  final SaleModel sale;
  final List<SaleItemModel> items;

  const _RefundDialog({required this.sale, required this.items});

  @override
  State<_RefundDialog> createState() => _RefundDialogState();
}

class _RefundDialogState extends State<_RefundDialog> {
  late final List<double> _returnQuantities;
  final _noteController = TextEditingController();
  bool _isProcessing = false;
  bool _refundAll = false;

  @override
  void initState() {
    super.initState();
    _returnQuantities = List<double>.filled(widget.items.length, 0);
  }

  @override
  void dispose() {
    _noteController.dispose();
    super.dispose();
  }

  double get _totalReturn {
    double total = 0;
    for (var i = 0; i < widget.items.length; i++) {
      final item = widget.items[i];
      final qty = _returnQuantities[i];
      total += qty * item.unitPrice;
    }
    if (widget.sale.itbisEnabled == 1) {
      total += total * widget.sale.itbisRate;
    }
    return total;
  }

  bool get _hasSelectedItems => _returnQuantities.any((qty) => qty > 0);

  void _toggleRefundAll() {
    setState(() {
      _refundAll = !_refundAll;
      for (var i = 0; i < widget.items.length; i++) {
        _returnQuantities[i] = _refundAll ? widget.items[i].qty : 0;
      }
    });
  }

  Future<void> _processRefund() async {
    if (!_hasSelectedItems) return;

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: const Row(
          children: [
            Icon(Icons.warning_amber_rounded, color: AppColors.teal700),
            SizedBox(width: 10),
            Text('Confirmar Devolución'),
          ],
        ),
        content: Text(
          '¿Procesar devolución por ${NumberFormat.currency(locale: 'es_DO', symbol: 'RD\$').format(_totalReturn)}?',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancelar'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.teal700,
              foregroundColor: Colors.white,
            ),
            child: const Text('Confirmar'),
          ),
        ],
      ),
    );

    if (confirmed != true) return;

    final authorized = await requireAuthorizationIfNeeded(
      context: context,
      action: AppActions.cancelSale,
      resourceType: 'sale',
      resourceId: widget.sale.id?.toString(),
      reason: 'Anular ticket',
    );
    if (!authorized) return;

    setState(() => _isProcessing = true);

    try {
      final returnItems = <Map<String, dynamic>>[];
      for (var i = 0; i < widget.items.length; i++) {
        final item = widget.items[i];
        final qty = _returnQuantities[i];
        if (qty > 0) {
          final saleItemId = item.id;
          if (saleItemId == null) {
            throw StateError('Item inválido: sale_item_id nulo');
          }
          returnItems.add({
            'sale_item_id': saleItemId,
            'product_id': item.productId,
            'description': item.productNameSnapshot,
            'qty': qty,
            'price': item.unitPrice,
          });
        }
      }

      await ReturnsRepository.createReturn(
        originalSaleId: widget.sale.id!,
        returnItems: returnItems,
        note: _noteController.text.isEmpty ? null : _noteController.text,
      );

      if (mounted) Navigator.pop(context, _RefundDialogResult.refunded);
    } catch (e, st) {
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: _processRefund,
          module: 'sales/returns_list/refund',
        );
      }
    } finally {
      if (mounted) setState(() => _isProcessing = false);
    }
  }

  Future<void> _cancelFullSale() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: Row(
          children: [
            Icon(Icons.cancel, color: AppColors.error),
            const SizedBox(width: 10),
            const Text('Anular Venta'),
          ],
        ),
        content: const Text(
          '¿Seguro que desea ANULAR este ticket?\n\nEsta acción es seria e irreversible. Se restaurará todo el stock.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancelar'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.error,
              foregroundColor: Colors.white,
            ),
            child: const Text('Anular'),
          ),
        ],
      ),
    );

    if (confirmed != true) return;

    setState(() => _isProcessing = true);

    try {
      final saleId = widget.sale.id;
      if (saleId == null) {
        throw StateError('Ticket inválido (sin ID)');
      }

      final ok = await SalesRepository.cancelSale(saleId);
      if (!ok) {
        throw StateError('No se pudo anular (posiblemente ya estaba anulada)');
      }

      if (mounted) Navigator.pop(context, _RefundDialogResult.cancelled);
    } catch (e, st) {
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: _cancelFullSale,
          module: 'sales/returns_list/cancel',
        );
      }
    } finally {
      if (mounted) setState(() => _isProcessing = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final currencyFormat = NumberFormat.currency(
      locale: 'es_DO',
      symbol: 'RD\$',
    );
    final screenSize = MediaQuery.of(context).size;

    return Dialog(
      backgroundColor: Colors.transparent,
      insetPadding: EdgeInsets.symmetric(
        horizontal: screenSize.width * 0.05,
        vertical: screenSize.height * 0.05,
      ),
      child: Container(
        constraints: BoxConstraints(
          maxWidth: 500,
          maxHeight: screenSize.height * 0.85,
        ),
        decoration: BoxDecoration(
          color: Colors.white,
          borderRadius: BorderRadius.circular(16),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withOpacity(0.2),
              blurRadius: 20,
              offset: const Offset(0, 10),
            ),
          ],
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Header
            Container(
              padding: const EdgeInsets.all(20),
              decoration: const BoxDecoration(
                gradient: LinearGradient(
                  colors: [AppColors.teal600, AppColors.teal800],
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                ),
                borderRadius: BorderRadius.only(
                  topLeft: Radius.circular(16),
                  topRight: Radius.circular(16),
                ),
              ),
              child: Row(
                children: [
                  const Icon(
                    Icons.keyboard_return_rounded,
                    color: Colors.white,
                    size: 28,
                  ),
                  const SizedBox(width: 14),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'Procesar Devolución',
                          style: TextStyle(
                            color: Colors.white,
                            fontSize: 18,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        Text(
                          widget.sale.localCode,
                          style: TextStyle(
                            color: Colors.white.withOpacity(0.8),
                            fontSize: 13,
                          ),
                        ),
                      ],
                    ),
                  ),
                  IconButton(
                    onPressed: _isProcessing
                        ? null
                        : () => Navigator.pop(context),
                    icon: const Icon(Icons.close, color: Colors.white),
                  ),
                ],
              ),
            ),

            // Seleccionar todo
            Padding(
              padding: const EdgeInsets.all(16),
              child: Row(
                children: [
                  Text(
                    'Productos',
                    style: TextStyle(
                      fontWeight: FontWeight.w600,
                      color: Colors.grey.shade700,
                    ),
                  ),
                  const Spacer(),
                  TextButton.icon(
                    onPressed: _toggleRefundAll,
                    icon: Icon(
                      _refundAll
                          ? Icons.check_box
                          : Icons.check_box_outline_blank,
                      size: 18,
                    ),
                    label: Text(
                      _refundAll ? 'Deseleccionar' : 'Seleccionar todo',
                    ),
                    style: TextButton.styleFrom(
                      foregroundColor: AppColors.teal700,
                    ),
                  ),
                ],
              ),
            ),

            // Lista de productos
            Flexible(
              child: ListView.separated(
                shrinkWrap: true,
                padding: const EdgeInsets.symmetric(horizontal: 16),
                itemCount: widget.items.length,
                separatorBuilder: (_, __) => const Divider(height: 1),
                itemBuilder: (context, index) {
                  final item = widget.items[index];
                  final returnQty = _returnQuantities[index];
                  final isSelected = returnQty > 0;

                  return Padding(
                    padding: const EdgeInsets.symmetric(vertical: 10),
                    child: Row(
                      children: [
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                item.productNameSnapshot,
                                style: TextStyle(
                                  fontWeight: FontWeight.w500,
                                  color: isSelected
                                      ? AppColors.teal700
                                      : Colors.black87,
                                ),
                              ),
                              Text(
                                '${currencyFormat.format(item.unitPrice)} × ${item.qty.toInt()}',
                                style: TextStyle(
                                  fontSize: 12,
                                  color: Colors.grey.shade600,
                                ),
                              ),
                            ],
                          ),
                        ),
                        Container(
                          decoration: BoxDecoration(
                            color: isSelected
                                ? AppColors.teal700.withOpacity(0.1)
                                : Colors.grey.shade100,
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(
                              color: isSelected
                                  ? AppColors.teal400
                                  : Colors.grey.shade300,
                            ),
                          ),
                          child: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              IconButton(
                                icon: Icon(
                                  Icons.remove,
                                  size: 18,
                                  color: returnQty > 0
                                      ? AppColors.teal700
                                      : Colors.grey,
                                ),
                                onPressed: returnQty > 0
                                    ? () => setState(() {
                                        _returnQuantities[index] =
                                            returnQty - 1;
                                        _refundAll = false;
                                      })
                                    : null,
                                constraints: const BoxConstraints(
                                  minWidth: 36,
                                  minHeight: 36,
                                ),
                              ),
                              SizedBox(
                                width: 32,
                                child: Text(
                                  '${returnQty.toInt()}',
                                  textAlign: TextAlign.center,
                                  style: TextStyle(
                                    fontWeight: FontWeight.bold,
                                    color: isSelected
                                        ? AppColors.teal700
                                        : Colors.grey,
                                  ),
                                ),
                              ),
                              IconButton(
                                icon: Icon(
                                  Icons.add,
                                  size: 18,
                                  color: returnQty < item.qty
                                      ? AppColors.teal700
                                      : Colors.grey,
                                ),
                                onPressed: returnQty < item.qty
                                    ? () => setState(
                                        () => _returnQuantities[index] =
                                            returnQty + 1,
                                      )
                                    : null,
                                constraints: const BoxConstraints(
                                  minWidth: 36,
                                  minHeight: 36,
                                ),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                  );
                },
              ),
            ),

            // Nota
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
              child: TextField(
                controller: _noteController,
                maxLines: 2,
                decoration: InputDecoration(
                  hintText: 'Motivo (opcional)',
                  hintStyle: TextStyle(
                    fontSize: 13,
                    color: Colors.grey.shade500,
                  ),
                  filled: true,
                  fillColor: Colors.grey.shade50,
                  contentPadding: const EdgeInsets.all(12),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                    borderSide: BorderSide.none,
                  ),
                ),
              ),
            ),

            // Footer
            Container(
              margin: const EdgeInsets.all(16),
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: _hasSelectedItems
                    ? AppColors.teal700.withOpacity(0.1)
                    : Colors.grey.shade100,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(
                  color: _hasSelectedItems
                      ? AppColors.teal400
                      : Colors.grey.shade300,
                ),
              ),
              child: Column(
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      const Text(
                        'Total a reembolsar:',
                        style: TextStyle(fontWeight: FontWeight.w500),
                      ),
                      Text(
                        currencyFormat.format(_totalReturn),
                        style: TextStyle(
                          fontWeight: FontWeight.bold,
                          fontSize: 20,
                          color: _hasSelectedItems
                              ? AppColors.teal700
                              : Colors.grey,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),
                  Row(
                    children: [
                      Expanded(
                        child: OutlinedButton.icon(
                          onPressed: _isProcessing ? null : _cancelFullSale,
                          icon: const Icon(Icons.cancel_outlined, size: 18),
                          label: const Text('Anular'),
                          style: OutlinedButton.styleFrom(
                            foregroundColor: AppColors.error,
                            side: BorderSide(color: AppColors.error),
                            padding: const EdgeInsets.symmetric(vertical: 12),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(8),
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        flex: 2,
                        child: ElevatedButton.icon(
                          onPressed: _hasSelectedItems && !_isProcessing
                              ? _processRefund
                              : null,
                          icon: _isProcessing
                              ? const SizedBox(
                                  width: 18,
                                  height: 18,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                    color: Colors.white,
                                  ),
                                )
                              : const Icon(Icons.check_circle, size: 18),
                          label: Text(
                            _isProcessing ? 'Procesando...' : 'Procesar',
                          ),
                          style: ElevatedButton.styleFrom(
                            backgroundColor: AppColors.teal700,
                            foregroundColor: Colors.white,
                            disabledBackgroundColor: Colors.grey.shade300,
                            padding: const EdgeInsets.symmetric(vertical: 12),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(8),
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

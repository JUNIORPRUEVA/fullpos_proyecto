import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';
import '../../../core/constants/app_colors.dart';
import '../../../core/printing/reports_printer.dart';
import '../../../core/utils/app_event_bus.dart';
import '../data/reports_repository.dart';
import 'widgets/date_range_selector.dart';
import 'widgets/advanced_kpi_cards.dart';
import 'widgets/sales_bar_chart.dart';
import 'widgets/payment_method_pie_chart.dart';
import 'widgets/loans_report_table.dart';
import 'widgets/pending_payments_table.dart';
import 'widgets/comparative_stats_card.dart';
import 'widgets/top_products_table.dart';
import 'widgets/top_clients_table.dart';

class ReportsPage extends StatefulWidget {
  const ReportsPage({super.key});

  @override
  State<ReportsPage> createState() => _ReportsPageState();
}

class _ReportsPageState extends State<ReportsPage>
    with SingleTickerProviderStateMixin {
  DateRangePeriod _selectedPeriod = DateRangePeriod.month;
  DateTime? _customStart;
  DateTime? _customEnd;

  late TabController _tabController;
  bool _isLoading = true;
  StreamSubscription<AppEvent>? _eventsSub;

  // Data
  KpisData? _kpis;
  List<SeriesDataPoint> _salesSeries = [];
  List<SeriesDataPoint> _profitSeries = [];
  List<SeriesDataPoint> _loansSeries = [];
  List<PaymentMethodData> _paymentMethods = [];
  List<TopProduct> _topProducts = [];
  List<TopClient> _topClients = [];
  List<LoanReportItem> _activeLoans = [];
  List<PendingPayment> _pendingPayments = [];
  List<SaleRecord> _salesList = [];
  Map<String, dynamic> _comparativeStats = {};

  final Map<String, bool> _pdfSections = {
    'kpis': true,
    'salesSeries': true,
    'paymentMethods': true,
    'profitSeries': true,
    'comparativeStats': true,
    'loansSeries': true,
    'topProducts': true,
    'topClients': true,
    'salesList': true,
    'activeLoans': true,
    'pendingPayments': true,
  };

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 5, vsync: this);
    _eventsSub = AppEventBus.stream.listen((event) {
      if (event is! SaleCompletedEvent) return;

      final range = DateRangeHelper.getRangeForPeriod(
        _selectedPeriod,
        customStart: _customStart,
        customEnd: _customEnd,
      );

      final startMs = range.start.millisecondsSinceEpoch;
      final endMs = range.end.millisecondsSinceEpoch;

      final createdAtMs = event.createdAtMs;
      final isInRange = createdAtMs >= startMs && createdAtMs <= endMs;

      if (!mounted) return;
      if (isInRange) {
        _loadData();
      }
    });
    _loadData();
  }

  @override
  void dispose() {
    _eventsSub?.cancel();
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _loadData() async {
    setState(() => _isLoading = true);

    final range = DateRangeHelper.getRangeForPeriod(
      _selectedPeriod,
      customStart: _customStart,
      customEnd: _customEnd,
    );

    final startMs = range.start.millisecondsSinceEpoch;
    final endMs = range.end.millisecondsSinceEpoch;

    Future<T> _safe<T>(Future<T> Function() run, T fallback) async {
      try {
        return await run();
      } catch (e) {
        debugPrint('Reporte: error obteniendo dato: $e');
        return fallback;
      }
    }

    final kpis = await _safe(
      () => ReportsRepository.getKpis(startMs: startMs, endMs: endMs),
      KpisData(
        totalSales: 0,
        totalProfit: 0,
        salesCount: 0,
        quotesCount: 0,
        quotesConverted: 0,
        avgTicket: 0,
      ),
    );

    final salesSeries = await _safe(
      () => ReportsRepository.getSalesSeries(startMs: startMs, endMs: endMs),
      <SeriesDataPoint>[],
    );

    final profitSeries = await _safe(
      () => ReportsRepository.getProfitSeries(startMs: startMs, endMs: endMs),
      <SeriesDataPoint>[],
    );

    final topProducts = await _safe(
      () => ReportsRepository.getTopProducts(
        startMs: startMs,
        endMs: endMs,
        limit: 10,
      ),
      <TopProduct>[],
    );

    final topClients = await _safe(
      () => ReportsRepository.getTopClients(
        startMs: startMs,
        endMs: endMs,
        limit: 10,
      ),
      <TopClient>[],
    );

    final salesList = await _safe(
      () => ReportsRepository.getSalesList(startMs: startMs, endMs: endMs),
      <SaleRecord>[],
    );

    final paymentMethods = await _safe(
      () => ReportsRepository.getPaymentMethodDistribution(
        startMs: startMs,
        endMs: endMs,
      ),
      <PaymentMethodData>[],
    );

    final activeLoans = await _safe(
      () => ReportsRepository.getActiveLoans(),
      <LoanReportItem>[],
    );

    final pendingPayments = await _safe(
      () => ReportsRepository.getPendingPayments(limit: 50),
      <PendingPayment>[],
    );

    final loansSeries = await _safe(
      () => ReportsRepository.getLoanCollectionsSeries(
        startMs: startMs,
        endMs: endMs,
      ),
      <SeriesDataPoint>[],
    );

    final comparativeStats = await _safe(
      () => ReportsRepository.getComparativeStats(),
      <String, dynamic>{},
    );

    if (!mounted) return;

    setState(() {
      _kpis = kpis;
      _salesSeries = salesSeries;
      _profitSeries = profitSeries;
      _topProducts = topProducts;
      _topClients = topClients;
      _salesList = salesList;
      _paymentMethods = paymentMethods;
      _activeLoans = activeLoans;
      _pendingPayments = pendingPayments;
      _loansSeries = loansSeries;
      _comparativeStats = comparativeStats;
      _isLoading = false;
    });
  }

  void _onPeriodChanged(DateRangePeriod period) {
    setState(() => _selectedPeriod = period);
    _loadData();
  }

  void _onCustomRangeChanged(DateTime start, DateTime end) {
    setState(() {
      _customStart = start;
      _customEnd = end;
    });
    _loadData();
  }

  Future<void> _exportCSV() async {
    final range = DateRangeHelper.getRangeForPeriod(
      _selectedPeriod,
      customStart: _customStart,
      customEnd: _customEnd,
    );

    final startMs = range.start.millisecondsSinceEpoch;
    final endMs = range.end.millisecondsSinceEpoch;

    try {
      final csv = await ReportsRepository.exportToCSV(
        startMs: startMs,
        endMs: endMs,
      );

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('CSV generado: ${csv.split('\n').length - 1} ventas'),
            backgroundColor: AppColors.success,
            action: SnackBarAction(
              label: 'Ver',
              textColor: Colors.white,
              onPressed: () {
                showDialog(
                  context: context,
                  builder: (context) => AlertDialog(
                    title: const Text('CSV Generado'),
                    content: SingleChildScrollView(child: SelectableText(csv)),
                    actions: [
                      TextButton(
                        onPressed: () => Navigator.pop(context),
                        child: const Text('Cerrar'),
                      ),
                    ],
                  ),
                );
              },
            ),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Error al exportar: $e')));
      }
    }
  }

  Future<void> _exportPdf() async {
    if (_isLoading) return;

    final selected = await showDialog<Map<String, bool>>(
      context: context,
      builder: (context) {
        final temp = Map<String, bool>.from(_pdfSections);
        return StatefulBuilder(
          builder: (context, setStateDialog) {
            Widget item(String key, String label) {
              return CheckboxListTile(
                value: temp[key] ?? false,
                onChanged: (v) => setStateDialog(() => temp[key] = v ?? false),
                title: Text(label),
                controlAffinity: ListTileControlAffinity.leading,
                dense: true,
              );
            }

            return AlertDialog(
              title: const Text('Configurar PDF'),
              content: SizedBox(
                width: 520,
                child: SingleChildScrollView(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      item('kpis', 'KPIs'),
                      item('salesSeries', 'Ventas por Período'),
                      item('paymentMethods', 'Métodos de Pago'),
                      item('profitSeries', 'Ganancias por Período'),
                      item('comparativeStats', 'Comparativa de Ventas'),
                      item('loansSeries', 'Cobros de Préstamos'),
                      const Divider(),
                      item('topProducts', 'Top Productos'),
                      item('topClients', 'Top Clientes'),
                      item('salesList', 'Ventas (Listado)'),
                      item('activeLoans', 'Préstamos Activos'),
                      item('pendingPayments', 'Pagos Pendientes'),
                    ],
                  ),
                ),
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: const Text('Cancelar'),
                ),
                ElevatedButton.icon(
                  onPressed: () => Navigator.pop(context, temp),
                  icon: const Icon(Icons.picture_as_pdf),
                  label: const Text('Generar PDF'),
                ),
              ],
            );
          },
        );
      },
    );

    if (selected == null) return;
    _pdfSections
      ..clear()
      ..addAll(selected);

    final range = DateRangeHelper.getRangeForPeriod(
      _selectedPeriod,
      customStart: _customStart,
      customEnd: _customEnd,
    );

    try {
      final pdfBytes = await ReportsPrinter.generatePdf(
        rangeStart: range.start,
        rangeEnd: range.end,
        sections: _pdfSections,
        kpis: _kpis,
        salesSeries: _salesSeries,
        profitSeries: _profitSeries,
        loansSeries: _loansSeries,
        paymentMethods: _paymentMethods,
        topProducts: _topProducts,
        topClients: _topClients,
        activeLoans: _activeLoans,
        pendingPayments: _pendingPayments,
        salesList: _salesList,
        comparativeStats: _comparativeStats,
      );

      final downloadsDir = await getDownloadsDirectory();
      if (downloadsDir == null) {
        throw StateError('No se pudo acceder al directorio de descargas');
      }

      final ts = DateFormat('yyyyMMdd_HHmmss').format(DateTime.now());
      final file = File('${downloadsDir.path}/Reporte_$ts.pdf');
      await file.writeAsBytes(pdfBytes, flush: true);

      // Opción 2: abrir compartir del sistema (Drive aparece si está disponible)
      await Share.shareXFiles([
        XFile(file.path),
      ], text: 'Reporte de Estadísticas');

      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('PDF generado: ${file.path}'),
          backgroundColor: AppColors.success,
        ),
      );
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Error al generar PDF: $e'),
          backgroundColor: AppColors.error,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.bgLight,
      body: Column(
        children: [
          _buildHeader(),
          Expanded(child: _isLoading ? _buildLoadingState() : _buildContent()),
        ],
      ),
    );
  }

  Widget _buildHeader() {
    return Container(
      decoration: BoxDecoration(
        color: Colors.white,
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.05),
            blurRadius: 10,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 12),
            child: Row(
              children: [
                IconButton(
                  icon: const Icon(Icons.arrow_back_rounded),
                  onPressed: () => context.go('/'),
                  tooltip: 'Volver',
                  style: IconButton.styleFrom(
                    backgroundColor: Colors.grey.shade100,
                  ),
                ),
                const SizedBox(width: 12),
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    gradient: const LinearGradient(
                      colors: [AppColors.teal, AppColors.teal700],
                    ),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: const Icon(
                    Icons.analytics,
                    color: Colors.white,
                    size: 24,
                  ),
                ),
                const SizedBox(width: 12),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Dashboard de Reportes',
                      style: TextStyle(
                        fontSize: 22,
                        fontWeight: FontWeight.bold,
                        color: Colors.black87,
                      ),
                    ),
                    Text(
                      'Estadísticas y métricas del negocio',
                      style: TextStyle(
                        fontSize: 13,
                        color: Colors.grey.shade600,
                      ),
                    ),
                  ],
                ),
                const Spacer(),
                _buildActionButton(
                  icon: Icons.picture_as_pdf,
                  label: 'PDF',
                  color: AppColors.error,
                  onPressed: _exportPdf,
                ),
                const SizedBox(width: 8),
                _buildActionButton(
                  icon: Icons.download,
                  label: 'Exportar CSV',
                  color: AppColors.gold,
                  onPressed: _exportCSV,
                ),
                const SizedBox(width: 8),
                IconButton(
                  icon: const Icon(Icons.refresh_rounded),
                  onPressed: _loadData,
                  tooltip: 'Recargar datos',
                  style: IconButton.styleFrom(
                    backgroundColor: AppColors.teal.withOpacity(0.1),
                    foregroundColor: AppColors.teal,
                  ),
                ),
              ],
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
            child: DateRangeSelector(
              selectedPeriod: _selectedPeriod,
              customStart: _customStart,
              customEnd: _customEnd,
              onPeriodChanged: _onPeriodChanged,
              onCustomRangeChanged: _onCustomRangeChanged,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildActionButton({
    required IconData icon,
    required String label,
    required Color color,
    required VoidCallback onPressed,
  }) {
    return ElevatedButton.icon(
      onPressed: onPressed,
      icon: Icon(icon, size: 18),
      label: Text(label),
      style: ElevatedButton.styleFrom(
        backgroundColor: color,
        foregroundColor: Colors.white,
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
        elevation: 0,
      ),
    );
  }

  Widget _buildLoadingState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              color: AppColors.teal.withOpacity(0.1),
              shape: BoxShape.circle,
            ),
            child: const CircularProgressIndicator(
              valueColor: AlwaysStoppedAnimation(AppColors.teal),
              strokeWidth: 3,
            ),
          ),
          const SizedBox(height: 20),
          const Text(
            'Cargando datos...',
            style: TextStyle(
              fontSize: 16,
              fontWeight: FontWeight.w500,
              color: Colors.black54,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            'Procesando estadísticas',
            style: TextStyle(fontSize: 13, color: Colors.grey.shade500),
          ),
        ],
      ),
    );
  }

  Widget _buildContent() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // KPIs principales
          if (_kpis != null) AdvancedKpiCards(kpis: _kpis!),
          const SizedBox(height: 24),

          // Gráficos principales
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Gráfico de ventas
              Expanded(
                flex: 3,
                child: _buildChartCard(
                  title: 'Ventas por Período',
                  icon: Icons.bar_chart,
                  child: SizedBox(
                    height: 280,
                    child: SalesBarChart(
                      data: _salesSeries,
                      barColor: AppColors.teal,
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 20),
              // Gráfico de métodos de pago
              Expanded(
                flex: 2,
                child: _buildChartCard(
                  title: 'Métodos de Pago',
                  icon: Icons.pie_chart,
                  child: SizedBox(
                    height: 280,
                    child: PaymentMethodPieChart(data: _paymentMethods),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 24),

          // Segunda fila de gráficos
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Gráfico de ganancias
              Expanded(
                flex: 2,
                child: _buildChartCard(
                  title: 'Ganancias por Período',
                  icon: Icons.trending_up,
                  child: SizedBox(
                    height: 250,
                    child: SalesBarChart(
                      data: _profitSeries,
                      barColor: AppColors.success,
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 20),
              // Estadísticas comparativas
              Expanded(
                flex: 2,
                child: _buildChartCard(
                  title: 'Comparativa de Ventas',
                  icon: Icons.compare_arrows,
                  child: SizedBox(
                    height: 250,
                    child: SingleChildScrollView(
                      padding: const EdgeInsets.symmetric(vertical: 8),
                      child: ComparativeStatsCard(stats: _comparativeStats),
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 20),
              // Cobros de préstamos
              Expanded(
                flex: 2,
                child: _buildChartCard(
                  title: 'Cobros de Préstamos',
                  icon: Icons.payments,
                  child: SizedBox(
                    height: 250,
                    child: SalesBarChart(
                      data: _loansSeries,
                      barColor: AppColors.gold,
                    ),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 24),

          // Sección de tablas con tabs
          _buildTabbedSection(),
        ],
      ),
    );
  }

  Widget _buildChartCard({
    required String title,
    required IconData icon,
    required Widget child,
  }) {
    return Container(
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(16),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.04),
            blurRadius: 10,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: AppColors.teal.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Icon(icon, color: AppColors.teal, size: 18),
                ),
                const SizedBox(width: 10),
                Text(
                  title,
                  style: const TextStyle(
                    fontSize: 15,
                    fontWeight: FontWeight.bold,
                    color: Colors.black87,
                  ),
                ),
              ],
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
            child: child,
          ),
        ],
      ),
    );
  }

  Widget _buildTabbedSection() {
    return Container(
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(16),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.04),
            blurRadius: 10,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Column(
        children: [
          Container(
            decoration: BoxDecoration(
              color: Colors.grey.shade50,
              borderRadius: const BorderRadius.vertical(
                top: Radius.circular(16),
              ),
            ),
            child: TabBar(
              controller: _tabController,
              labelColor: AppColors.teal,
              unselectedLabelColor: Colors.black54,
              indicatorColor: AppColors.teal,
              indicatorWeight: 3,
              labelStyle: const TextStyle(
                fontWeight: FontWeight.w600,
                fontSize: 13,
              ),
              tabs: [
                _buildTab(Icons.inventory_2, 'Top Productos'),
                _buildTab(Icons.people, 'Top Clientes'),
                _buildTab(Icons.receipt_long, 'Ventas'),
                _buildTab(Icons.account_balance_wallet, 'Préstamos'),
                _buildTab(Icons.schedule, 'Pagos Pendientes'),
              ],
            ),
          ),
          SizedBox(
            height: 450,
            child: TabBarView(
              controller: _tabController,
              children: [
                TopProductsTable(products: _topProducts),
                TopClientsTable(clients: _topClients),
                _buildSalesTable(),
                LoansReportTable(
                  loans: _activeLoans,
                  onViewAll: () => context.go('/loans'),
                ),
                PendingPaymentsTable(
                  payments: _pendingPayments,
                  onViewAll: () => context.go('/loans'),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildTab(IconData icon, String label) {
    return Tab(
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [Icon(icon, size: 18), const SizedBox(width: 6), Text(label)],
      ),
    );
  }

  Widget _buildSalesTable() {
    if (_salesList.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: Colors.grey.shade100,
                shape: BoxShape.circle,
              ),
              child: Icon(
                Icons.receipt_long,
                size: 48,
                color: Colors.grey.shade400,
              ),
            ),
            const SizedBox(height: 16),
            const Text(
              'No hay ventas para mostrar',
              style: TextStyle(
                color: Colors.black54,
                fontSize: 15,
                fontWeight: FontWeight.w500,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              'Las ventas del período aparecerán aquí',
              style: TextStyle(color: Colors.grey.shade500, fontSize: 13),
            ),
          ],
        ),
      );
    }

    return Column(
      children: [
        // Header
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          decoration: BoxDecoration(
            gradient: LinearGradient(
              colors: [
                AppColors.teal.withOpacity(0.1),
                AppColors.teal.withOpacity(0.05),
              ],
            ),
            border: Border(bottom: BorderSide(color: Colors.grey.shade300)),
          ),
          child: const Row(
            children: [
              Expanded(
                flex: 2,
                child: Text(
                  'Código',
                  style: TextStyle(fontWeight: FontWeight.w600, fontSize: 12),
                ),
              ),
              Expanded(
                flex: 2,
                child: Text(
                  'Fecha',
                  style: TextStyle(fontWeight: FontWeight.w600, fontSize: 12),
                ),
              ),
              Expanded(
                flex: 3,
                child: Text(
                  'Cliente',
                  style: TextStyle(fontWeight: FontWeight.w600, fontSize: 12),
                ),
              ),
              Expanded(
                flex: 2,
                child: Text(
                  'Total',
                  style: TextStyle(fontWeight: FontWeight.w600, fontSize: 12),
                  textAlign: TextAlign.right,
                ),
              ),
              Expanded(
                flex: 2,
                child: Text(
                  'Método',
                  style: TextStyle(fontWeight: FontWeight.w600, fontSize: 12),
                  textAlign: TextAlign.center,
                ),
              ),
            ],
          ),
        ),
        // Rows
        Expanded(
          child: ListView.builder(
            itemCount: _salesList.length > 50 ? 50 : _salesList.length,
            itemBuilder: (context, index) {
              final sale = _salesList[index];
              final date = DateTime.fromMillisecondsSinceEpoch(
                sale.createdAtMs,
              );
              final dateStr =
                  '${date.day.toString().padLeft(2, '0')}/${date.month.toString().padLeft(2, '0')}/${date.year}';

              return Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 16,
                  vertical: 12,
                ),
                decoration: BoxDecoration(
                  border: Border(
                    bottom: BorderSide(color: Colors.grey.shade200),
                  ),
                ),
                child: Row(
                  children: [
                    Expanded(
                      flex: 2,
                      child: Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 8,
                          vertical: 4,
                        ),
                        decoration: BoxDecoration(
                          color: AppColors.teal.withOpacity(0.1),
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: Text(
                          sale.localCode,
                          style: const TextStyle(
                            fontSize: 11,
                            fontFamily: 'monospace',
                            fontWeight: FontWeight.w600,
                            color: AppColors.teal,
                          ),
                        ),
                      ),
                    ),
                    Expanded(
                      flex: 2,
                      child: Text(
                        dateStr,
                        style: const TextStyle(fontSize: 12),
                      ),
                    ),
                    Expanded(
                      flex: 3,
                      child: Text(
                        sale.customerName ?? 'Cliente General',
                        style: const TextStyle(fontSize: 12),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    Expanded(
                      flex: 2,
                      child: Text(
                        'RD\$ ${sale.total.toStringAsFixed(2)}',
                        style: const TextStyle(
                          fontSize: 12,
                          fontWeight: FontWeight.w600,
                          color: AppColors.teal,
                        ),
                        textAlign: TextAlign.right,
                      ),
                    ),
                    Expanded(
                      flex: 2,
                      child: Center(
                        child: _buildPaymentMethodBadge(sale.paymentMethod),
                      ),
                    ),
                  ],
                ),
              );
            },
          ),
        ),
        // Footer
        if (_salesList.length > 50)
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.grey.shade50,
              border: Border(top: BorderSide(color: Colors.grey.shade300)),
            ),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(Icons.info_outline, size: 16, color: Colors.grey.shade600),
                const SizedBox(width: 8),
                Text(
                  'Mostrando 50 de ${_salesList.length} ventas',
                  style: TextStyle(fontSize: 12, color: Colors.grey.shade600),
                ),
              ],
            ),
          ),
      ],
    );
  }

  Widget _buildPaymentMethodBadge(String? method) {
    String label;
    Color color;
    IconData icon;

    switch (method?.toLowerCase()) {
      case 'cash':
      case 'efectivo':
      case null:
        label = 'Efectivo';
        color = AppColors.success;
        icon = Icons.payments;
        break;
      case 'card':
      case 'tarjeta':
        label = 'Tarjeta';
        color = Colors.blue;
        icon = Icons.credit_card;
        break;
      case 'transfer':
      case 'transferencia':
        label = 'Transfer';
        color = Colors.purple;
        icon = Icons.swap_horiz;
        break;
      case 'credit':
      case 'credito':
      case 'crédito':
        label = 'Crédito';
        color = AppColors.gold;
        icon = Icons.access_time;
        break;
      default:
        label = method ?? 'N/A';
        color = Colors.grey;
        icon = Icons.help_outline;
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 12, color: color),
          const SizedBox(width: 4),
          Text(
            label,
            style: TextStyle(
              fontSize: 10,
              fontWeight: FontWeight.w600,
              color: color,
            ),
          ),
        ],
      ),
    );
  }
}

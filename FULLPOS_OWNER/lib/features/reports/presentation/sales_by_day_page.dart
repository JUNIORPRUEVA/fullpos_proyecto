import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../data/report_models.dart';
import '../data/reports_repository.dart';
import '../data/sale_realtime_service.dart';

DateTime _dateOnly(DateTime dt) => DateTime(dt.year, dt.month, dt.day);

class SalesByDayPage extends ConsumerStatefulWidget {
  const SalesByDayPage({super.key});

  @override
  ConsumerState<SalesByDayPage> createState() => _SalesByDayPageState();
}

class _SalesByDayPageState extends ConsumerState<SalesByDayPage>
    with WidgetsBindingObserver {
  Timer? _autoRefreshTimer;
  StreamSubscription<SaleRealtimeMessage>? _saleRealtimeSubscription;
  bool _reloadInProgress = false;
  bool _reloadRequested = false;

  PaginatedSales? _page;
  SalesSummary? _summary;
  bool _loading = true;
  String? _error;
  late DateTime _from;
  late DateTime _to;

  final _clientCtrl = TextEditingController();
  final _cashierCtrl = TextEditingController();
  final _searchCtrl = TextEditingController();

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    final today = _dateOnly(DateTime.now());
    _from = today;
    _to = today;
    _autoRefreshTimer = Timer.periodic(
      const Duration(seconds: 60),
      (_) => _load(showLoading: false),
    );
    _saleRealtimeSubscription = ref
        .read(saleRealtimeServiceProvider)
        .stream
        .listen((_) => _load(showLoading: false));
    _load(showLoading: true);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _autoRefreshTimer?.cancel();
    _saleRealtimeSubscription?.cancel();
    _clientCtrl.dispose();
    _cashierCtrl.dispose();
    _searchCtrl.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _load(showLoading: false);
    }
  }

  void _setRange(DateTime from, DateTime to) {
    setState(() {
      _from = _dateOnly(from);
      _to = _dateOnly(to);
    });
    _load(showLoading: true);
  }

  Future<void> _load({required bool showLoading}) async {
    if (_reloadInProgress) {
      _reloadRequested = true;
      return;
    }
    _reloadInProgress = true;
    _reloadRequested = false;
    if (showLoading && mounted) {
      setState(() {
        _loading = true;
        _error = null;
      });
    }

    final repo = ref.read(reportsRepositoryProvider);
    final fmt = DateFormat('yyyy-MM-dd');
    final fromStr = fmt.format(_from);
    final toStr = fmt.format(_to);
    try {
      final results = await Future.wait<Object?>([
        repo.salesList(fromStr, toStr, page: 1),
        repo.salesSummary(fromStr, toStr),
      ]);
      if (!mounted) return;
      setState(() {
        _page = results[0] as PaginatedSales;
        _summary = results[1] as SalesSummary;
        if (showLoading) _loading = false;
      });
    } catch (error) {
      if (!mounted) return;
      setState(() {
        if (showLoading) {
          _error = 'No se pudieron cargar las ventas.';
          _loading = false;
        }
      });
    } finally {
      _reloadInProgress = false;
      if (_reloadRequested && mounted) {
        _reloadRequested = false;
        unawaited(_load(showLoading: false));
      }
    }
  }

  List<SaleRow> get _filteredSales {
    final rows = _page?.data ?? [];
    final clientTerm = _clientCtrl.text.trim().toLowerCase();
    final cashierTerm = _cashierCtrl.text.trim().toLowerCase();
    final searchTerm = _searchCtrl.text.trim().toLowerCase();
    return rows.where((sale) {
      final customer = (sale.customerName ?? '').toLowerCase();
      final cashier = (sale.user?.displayName ?? sale.user?.username ?? '')
          .toLowerCase();
      final localCode = sale.localCode.toLowerCase();
      final matchesClient = clientTerm.isEmpty || customer.contains(clientTerm);
      final matchesCashier =
          cashierTerm.isEmpty || cashier.contains(cashierTerm);
      final matchesSearch =
          searchTerm.isEmpty ||
          localCode.contains(searchTerm) ||
          sale.paymentMethod?.toLowerCase().contains(searchTerm) == true ||
          customer.contains(searchTerm);
      return matchesClient && matchesCashier && matchesSearch;
    }).toList();
  }

  Future<void> _showSummaryDialog() async {
    final filtered = _filteredSales;
    final currency = NumberFormat.currency(locale: 'es_DO', symbol: '\$');
    final summary = _summary;
    final filteredTotal = filtered.fold<double>(
      0.0,
      (sum, sale) => sum + sale.total,
    );
    final filteredAverage = filtered.isEmpty
        ? 0
        : filteredTotal / filtered.length;
    final filteredCount = filtered.length;

    final rangeFmt = DateFormat('yyyy-MM-dd');
    final rangeLabel = rangeFmt.format(_from) == rangeFmt.format(_to)
        ? rangeFmt.format(_from)
        : '${rangeFmt.format(_from)} - ${rangeFmt.format(_to)}';

    await showDialog<void>(
      context: context,
      builder: (ctx) {
        return AlertDialog(
          title: Text('Resumen â€” $rangeLabel'),
          content: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Filtro activo: $filteredCount ventas seleccionadas.'),
                const SizedBox(height: 10),
                Text(
                  'Total seleccionado: ${currency.format(filteredTotal)}\n'
                  'Promedio: ${currency.format(filteredAverage)}',
                ),
                const SizedBox(height: 12),
                if (summary != null) ...[
                  Text(
                    'Resumen general del período:',
                    style: Theme.of(context).textTheme.titleSmall,
                  ),
                  const SizedBox(height: 6),
                  Text(
                    'Total vendido: ${currency.format(summary.total)}\n'
                    'Ganancia estimada: ${currency.format(summary.profit)}\n'
                    'Costo: ${currency.format(summary.totalCost)}',
                  ),
                ],
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text('Cerrar'),
            ),
          ],
        );
      },
    );
  }

  Widget _buildFiltersRow(ThemeData theme) {
    return Row(
      children: [
        Expanded(
          child: TextField(
            controller: _searchCtrl,
            decoration: InputDecoration(
              hintText: 'Buscar código, cliente o método',
              prefixIcon: const Icon(Icons.search),
              suffixIcon: _searchCtrl.text.isNotEmpty
                  ? IconButton(
                      icon: const Icon(Icons.close),
                      onPressed: () {
                        _searchCtrl.clear();
                        setState(() {});
                      },
                    )
                  : null,
              contentPadding: const EdgeInsets.symmetric(vertical: 12),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(14),
                borderSide: BorderSide.none,
              ),
              filled: true,
            ),
            onChanged: (_) => setState(() {}),
          ),
        ),
        const SizedBox(width: 10),
        OutlinedButton.icon(
          onPressed: _pickRange,
          icon: const Icon(Icons.date_range_outlined),
          label: Text(_rangeLabelShort()),
        ),
        const SizedBox(width: 10),
        OutlinedButton.icon(
          onPressed: _showFiltersSheet,
          icon: const Icon(Icons.filter_list),
          label: const Text('Filtros'),
        ),
        const SizedBox(width: 6),
        IconButton(
          icon: const Icon(Icons.refresh),
          tooltip: 'Actualizar',
          onPressed: () => _load(showLoading: true),
        ),
      ],
    );
  }

  String _rangeLabelShort() {
    final fmt = DateFormat('dd/MM');
    final fromLabel = fmt.format(_from);
    final toLabel = fmt.format(_to);
    if (fromLabel == toLabel) return fromLabel;
    return '$fromLabel - $toLabel';
  }

  Future<void> _pickRange() async {
    final today = DateTime.now();
    final picked = await showDateRangePicker(
      context: context,
      firstDate: today.subtract(const Duration(days: 365)),
      lastDate: today.add(const Duration(days: 1)),
      initialDateRange: DateTimeRange(start: _from, end: _to),
    );
    if (picked != null) {
      _setRange(_dateOnly(picked.start), _dateOnly(picked.end));
    }
  }

  Future<void> _showFiltersSheet() async {
    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (context) {
        final viewInsets = MediaQuery.of(context).viewInsets.bottom;
        return Padding(
          padding: EdgeInsets.only(bottom: viewInsets),
          child: SingleChildScrollView(
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 20),
              child: _buildFilterSheetContent(),
            ),
          ),
        );
      },
    );
  }

  Widget _buildFilterSheetContent() {
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Filtros avanzados',
          style: Theme.of(context).textTheme.titleMedium,
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _clientCtrl,
          decoration: const InputDecoration(
            labelText: 'Cliente',
            prefixIcon: Icon(Icons.person_search_outlined),
          ),
          onChanged: (_) => setState(() {}),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _cashierCtrl,
          decoration: const InputDecoration(
            labelText: 'Cajero',
            prefixIcon: Icon(Icons.badge_outlined),
          ),
          onChanged: (_) => setState(() {}),
        ),
        const SizedBox(height: 16),
        Row(
          children: [
            TextButton(
              onPressed: () {
                _clientCtrl.clear();
                _cashierCtrl.clear();
                setState(() {});
              },
              child: const Text('Limpiar'),
            ),
            const Spacer(),
            ElevatedButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Aplicar'),
            ),
          ],
        ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final currency = NumberFormat.currency(locale: 'es_DO', symbol: '\$');
    final filtered = _filteredSales;

    return Stack(
      children: [
        Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              _buildFiltersRow(theme),
              if (_clientCtrl.text.isNotEmpty ||
                  _cashierCtrl.text.isNotEmpty ||
                  _searchCtrl.text.isNotEmpty)
                Padding(
                  padding: const EdgeInsets.only(top: 8),
                  child: Wrap(
                    spacing: 8,
                    children: [..._buildActiveFilterChips()],
                  ),
                ),
              const SizedBox(height: 14),
              Expanded(child: _buildSalesPanel(theme, currency, filtered)),
            ],
          ),
        ),
        Positioned(
          right: 20,
          bottom: 20,
          child: FloatingActionButton.extended(
            onPressed: _loading ? null : _showSummaryDialog,
            icon: const Icon(Icons.summarize_outlined),
            label: const Text('Resumen'),
          ),
        ),
      ],
    );
  }

  Widget _buildSalesPanel(
    ThemeData theme,
    NumberFormat currency,
    List<SaleRow> filtered,
  ) {
    if (_loading) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_error != null) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(_error!, style: theme.textTheme.bodyMedium),
            const SizedBox(height: 10),
            OutlinedButton.icon(
              onPressed: () => _load(showLoading: true),
              icon: const Icon(Icons.refresh),
              label: const Text('Reintentar'),
            ),
          ],
        ),
      );
    }
    if (filtered.isEmpty) {
      return Center(
        child: Text(
          'No hay ventas para los filtros seleccionados.',
          style: theme.textTheme.bodyMedium,
        ),
      );
    }
    return Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 860),
        child: ListView.separated(
          padding: const EdgeInsets.only(bottom: 120),
          itemCount: filtered.length,
          separatorBuilder: (context, index) => const SizedBox(height: 12),
          itemBuilder: (context, index) {
            final sale = filtered[index];
            return _buildSaleRow(context, theme, currency, sale);
          },
        ),
      ),
    );
  }

  Widget _buildSaleRow(
    BuildContext context,
    ThemeData theme,
    NumberFormat currency,
    SaleRow sale,
  ) {
    final cashier =
        sale.user?.displayName ?? sale.user?.username ?? 'No asignado';
    final customer = sale.customerName ?? 'Cliente general';
    final timeLabel = sale.createdAt != null
        ? DateFormat('dd/MM/yyyy HH:mm').format(sale.createdAt!)
        : 'Fecha no disponible';
    final paymentMethod =
        (sale.paymentMethod?.toUpperCase() ?? 'método no registrado');
    return Material(
      color: theme.colorScheme.surface,
      borderRadius: BorderRadius.circular(18),
      child: InkWell(
        borderRadius: BorderRadius.circular(18),
        onTap: () => context.go('/sales/detail/${sale.id}'),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  Expanded(
                    child: Text(
                      '${sale.localCode} Â· $timeLabel',
                      style: theme.textTheme.titleSmall?.copyWith(
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                  Text(
                    currency.format(sale.total),
                    style: theme.textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              Text(
                'Cliente: $customer',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurface.withValues(alpha: 0.8),
                ),
              ),
              const SizedBox(height: 12),
              Wrap(
                spacing: 8,
                runSpacing: 6,
                children: [
                  _buildBadge('Cajero', cashier, theme),
                  _buildBadge('Pago', paymentMethod, theme),
                  if (sale.sessionId != null)
                    _buildBadge('Sesión', sale.sessionId.toString(), theme),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildBadge(String label, String value, ThemeData theme) {
    return Chip(
      materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
      backgroundColor: theme.colorScheme.primary.withValues(alpha: 0.08),
      labelPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 0),
      label: Text(
        '$label: $value',
        style: theme.textTheme.bodySmall?.copyWith(
          fontWeight: FontWeight.w600,
          color: theme.colorScheme.primary,
        ),
      ),
    );
  }

  List<Widget> _buildActiveFilterChips() {
    final chips = <Widget>[];
    if (_clientCtrl.text.isNotEmpty) {
      chips.add(
        InputChip(
          label: Text('Cliente: ${_clientCtrl.text.trim()}'),
          onDeleted: () {
            _clientCtrl.clear();
            setState(() {});
          },
        ),
      );
    }
    if (_cashierCtrl.text.isNotEmpty) {
      chips.add(
        InputChip(
          label: Text('Cajero: ${_cashierCtrl.text.trim()}'),
          onDeleted: () {
            _cashierCtrl.clear();
            setState(() {});
          },
        ),
      );
    }
    if (_searchCtrl.text.isNotEmpty) {
      chips.add(
        InputChip(
          label: Text('Buscar: ${_searchCtrl.text.trim()}'),
          onDeleted: () {
            _searchCtrl.clear();
            setState(() {});
          },
        ),
      );
    }
    return chips;
  }

}

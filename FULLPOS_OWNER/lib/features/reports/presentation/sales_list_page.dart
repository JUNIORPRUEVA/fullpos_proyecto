import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';
import '../../../core/providers/sync_request_provider.dart';
import '../../../core/utils/accounting_format.dart';
import '../data/report_models.dart';
import '../data/reports_repository.dart';
import '../data/sale_realtime_service.dart';

class SalesListPage extends ConsumerStatefulWidget {
  const SalesListPage({super.key, this.initialFrom, this.initialTo});

  final DateTime? initialFrom;
  final DateTime? initialTo;

  @override
  ConsumerState<SalesListPage> createState() => _SalesListPageState();
}

class _SalesListPageState extends ConsumerState<SalesListPage>
    with WidgetsBindingObserver {
  Timer? _autoRefreshTimer;
  StreamSubscription<SaleRealtimeMessage>? _saleRealtimeSubscription;
  bool _refreshInFlight = false;
  bool _reloadRequested = false;

  static const Duration _autoRefreshInterval = Duration(seconds: 60);

  PaginatedSales? _page;
  SalesSummary? _summary;
  bool _loading = true;
  String? _error;
  int _currentPage = 1;
  late DateTime _from;
  late DateTime _to;

  @override
  void initState() {
    super.initState();
    final now = DateTime.now();
    final todayStart = DateTime(now.year, now.month, now.day);
    _to = widget.initialTo ?? now;
    _from = widget.initialFrom ?? todayStart;
    WidgetsBinding.instance.addObserver(this);
    _load(page: 1, showLoading: true);
    _autoRefreshTimer = Timer.periodic(_autoRefreshInterval, (_) {
      _load(page: _currentPage, showLoading: false);
    });
    _saleRealtimeSubscription = ref
        .read(saleRealtimeServiceProvider)
        .stream
        .listen((_) => _load(page: 1, showLoading: false));
  }

  @override
  void dispose() {
    _autoRefreshTimer?.cancel();
    _saleRealtimeSubscription?.cancel();
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _load(page: _currentPage, showLoading: false);
    }
  }

  Future<void> _load({required int page, required bool showLoading}) async {
    if (_refreshInFlight) {
      _reloadRequested = true;
      return;
    }
    _refreshInFlight = true;
    _reloadRequested = false;

    if (showLoading && mounted) {
      setState(() {
        _loading = true;
        _error = null;
      });
    }
    final repo = ref.read(reportsRepositoryProvider);
    final fmt = DateFormat('yyyy-MM-dd');
    try {
      final fromStr = fmt.format(_from);
      final toStr = fmt.format(_to);

      final results = await Future.wait<Object?>([
        repo.salesList(fromStr, toStr, page: page),
        repo.salesSummary(fromStr, toStr),
      ]);

      final data = results[0] as PaginatedSales;
      final summary = results[1] as SalesSummary;
      if (!mounted) return;
      setState(() {
        _page = data;
        _summary = summary;
        _currentPage = page;
        if (showLoading) _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        if (showLoading) {
          _error = 'Error cargando ventas';
          _loading = false;
        }
      });
    } finally {
      _refreshInFlight = false;
      if (_reloadRequested && mounted) {
        _reloadRequested = false;
        unawaited(_load(page: _currentPage, showLoading: false));
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    ref.listen<SyncRequest>(syncRequestProvider, (previous, next) {
      if (previous?.revision == next.revision) return;
      if (!next.appliesTo('/sales/list')) return;
      unawaited(_load(page: 1, showLoading: true));
    });

    final summary = _summary;

    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _SalesFilters(
            from: _from,
            to: _to,
            onChange: (from, to) {
              setState(() {
                _from = from;
                _to = to;
              });
              _load(page: 1, showLoading: true);
            },
            onQuickRange: (days) {
              final now = DateTime.now();
              final end = now;
              final start = days == 0
                  ? DateTime(now.year, now.month, now.day)
                  : DateTime(
                      now.year,
                      now.month,
                      now.day,
                    ).subtract(Duration(days: days - 1));
              setState(() {
                _from = start;
                _to = end;
              });
              _load(page: 1, showLoading: true);
            },
          ),
          const SizedBox(height: 12),
          Expanded(
            child: _loading
                ? const Center(child: CircularProgressIndicator())
                : _error != null
                ? Center(child: Text(_error!))
                : Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Text(
                            'Ventas',
                            style: Theme.of(context).textTheme.titleMedium,
                          ),
                          Row(
                            children: [
                              IconButton(
                                icon: const Icon(Icons.chevron_left),
                                onPressed: _currentPage > 1
                                    ? () => _load(
                                        page: _currentPage - 1,
                                        showLoading: true,
                                      )
                                    : null,
                              ),
                              Text('Página $_currentPage'),
                              IconButton(
                                icon: const Icon(Icons.chevron_right),
                                onPressed:
                                    ((_page?.data.length ?? 0) >=
                                        (_page?.pageSize ?? 20))
                                    ? () => _load(
                                        page: _currentPage + 1,
                                        showLoading: true,
                                      )
                                    : null,
                              ),
                            ],
                          ),
                        ],
                      ),
                      const SizedBox(height: 12),
                      Wrap(
                        spacing: 12,
                        runSpacing: 12,
                        children: [
                          _SalesMetric(
                            title: 'Total vendido',
                            value: summary != null
                                ? formatAccountingAmount(summary.total)
                                : '--',
                            icon: Icons.payments_outlined,
                          ),
                          _SalesMetric(
                            title: 'Costo',
                            value: summary != null
                                ? formatAccountingAmount(summary.totalCost)
                                : '--',
                            icon: Icons.shopping_cart_outlined,
                          ),
                          _SalesMetric(
                            title: 'Ganancia',
                            value: summary != null
                                ? formatAccountingAmount(summary.profit)
                                : '--',
                            icon: Icons.trending_up_outlined,
                          ),
                        ],
                      ),
                      const SizedBox(height: 8),
                      Expanded(
                        child: Card(
                          child: ListView.separated(
                            itemCount: _page?.data.length ?? 0,
                            separatorBuilder: (context, separatorIndex) =>
                                const Divider(height: 1),
                            itemBuilder: (context, index) {
                              final sale = _page!.data[index];
                              return ListTile(
                                leading: const Icon(
                                  Icons.receipt_long_outlined,
                                ),
                                title: Text(
                                  '${sale.localCode} • ${sale.paymentMethod ?? 'N/D'}',
                                ),
                                subtitle: Text(
                                  [
                                    if ((sale.customerName ?? '')
                                        .trim()
                                        .isNotEmpty)
                                      sale.customerName!.trim(),
                                    sale.createdAt != null
                                        ? DateFormat(
                                            'yyyy-MM-dd HH:mm',
                                          ).format(sale.createdAt!)
                                        : 'Fecha N/D',
                                  ].join(' • '),
                                ),
                                trailing: Text(
                                  formatAccountingAmount(sale.total),
                                ),
                                onTap: () =>
                                    context.go('/sales/detail/${sale.id}'),
                              );
                            },
                          ),
                        ),
                      ),
                    ],
                  ),
          ),
        ],
      ),
    );
  }
}

class _SalesFilters extends StatelessWidget {
  const _SalesFilters({
    required this.from,
    required this.to,
    required this.onChange,
    required this.onQuickRange,
  });

  final DateTime from;
  final DateTime to;
  final void Function(DateTime, DateTime) onChange;
  final ValueChanged<int> onQuickRange;

  @override
  Widget build(BuildContext context) {
    final fmt = DateFormat('yyyy-MM-dd');
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Expanded(
              child: OutlinedButton.icon(
                icon: const Icon(Icons.date_range),
                label: Text('Rango: ${fmt.format(from)} • ${fmt.format(to)}'),
                onPressed: () async {
                  final picked = await showDateRangePicker(
                    context: context,
                    firstDate: DateTime.now().subtract(
                      const Duration(days: 365),
                    ),
                    lastDate: DateTime.now().add(const Duration(days: 1)),
                    initialDateRange: DateTimeRange(start: from, end: to),
                  );
                  if (picked != null) onChange(picked.start, picked.end);
                },
              ),
            ),
          ],
        ),
        const SizedBox(height: 8),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            ActionChip(
              label: const Text('Hoy'),
              onPressed: () => onQuickRange(0),
            ),
            ActionChip(
              label: const Text('7 dias'),
              onPressed: () => onQuickRange(7),
            ),
            ActionChip(
              label: const Text('30 dias'),
              onPressed: () => onQuickRange(30),
            ),
          ],
        ),
      ],
    );
  }
}

class _SalesMetric extends StatelessWidget {
  const _SalesMetric({
    required this.title,
    required this.value,
    required this.icon,
  });

  final String title;
  final String value;
  final IconData icon;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 18),
          const SizedBox(width: 10),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                title,
                style: theme.textTheme.labelMedium?.copyWith(
                  color: theme.colorScheme.onSurface.withValues(alpha: 0.7),
                ),
              ),
              const SizedBox(height: 2),
              Text(value, style: theme.textTheme.titleSmall),
            ],
          ),
        ],
      ),
    );
  }
}

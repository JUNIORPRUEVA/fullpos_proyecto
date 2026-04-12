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

DateTime _dateOnly(DateTime value) =>
    DateTime(value.year, value.month, value.day);

class SalesByDayPage extends ConsumerStatefulWidget {
  const SalesByDayPage({super.key});

  @override
  ConsumerState<SalesByDayPage> createState() => _SalesByDayPageState();
}

class _SalesByDayPageState extends ConsumerState<SalesByDayPage>
    with WidgetsBindingObserver {
  StreamSubscription<SaleRealtimeMessage>? _saleRealtimeSubscription;
  bool _reloadInProgress = false;
  bool _reloadRequested = false;

  PaginatedSales? _page;
  SalesSummary? _summary;
  List<SalesByDay> _byDay = const [];
  bool _loading = true;
  String? _error;
  late DateTime _from;
  late DateTime _to;

  final _clientCtrl = TextEditingController();
  final _cashierCtrl = TextEditingController();
  final _paymentCtrl = TextEditingController();
  final _searchCtrl = TextEditingController();

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    final today = _dateOnly(DateTime.now());
    _from = today.subtract(const Duration(days: 6));
    _to = today;
    _saleRealtimeSubscription = ref
        .read(saleRealtimeServiceProvider)
        .stream
        .listen((_) => _load(showLoading: false));
    _load(showLoading: true);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _saleRealtimeSubscription?.cancel();
    _clientCtrl.dispose();
    _cashierCtrl.dispose();
    _paymentCtrl.dispose();
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
    final format = DateFormat('yyyy-MM-dd');
    final fromStr = format.format(_from);
    final toStr = format.format(_to);

    try {
      final results = await Future.wait<Object?>([
        _loadAllSales(repo, fromStr, toStr),
        repo.salesSummary(fromStr, toStr),
        repo.salesByDay(fromStr, toStr),
      ]);

      if (!mounted) return;
      setState(() {
        _page = results[0] as PaginatedSales;
        _summary = results[1] as SalesSummary;
        _byDay = results[2] as List<SalesByDay>;
        if (showLoading) {
          _loading = false;
        }
      });
    } catch (_) {
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

  Future<PaginatedSales> _loadAllSales(
    ReportsRepository repo,
    String from,
    String to,
  ) async {
    const pageSize = 100;
    final firstPage = await repo.salesList(from, to, page: 1, pageSize: pageSize);
    if (firstPage.total <= firstPage.data.length) {
      return firstPage;
    }

    final allRows = <SaleRow>[...firstPage.data];
    var page = 2;

    while (allRows.length < firstPage.total) {
      final nextPage = await repo.salesList(
        from,
        to,
        page: page,
        pageSize: pageSize,
      );
      if (nextPage.data.isEmpty) break;
      allRows.addAll(nextPage.data);
      page += 1;
    }

    return PaginatedSales(
      data: allRows,
      page: 1,
      pageSize: allRows.length,
      total: firstPage.total,
    );
  }

  List<SaleRow> get _filteredSales {
    final rows = _page?.data ?? const <SaleRow>[];
    final clientTerm = _clientCtrl.text.trim().toLowerCase();
    final cashierTerm = _cashierCtrl.text.trim().toLowerCase();
    final paymentTerm = _paymentCtrl.text.trim().toLowerCase();
    final searchTerm = _searchCtrl.text.trim().toLowerCase();

    return rows.where((sale) {
      final customer = (sale.customerName ?? '').toLowerCase();
      final cashier = (sale.user?.displayName ?? sale.user?.username ?? '')
          .toLowerCase();
      final payment = (sale.paymentMethod ?? '').toLowerCase();
      final matchesClient = clientTerm.isEmpty || customer.contains(clientTerm);
      final matchesCashier =
          cashierTerm.isEmpty || cashier.contains(cashierTerm);
      final matchesPayment =
          paymentTerm.isEmpty || payment.contains(paymentTerm);
      final matchesSearch =
          searchTerm.isEmpty ||
          customer.contains(searchTerm) ||
          cashier.contains(searchTerm) ||
          payment.contains(searchTerm);

      return matchesClient && matchesCashier && matchesPayment && matchesSearch;
    }).toList();
  }

  String _rangeLabel() {
    final format = DateFormat('dd MMM yyyy');
    final fromLabel = format.format(_from);
    final toLabel = format.format(_to);
    return fromLabel == toLabel ? fromLabel : '$fromLabel - $toLabel';
  }

  Map<String, List<SaleRow>> get _groupedFilteredSales {
    final grouped = <String, List<SaleRow>>{};
    final formatter = DateFormat('yyyy-MM-dd');

    for (final sale in _filteredSales) {
      final createdAt = sale.createdAt;
      final key = createdAt == null
          ? formatter.format(_from)
          : formatter.format(_dateOnly(createdAt.toLocal()));
      grouped.putIfAbsent(key, () => <SaleRow>[]).add(sale);
    }

    return grouped;
  }

  Future<void> _showFiltersDialog() async {
    var localFrom = _from;
    var localTo = _to;
    var localClient = _clientCtrl.text;
    var localCashier = _cashierCtrl.text;
    var localPayment = _paymentCtrl.text;

    await showDialog<void>(
      context: context,
      builder: (context) {
        return StatefulBuilder(
          builder: (context, setDialogState) {
            Future<void> pickCustomRange() async {
              final picked = await showDateRangePicker(
                context: context,
                firstDate: DateTime.now().subtract(const Duration(days: 365)),
                lastDate: DateTime.now().add(const Duration(days: 1)),
                initialDateRange: DateTimeRange(start: localFrom, end: localTo),
              );
              if (picked == null) return;
              setDialogState(() {
                localFrom = _dateOnly(picked.start);
                localTo = _dateOnly(picked.end);
              });
            }

            return Dialog(
              insetPadding: const EdgeInsets.symmetric(
                horizontal: 22,
                vertical: 24,
              ),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(24),
              ),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 420),
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(18, 18, 18, 16),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Filtros',
                        style: Theme.of(context).textTheme.titleMedium
                            ?.copyWith(fontWeight: FontWeight.w800),
                      ),
                      const SizedBox(height: 14),
                      Wrap(
                        spacing: 8,
                        runSpacing: 8,
                        children: [
                          _DialogQuickButton(
                            label: 'Hoy',
                            onTap: () {
                              setDialogState(() {
                                final today = _dateOnly(DateTime.now());
                                localFrom = today;
                                localTo = today;
                              });
                            },
                          ),
                          _DialogQuickButton(
                            label: 'Ayer',
                            onTap: () {
                              setDialogState(() {
                                final today = _dateOnly(DateTime.now());
                                final yesterday = today.subtract(
                                  const Duration(days: 1),
                                );
                                localFrom = yesterday;
                                localTo = yesterday;
                              });
                            },
                          ),
                          _DialogQuickButton(
                            label: '7 dias',
                            onTap: () {
                              setDialogState(() {
                                final today = _dateOnly(DateTime.now());
                                localFrom = today.subtract(
                                  const Duration(days: 6),
                                );
                                localTo = today;
                              });
                            },
                          ),
                        ],
                      ),
                      const SizedBox(height: 12),
                      InkWell(
                        borderRadius: BorderRadius.circular(18),
                        onTap: pickCustomRange,
                        child: Container(
                          width: double.infinity,
                          padding: const EdgeInsets.symmetric(
                            horizontal: 14,
                            vertical: 13,
                          ),
                          decoration: BoxDecoration(
                            borderRadius: BorderRadius.circular(18),
                            border: Border.all(
                              color: Theme.of(
                                context,
                              ).colorScheme.outlineVariant,
                            ),
                          ),
                          child: Row(
                            children: [
                              const Icon(Icons.date_range_outlined, size: 18),
                              const SizedBox(width: 10),
                              Expanded(
                                child: Text(
                                  '${DateFormat('dd/MM/yyyy').format(localFrom)} - ${DateFormat('dd/MM/yyyy').format(localTo)}',
                                  style: Theme.of(context).textTheme.bodyMedium
                                      ?.copyWith(fontWeight: FontWeight.w700),
                                ),
                              ),
                            ],
                          ),
                        ),
                      ),
                      const SizedBox(height: 14),
                      TextFormField(
                        initialValue: localClient,
                        decoration: const InputDecoration(
                          labelText: 'Cliente',
                          prefixIcon: Icon(Icons.person_outline),
                        ),
                        onChanged: (value) => localClient = value,
                      ),
                      const SizedBox(height: 10),
                      TextFormField(
                        initialValue: localCashier,
                        decoration: const InputDecoration(
                          labelText: 'Cajero',
                          prefixIcon: Icon(Icons.badge_outlined),
                        ),
                        onChanged: (value) => localCashier = value,
                      ),
                      const SizedBox(height: 10),
                      TextFormField(
                        initialValue: localPayment,
                        decoration: const InputDecoration(
                          labelText: 'Tipo de pago',
                          prefixIcon: Icon(Icons.payments_outlined),
                        ),
                        onChanged: (value) => localPayment = value,
                      ),
                      const SizedBox(height: 16),
                      Row(
                        children: [
                          Expanded(
                            child: TextButton(
                              onPressed: () {
                                setDialogState(() {
                                  localFrom = _dateOnly(DateTime.now());
                                  localTo = localFrom;
                                  localClient = '';
                                  localCashier = '';
                                  localPayment = '';
                                });
                              },
                              child: const Text('Limpiar'),
                            ),
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: FilledButton(
                              onPressed: () {
                                final shouldReload =
                                    !_sameDate(localFrom, _from) ||
                                    !_sameDate(localTo, _to);
                                _clientCtrl.text = localClient.trim();
                                _cashierCtrl.text = localCashier.trim();
                                _paymentCtrl.text = localPayment.trim();
                                Navigator.of(context).pop();
                                if (!mounted) return;
                                if (shouldReload) {
                                  _setRange(localFrom, localTo);
                                } else {
                                  setState(() {});
                                }
                              },
                              child: const Text('Aplicar'),
                            ),
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
      },
    );
  }

  bool get _hasActiveFilters {
    return _clientCtrl.text.trim().isNotEmpty ||
        _cashierCtrl.text.trim().isNotEmpty ||
        _paymentCtrl.text.trim().isNotEmpty ||
        _searchCtrl.text.trim().isNotEmpty;
  }

  @override
  Widget build(BuildContext context) {
    ref.listen<SyncRequest>(syncRequestProvider, (previous, next) {
      if (previous?.revision == next.revision) return;
      if (!next.appliesTo('/sales/by-day')) return;
      unawaited(_load(showLoading: true));
    });

    final theme = Theme.of(context);
    final filtered = _filteredSales;
    final groupedSales = _groupedFilteredSales;
    final filteredTotal = filtered.fold<double>(
      0,
      (sum, sale) => sum + sale.total,
    );

    return Padding(
      padding: const EdgeInsets.fromLTRB(12, 4, 12, 0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _TopInfoStrip(
            rangeLabel: _rangeLabel(),
            salesCount: filtered.length,
            totalLabel: formatAccountingAmount(
              filtered.isEmpty ? (_summary?.total ?? 0) : filteredTotal,
            ),
          ),
          const SizedBox(height: 8),
          _DailyMetricsStrip(
            byDay: _byDay,
            summary: _summary,
            visibleSalesCount: filtered.length,
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _searchCtrl,
                  onChanged: (_) => setState(() {}),
                  decoration: InputDecoration(
                    hintText: 'Buscar cliente, cajero o pago',
                    isDense: true,
                    prefixIcon: const Icon(Icons.search, size: 20),
                    suffixIcon: _searchCtrl.text.isEmpty
                        ? null
                        : IconButton(
                            onPressed: () {
                              _searchCtrl.clear();
                              setState(() {});
                            },
                            icon: const Icon(Icons.close, size: 18),
                          ),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              SizedBox(
                height: 46,
                child: FilledButton.tonalIcon(
                  onPressed: _showFiltersDialog,
                  icon: const Icon(Icons.tune_rounded, size: 18),
                  label: const Text('Filtro'),
                ),
              ),
            ],
          ),
          if (_hasActiveFilters) ...[
            const SizedBox(height: 8),
            Wrap(
              spacing: 6,
              runSpacing: 6,
              children: _buildActiveFilterChips(),
            ),
          ],
          const SizedBox(height: 10),
          Expanded(
            child: _buildSalesPanel(theme, filtered, groupedSales),
          ),
        ],
      ),
    );
  }

  Widget _buildSalesPanel(
    ThemeData theme,
    List<SaleRow> filtered,
    Map<String, List<SaleRow>> groupedSales,
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
            OutlinedButton(
              onPressed: () => _load(showLoading: true),
              child: const Text('Reintentar'),
            ),
          ],
        ),
      );
    }

    if (filtered.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              _hasActiveFilters
                  ? 'No hay ventas para los filtros seleccionados.'
                  : 'No hay ventas registradas en el rango actual.',
              style: theme.textTheme.bodyMedium,
            ),
            const SizedBox(height: 10),
            OutlinedButton.icon(
              onPressed: _showFiltersDialog,
              icon: const Icon(Icons.date_range_outlined),
              label: const Text('Cambiar rango'),
            ),
          ],
        ),
      );
    }

    return Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 860),
        child: ListView.separated(
          padding: const EdgeInsets.only(bottom: 24),
          itemCount: groupedSales.length,
          separatorBuilder: (_, _) => const SizedBox(height: 8),
          itemBuilder: (context, index) {
            final entry = groupedSales.entries.elementAt(index);
            return _SalesDaySection(
              dateKey: entry.key,
              sales: entry.value,
            );
          },
        ),
      ),
    );
  }

  List<Widget> _buildActiveFilterChips() {
    final chips = <Widget>[];

    void addChip(String label, TextEditingController controller) {
      if (controller.text.trim().isEmpty) return;
      chips.add(
        InputChip(
          label: Text('$label: ${controller.text.trim()}'),
          onDeleted: () {
            controller.clear();
            setState(() {});
          },
        ),
      );
    }

    addChip('Cliente', _clientCtrl);
    addChip('Cajero', _cashierCtrl);
    addChip('Pago', _paymentCtrl);
    addChip('Buscar', _searchCtrl);
    return chips;
  }
}

class _TopInfoStrip extends StatelessWidget {
  const _TopInfoStrip({
    required this.rangeLabel,
    required this.salesCount,
    required this.totalLabel,
  });

  final String rangeLabel;
  final int salesCount;
  final String totalLabel;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: Row(
        children: [
          Expanded(
            child: Text(
              rangeLabel,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.labelLarge?.copyWith(
                fontWeight: FontWeight.w800,
              ),
            ),
          ),
          Text(
            '$salesCount ventas',
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(width: 10),
          Text(
            totalLabel,
            style: theme.textTheme.labelLarge?.copyWith(
              fontWeight: FontWeight.w900,
            ),
          ),
        ],
      ),
    );
  }
}

class _DailyMetricsStrip extends StatelessWidget {
  const _DailyMetricsStrip({
    required this.byDay,
    required this.summary,
    required this.visibleSalesCount,
  });

  final List<SalesByDay> byDay;
  final SalesSummary? summary;
  final int visibleSalesCount;

  @override
  Widget build(BuildContext context) {
    final daysWithSales = byDay.length;
    final totalCount = summary?.count ?? visibleSalesCount;
    final averagePerSale = summary?.average ?? 0;

    return Row(
      children: [
        Expanded(
          child: _MetricCard(
            label: 'Dias con ventas',
            value: '$daysWithSales',
          ),
        ),
        const SizedBox(width: 8),
        Expanded(
          child: _MetricCard(
            label: 'Ventas cargadas',
            value: '$totalCount',
          ),
        ),
        const SizedBox(width: 8),
        Expanded(
          child: _MetricCard(
            label: 'Ticket promedio',
            value: formatAccountingAmount(averagePerSale),
            emphasized: true,
          ),
        ),
      ],
    );
  }
}

class _MetricCard extends StatelessWidget {
  const _MetricCard({
    required this.label,
    required this.value,
    this.emphasized = false,
  });

  final String label;
  final String value;
  final bool emphasized;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: emphasized
            ? theme.colorScheme.primaryContainer.withAlpha((0.65 * 255).round())
            : theme.colorScheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 6),
          Text(
            value,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: theme.textTheme.titleSmall?.copyWith(
              fontWeight: FontWeight.w900,
            ),
          ),
        ],
      ),
    );
  }
}

class _SalesDaySection extends StatelessWidget {
  const _SalesDaySection({required this.dateKey, required this.sales});

  final String dateKey;
  final List<SaleRow> sales;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final date = DateTime.tryParse(dateKey);
    final label = date == null
        ? dateKey
        : DateFormat('EEEE, dd MMM yyyy', 'es').format(date);
    final total = sales.fold<double>(0, (sum, sale) => sum + sale.total);

    return Container(
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  _capitalize(label),
                  style: theme.textTheme.titleSmall?.copyWith(
                    fontWeight: FontWeight.w900,
                  ),
                ),
              ),
              Text(
                '${sales.length} ventas',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                  fontWeight: FontWeight.w700,
                ),
              ),
              const SizedBox(width: 10),
              Text(
                formatAccountingAmount(total),
                style: theme.textTheme.titleSmall?.copyWith(
                  fontWeight: FontWeight.w900,
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          ...sales.map((sale) => Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: _CompactSaleRow(sale: sale),
              )),
        ],
      ),
    );
  }
}

class _CompactSaleRow extends StatelessWidget {
  const _CompactSaleRow({required this.sale});

  final SaleRow sale;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final customer = (sale.customerName ?? '').trim().isEmpty
        ? 'Cliente general'
        : sale.customerName!.trim();
    final cashier = sale.user?.displayName ?? sale.user?.username ?? 'N/D';
    final payment = (sale.paymentMethod ?? 'otro').trim();
    final createdAt = sale.createdAt?.toLocal();
    final timeLabel = createdAt == null
        ? 'Hora no disponible'
        : DateFormat('hh:mm a', 'es').format(createdAt);

    return Material(
      color: theme.colorScheme.surface,
      borderRadius: BorderRadius.circular(16),
      child: InkWell(
        borderRadius: BorderRadius.circular(16),
        onTap: () => context.go('/sales/detail/${sale.id}'),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: theme.colorScheme.outlineVariant),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          customer,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: theme.textTheme.titleSmall?.copyWith(
                            fontWeight: FontWeight.w800,
                          ),
                        ),
                        const SizedBox(height: 2),
                        Text(
                          'Factura ${sale.localCode} · $timeLabel',
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 10),
                  Text(
                    formatAccountingAmount(sale.total),
                    style: theme.textTheme.titleSmall?.copyWith(
                      fontWeight: FontWeight.w900,
                      letterSpacing: -0.2,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 4),
              Text(
                '$cashier · ${payment.toLowerCase()}',
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                  fontWeight: FontWeight.w500,
                  fontSize: 11.5,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

String _capitalize(String value) {
  if (value.isEmpty) return value;
  return value[0].toUpperCase() + value.substring(1);
}

class _DialogQuickButton extends StatelessWidget {
  const _DialogQuickButton({required this.label, required this.onTap});

  final String label;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return OutlinedButton(onPressed: onTap, child: Text(label));
  }
}

bool _sameDate(DateTime left, DateTime right) {
  return left.year == right.year &&
      left.month == right.month &&
      left.day == right.day;
}

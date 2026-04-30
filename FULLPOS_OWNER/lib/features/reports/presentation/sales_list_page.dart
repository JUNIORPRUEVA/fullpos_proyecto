import 'dart:async';
import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';
import '../../../core/providers/sync_request_provider.dart';
import '../../../core/utils/accounting_format.dart';
import '../data/report_data.dart';
import '../data/report_realtime_projection.dart';
import '../data/report_models.dart';
import '../data/reports_repository.dart';
import '../data/sale_realtime_service.dart';

const _salesHorizontalGap = 8.0;
const _maxSalesRangeDays = 365;
const _maxSalesRangeOffsetDays = _maxSalesRangeDays - 1;

class SalesListPage extends ConsumerStatefulWidget {
  const SalesListPage({super.key, this.initialFrom, this.initialTo});

  final DateTime? initialFrom;
  final DateTime? initialTo;

  @override
  ConsumerState<SalesListPage> createState() => _SalesListPageState();
}

class _SalesListPageState extends ConsumerState<SalesListPage>
    with WidgetsBindingObserver {
  StreamSubscription<SaleRealtimeMessage>? _saleRealtimeSubscription;
  bool _refreshInFlight = false;
  bool _reloadRequested = false;

  ReportData? _reportData;
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
    final defaultFrom = todayStart.subtract(
      const Duration(days: _maxSalesRangeOffsetDays),
    );
    final normalizedRange = _normalizeSalesRange(
      widget.initialFrom ?? defaultFrom,
      widget.initialTo ?? now,
    );
    _from = normalizedRange.start;
    _to = normalizedRange.end;
    WidgetsBinding.instance.addObserver(this);
    _load(page: 1, showLoading: true);
    _saleRealtimeSubscription = ref
        .read(saleRealtimeServiceProvider)
        .stream
        .listen((message) {
          _applyRealtimeMessage(message);
          unawaited(_load(page: 1, showLoading: false));
        });
  }

  @override
  void dispose() {
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

  void _setRange(DateTime from, DateTime to) {
    final normalizedRange = _normalizeSalesRange(from, to);
    setState(() {
      _from = normalizedRange.start;
      _to = normalizedRange.end;
      _currentPage = 1;
    });
    _load(page: 1, showLoading: true);
  }

  Future<void> _pickCustomRange() async {
    final picked = await _showCompactDateRangeSheet(
      context,
      initialFrom: _from,
      initialTo: _to,
    );
    if (picked == null || !mounted) return;
    _setRange(picked.start, picked.end);
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
    try {
      final report = await repo.getReportData(
        DateFilter(start: _from, end: _to),
      );
      final totalPages = math.max(1, (report.sales.length / 20).ceil());
      final resolvedPage = page.clamp(1, totalPages);
      if (!mounted) return;
      setState(() {
        _reportData = report;
        _currentPage = resolvedPage;
        if (showLoading) _loading = false;
      });
    } catch (error) {
      if (!mounted) return;
      setState(() {
        if (showLoading) {
          _error = _friendlySalesLoadError(error);
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

  void _applyRealtimeMessage(SaleRealtimeMessage message) {
    final report = _reportData;
    if (report == null || !mounted) return;

    final projected = applySaleRealtimeProjection(
      current: report,
      message: message,
      from: _from,
      to: _to,
    );
    final totalPages = math.max(1, (projected.sales.length / 20).ceil());

    setState(() {
      _reportData = projected;
      if (_currentPage > totalPages) {
        _currentPage = totalPages;
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    ref.listen<SyncRequest>(syncRequestProvider, (previous, next) {
      if (previous?.revision == next.revision) return;
      if (!next.appliesTo('/sales/list')) return;
      unawaited(_load(page: 1, showLoading: false));
    });

    final report = _reportData;
    final allSales = report?.sales ?? const <SaleRow>[];
    const pageSize = 20;
    final totalPages = math.max(1, (allSales.length / pageSize).ceil());
    final startIndex = (_currentPage - 1) * pageSize;
    final endIndex = math.min(startIndex + pageSize, allSales.length);
    final visibleSales = startIndex >= allSales.length
        ? const <SaleRow>[]
        : allSales.sublist(startIndex, endIndex);

    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _SalesFilters(
            from: _from,
            to: _to,
            onPickRange: () => unawaited(_pickCustomRange()),
            onChange: (from, to) {
              _setRange(from, to);
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
              _setRange(start, end);
            },
          ),
          const SizedBox(height: 12),
          Expanded(
            child: _loading
                ? const Center(child: CircularProgressIndicator())
                : _error != null
                ? _SalesLoadErrorState(
                    message: _error!,
                    rangeLabel: _formatSalesDateRange(_from, _to),
                    onRetry: () => _load(page: 1, showLoading: true),
                  )
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
                              Text('Página $_currentPage de $totalPages'),
                              IconButton(
                                icon: const Icon(Icons.chevron_right),
                                onPressed: _currentPage < totalPages
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
                      Row(
                        children: [
                          Expanded(
                            child: _SalesMetric(
                              title: 'Total vendido',
                              value: report != null
                                  ? formatAccountingAmount(report.totalSales)
                                  : '--',
                              icon: Icons.payments_outlined,
                            ),
                          ),
                          const SizedBox(width: _salesHorizontalGap),
                          Expanded(
                            child: _SalesMetric(
                              title: 'Costo',
                              value: report != null
                                  ? formatAccountingAmount(report.totalCost)
                                  : '--',
                              icon: Icons.inventory_2_outlined,
                            ),
                          ),
                          const SizedBox(width: _salesHorizontalGap),
                          Expanded(
                            child: _SalesMetric(
                              title: 'Ganancia',
                              value: report != null
                                  ? formatAccountingAmount(report.profit)
                                  : '--',
                              icon: Icons.trending_up_outlined,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 8),
                      Expanded(
                        child: allSales.isEmpty
                            ? _SalesNoDataState(
                                rangeLabel: _formatSalesDateRange(_from, _to),
                                onChangeRange: () =>
                                    unawaited(_pickCustomRange()),
                              )
                            : Card(
                                child: ListView.separated(
                                  itemCount: visibleSales.length,
                                  separatorBuilder: (context, separatorIndex) =>
                                      const Divider(height: 1),
                                  itemBuilder: (context, index) {
                                    final sale = visibleSales[index];
                                    return _CompactSaleRow(
                                      sale: sale,
                                      onTap: () => context.go(
                                        '/sales/detail/${sale.id}',
                                      ),
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
    required this.onPickRange,
    required this.onChange,
    required this.onQuickRange,
  });

  final DateTime from;
  final DateTime to;
  final VoidCallback onPickRange;
  final void Function(DateTime, DateTime) onChange;
  final ValueChanged<int> onQuickRange;

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      child: Row(
        children: [
          _RangeChip(label: _salesRangeLabel(from, to)),
          const SizedBox(width: _salesHorizontalGap),
          ActionChip(
            label: const Text('Hoy'),
            onPressed: () => onQuickRange(0),
          ),
          const SizedBox(width: _salesHorizontalGap),
          ActionChip(
            label: const Text('7 dias'),
            onPressed: () => onQuickRange(7),
          ),
          const SizedBox(width: _salesHorizontalGap),
          ActionChip(
            label: const Text('30 dias'),
            onPressed: () => onQuickRange(30),
          ),
          const SizedBox(width: _salesHorizontalGap),
          ActionChip(
            label: const Text('365 dias'),
            onPressed: () => onQuickRange(_maxSalesRangeDays),
          ),
          const SizedBox(width: _salesHorizontalGap),
          IconButton.filledTonal(
            tooltip: 'Elegir rango',
            onPressed: onPickRange,
            icon: const Icon(Icons.calendar_month_outlined),
          ),
        ],
      ),
    );
  }
}

class _RangeChip extends StatelessWidget {
  const _RangeChip({required this.label});

  final String label;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: theme.colorScheme.primaryContainer.withValues(alpha: 0.55),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            Icons.calendar_today_outlined,
            size: 16,
            color: theme.colorScheme.primary,
          ),
          const SizedBox(width: 8),
          Text(
            label,
            style: theme.textTheme.labelLarge?.copyWith(
              color: theme.colorScheme.primary,
              fontWeight: FontWeight.w700,
            ),
          ),
        ],
      ),
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
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        children: [
          Icon(icon, size: 17),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  title,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.labelSmall?.copyWith(
                    color: theme.colorScheme.onSurface.withValues(alpha: 0.72),
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  value,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.titleSmall?.copyWith(
                    fontWeight: FontWeight.w800,
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

class _SalesLoadErrorState extends StatelessWidget {
  const _SalesLoadErrorState({
    required this.message,
    required this.rangeLabel,
    required this.onRetry,
  });

  final String message;
  final String rangeLabel;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 360),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.cloud_off_outlined,
              size: 42,
              color: theme.colorScheme.error,
            ),
            const SizedBox(height: 12),
            Text(
              message,
              textAlign: TextAlign.center,
              style: theme.textTheme.titleSmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
                fontWeight: FontWeight.w800,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'Rango: $rangeLabel',
              textAlign: TextAlign.center,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
                fontWeight: FontWeight.w600,
              ),
            ),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              onPressed: onRetry,
              icon: const Icon(Icons.refresh_rounded),
              label: const Text('Reintentar'),
            ),
          ],
        ),
      ),
    );
  }
}

class _SalesNoDataState extends StatelessWidget {
  const _SalesNoDataState({
    required this.rangeLabel,
    required this.onChangeRange,
  });

  final String rangeLabel;
  final VoidCallback onChangeRange;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 360),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.search_off_outlined,
              size: 42,
              color: theme.colorScheme.onSurfaceVariant,
            ),
            const SizedBox(height: 12),
            Text(
              'Sin ventas en este rango',
              textAlign: TextAlign.center,
              style: theme.textTheme.titleSmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
                fontWeight: FontWeight.w800,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'Rango: $rangeLabel',
              textAlign: TextAlign.center,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
                fontWeight: FontWeight.w600,
              ),
            ),
            const SizedBox(height: 12),
            FilledButton.tonalIcon(
              onPressed: onChangeRange,
              icon: const Icon(Icons.tune_rounded, size: 18),
              label: const Text('Cambiar filtro'),
            ),
          ],
        ),
      ),
    );
  }
}

class _CompactSaleRow extends StatelessWidget {
  const _CompactSaleRow({required this.sale, required this.onTap});

  final SaleRow sale;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final dateLabel = sale.createdAt != null
        ? DateFormat('yyyy-MM-dd HH:mm').format(sale.createdAt!)
        : 'Fecha N/D';
    final paymentLabel = _translatePaymentMethod(sale.paymentMethod);
    final primaryLabel = _buildSalePrimaryLabel(sale);

    return InkWell(
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        child: Row(
          children: [
            Icon(
              Icons.receipt_long_outlined,
              size: 18,
              color: theme.colorScheme.primary,
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                '$primaryLabel • $paymentLabel • $dateLabel',
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: theme.textTheme.bodyMedium?.copyWith(
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
            const SizedBox(width: 10),
            Text(
              formatAccountingAmount(sale.total),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.titleSmall?.copyWith(
                fontWeight: FontWeight.w900,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

Future<DateTimeRange?> _showCompactDateRangeSheet(
  BuildContext context, {
  required DateTime initialFrom,
  required DateTime initialTo,
}) {
  final now = DateTime.now();
  final today = DateTime(now.year, now.month, now.day);
  final firstDate = today.subtract(
    const Duration(days: _maxSalesRangeOffsetDays),
  );
  final lastDate = today;
  final fmt = DateFormat('yyyy-MM-dd');

  return showModalBottomSheet<DateTimeRange>(
    context: context,
    showDragHandle: true,
    backgroundColor: Theme.of(context).colorScheme.surface,
    shape: const RoundedRectangleBorder(
      borderRadius: BorderRadius.vertical(top: Radius.circular(28)),
    ),
    builder: (context) {
      var start = DateTime(
        initialFrom.year,
        initialFrom.month,
        initialFrom.day,
      );
      var end = DateTime(initialTo.year, initialTo.month, initialTo.day);
      if (start.isBefore(firstDate)) start = firstDate;
      if (start.isAfter(lastDate)) start = lastDate;
      if (end.isBefore(firstDate)) end = firstDate;
      if (end.isAfter(lastDate)) end = lastDate;
      if (start.isAfter(end)) start = end;

      return StatefulBuilder(
        builder: (context, setModalState) {
          Future<void> pickStart() async {
            final picked = await showDatePicker(
              context: context,
              firstDate: firstDate,
              lastDate: end.isAfter(lastDate) ? lastDate : end,
              initialDate: start,
              helpText: 'Fecha inicial',
            );
            if (picked == null) return;
            setModalState(() {
              start = picked;
              if (start.isAfter(end)) {
                end = start;
              }
            });
          }

          Future<void> pickEnd() async {
            final picked = await showDatePicker(
              context: context,
              firstDate: start.isBefore(firstDate) ? firstDate : start,
              lastDate: lastDate,
              initialDate: end.isBefore(start) ? start : end,
              helpText: 'Fecha final',
            );
            if (picked == null) return;
            setModalState(() {
              end = picked;
            });
          }

          return SafeArea(
            top: false,
            child: Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Filtrar por fecha',
                    style: Theme.of(context).textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    'Elige un intervalo compacto para el reporte.',
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                  const SizedBox(height: 16),
                  Row(
                    children: [
                      Expanded(
                        child: _DateBox(
                          label: 'Desde',
                          value: fmt.format(start),
                          onTap: pickStart,
                        ),
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: _DateBox(
                          label: 'Hasta',
                          value: fmt.format(end),
                          onTap: pickEnd,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),
                  Row(
                    children: [
                      Expanded(
                        child: OutlinedButton(
                          onPressed: () => Navigator.of(context).pop(),
                          child: const Text('Cancelar'),
                        ),
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: FilledButton(
                          onPressed: () {
                            Navigator.of(
                              context,
                            ).pop(DateTimeRange(start: start, end: end));
                          },
                          child: const Text('Aplicar'),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          );
        },
      );
    },
  );
}

class _DateBox extends StatelessWidget {
  const _DateBox({
    required this.label,
    required this.value,
    required this.onTap,
  });

  final String label;
  final String value;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(18),
      child: Ink(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: theme.colorScheme.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(18),
          border: Border.all(color: theme.colorScheme.outlineVariant),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label,
              style: theme.textTheme.labelMedium?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 4),
            Row(
              children: [
                const Icon(Icons.event_outlined, size: 16),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    value,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: theme.textTheme.bodyMedium?.copyWith(
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

String _buildSalePrimaryLabel(SaleRow sale) {
  final customer = sale.customerName?.trim();
  if (customer != null && customer.isNotEmpty) {
    return customer;
  }
  return 'Venta sin cliente';
}

String _translatePaymentMethod(String? value) {
  switch (value?.trim().toLowerCase()) {
    case 'cash':
    case 'efectivo':
      return 'Efectivo';
    case 'card':
    case 'tarjeta':
      return 'Tarjeta';
    case 'transfer':
    case 'transferencia':
      return 'Transferencia';
    case 'mixed':
    case 'mixto':
      return 'Mixto';
    case 'credit':
    case 'credito':
      return 'Crédito';
    default:
      final normalized = value?.trim();
      return normalized == null || normalized.isEmpty
          ? 'No especificado'
          : normalized;
  }
}

bool _sameSalesDate(DateTime left, DateTime right) {
  return left.year == right.year &&
      left.month == right.month &&
      left.day == right.day;
}

DateTime _salesDateOnly(DateTime value) {
  return DateTime(value.year, value.month, value.day);
}

DateTime _clampSalesDate(
  DateTime value,
  DateTime firstDate,
  DateTime lastDate,
) {
  if (value.isBefore(firstDate)) return firstDate;
  if (value.isAfter(lastDate)) return lastDate;
  return value;
}

DateTimeRange _normalizeSalesRange(DateTime from, DateTime to) {
  final today = _salesDateOnly(DateTime.now());
  final firstDate = today.subtract(
    const Duration(days: _maxSalesRangeOffsetDays),
  );
  var normalizedFrom = _clampSalesDate(_salesDateOnly(from), firstDate, today);
  var normalizedTo = _clampSalesDate(_salesDateOnly(to), firstDate, today);
  if (normalizedFrom.isAfter(normalizedTo)) {
    normalizedFrom = normalizedTo;
  }
  return DateTimeRange(start: normalizedFrom, end: normalizedTo);
}

String _formatSalesDateRange(DateTime from, DateTime to) {
  final fmt = DateFormat('dd/MM/yyyy');
  return '${fmt.format(_salesDateOnly(from))} - ${fmt.format(_salesDateOnly(to))}';
}

String _friendlySalesLoadError(Object error) {
  final raw = error.toString().replaceFirst('Exception: ', '').trim();
  final lower = raw.toLowerCase();
  if (lower.contains('range cannot exceed')) {
    return 'El rango no puede exceder $_maxSalesRangeDays días.';
  }
  if (lower.contains('from must be before')) {
    return 'La fecha inicial debe ser anterior o igual a la fecha final.';
  }
  if (lower.contains('rango de fechas inv')) {
    return 'El rango de fechas no es válido.';
  }
  if (raw.isEmpty) return 'No se pudieron cargar las ventas.';
  return 'No se pudieron cargar las ventas: $raw';
}

String _salesRangeLabel(DateTime from, DateTime to) {
  final now = DateTime.now();
  final today = DateTime(now.year, now.month, now.day);
  final fromDay = DateTime(from.year, from.month, from.day);
  final toDay = DateTime(to.year, to.month, to.day);
  if (_sameSalesDate(fromDay, today) && _sameSalesDate(toDay, today)) {
    return 'Hoy';
  }
  if (_sameSalesDate(toDay, today) &&
      fromDay == today.subtract(const Duration(days: 6))) {
    return '7 dias';
  }
  if (_sameSalesDate(toDay, today) &&
      fromDay == today.subtract(const Duration(days: 29))) {
    return '30 dias';
  }
  if (_sameSalesDate(toDay, today) &&
      fromDay ==
          today.subtract(const Duration(days: _maxSalesRangeOffsetDays))) {
    return '365 dias';
  }
  final fmt = DateFormat('dd/MM/yyyy');
  return '${fmt.format(fromDay)} - ${fmt.format(toDay)}';
}

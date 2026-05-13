import 'dart:async';
import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';
import '../../../core/providers/sync_request_provider.dart';
import '../../../core/utils/accounting_format.dart';
import '../application/sales_date_filter_controller.dart';
import '../application/sales_financial_summary.dart';
import '../data/report_data.dart';
import '../data/report_realtime_projection.dart';
import '../data/report_models.dart';
import '../data/reports_repository.dart';
import '../data/sale_realtime_service.dart';
import 'widgets/sales_date_filter_bar.dart';

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
    if (widget.initialFrom != null || widget.initialTo != null) {
      final current = ref.read(salesDateFilterProvider).range;
      ref
          .read(salesDateFilterProvider.notifier)
          .applyCustomRange(
            widget.initialFrom ?? current.start,
            widget.initialTo ?? current.end,
          );
    }
    final range = ref.read(salesDateFilterProvider).range;
    _from = range.start;
    _to = range.end;
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
    ref.read(salesDateFilterProvider.notifier).applyCustomRange(from, to);
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
    final activeRange = ref.read(salesDateFilterProvider).range;
    _from = activeRange.start;
    _to = activeRange.end;
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
    ref.listen<SalesDateFilterState>(salesDateFilterProvider, (previous, next) {
      if (previous != null && previous.hasSameRangeAs(next)) return;
      final range = next.range;
      setState(() {
        _from = range.start;
        _to = range.end;
        _currentPage = 1;
      });
      unawaited(_load(page: 1, showLoading: true));
    });

    ref.listen<SyncRequest>(syncRequestProvider, (previous, next) {
      if (previous?.revision == next.revision) return;
      if (!next.appliesTo('/sales/list')) return;
      unawaited(_load(page: 1, showLoading: false));
    });

    final report = _reportData;
    final allSales = report?.sales ?? const <SaleRow>[];
    final financialSummary = SalesFinancialSummary.fromSales(
      allSales,
      totalProfit: report?.profit ?? 0,
    );
    const pageSize = 20;
    final totalPages = math.max(1, (allSales.length / pageSize).ceil());
    final startIndex = (_currentPage - 1) * pageSize;
    final endIndex = math.min(startIndex + pageSize, allSales.length);
    final visibleSales = startIndex >= allSales.length
        ? const <SaleRow>[]
        : allSales.sublist(startIndex, endIndex);

    final rangeLabel = _formatSalesDateRange(_from, _to);

    return LayoutBuilder(
      builder: (context, constraints) {
        final showSidePanel = constraints.maxWidth >= 1100;
        final panelWidth = constraints.maxWidth >= 1280 ? 340.0 : 312.0;
        final showFloatingSummary =
            !showSidePanel && !_loading && _error == null;

        final content = Padding(
          padding: const EdgeInsets.all(16),
          child: _loading
              ? _buildSalesStatusContent(
                  const Center(child: CircularProgressIndicator()),
                )
              : _error != null
              ? _buildSalesStatusContent(
                  _SalesLoadErrorState(
                    message: _error!,
                    rangeLabel: rangeLabel,
                    onRetry: () => _load(page: 1, showLoading: true),
                  ),
                )
              : showSidePanel
              ? Row(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Expanded(
                      child: _buildSalesListContent(
                        context: context,
                        allSales: allSales,
                        visibleSales: visibleSales,
                        totalPages: totalPages,
                        rangeLabel: rangeLabel,
                        listBottomPadding: 0,
                      ),
                    ),
                    const SizedBox(width: 14),
                    SizedBox(
                      width: panelWidth,
                      child: _FinancialSummaryPanel(
                        summary: financialSummary,
                        rangeLabel: rangeLabel,
                      ),
                    ),
                  ],
                )
              : _buildSalesListContent(
                  context: context,
                  allSales: allSales,
                  visibleSales: visibleSales,
                  totalPages: totalPages,
                  rangeLabel: rangeLabel,
                  listBottomPadding: 92,
                ),
        );

        return Stack(
          children: [
            Positioned.fill(child: content),
            if (showFloatingSummary)
              Positioned(
                right: 18,
                bottom: 18,
                child: _FloatingSummaryButton(
                  onPressed: () => _showFinancialSummarySheet(
                    context,
                    summary: financialSummary,
                    rangeLabel: rangeLabel,
                  ),
                ),
              ),
          ],
        );
      },
    );
  }

  Widget _buildSalesStatusContent(Widget child) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SalesDateFilterBar(),
        const SizedBox(height: 12),
        Expanded(child: child),
      ],
    );
  }

  Widget _buildSalesListContent({
    required BuildContext context,
    required List<SaleRow> allSales,
    required List<SaleRow> visibleSales,
    required int totalPages,
    required String rangeLabel,
    required double listBottomPadding,
  }) {
    final theme = Theme.of(context);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SalesDateFilterBar(),
        const SizedBox(height: 12),
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text('Ventas', style: theme.textTheme.titleMedium),
            Row(
              children: [
                IconButton(
                  icon: const Icon(Icons.chevron_left),
                  onPressed: _currentPage > 1
                      ? () => _load(page: _currentPage - 1, showLoading: true)
                      : null,
                ),
                Text('Página $_currentPage de $totalPages'),
                IconButton(
                  icon: const Icon(Icons.chevron_right),
                  onPressed: _currentPage < totalPages
                      ? () => _load(page: _currentPage + 1, showLoading: true)
                      : null,
                ),
              ],
            ),
          ],
        ),
        const SizedBox(height: 12),
        Expanded(
          child: allSales.isEmpty
              ? _SalesNoDataState(
                  rangeLabel: rangeLabel,
                  onChangeRange: () => unawaited(_pickCustomRange()),
                )
              : DecoratedBox(
                  decoration: BoxDecoration(
                    color: theme.colorScheme.surface,
                    borderRadius: BorderRadius.circular(16),
                    border: Border.all(color: theme.colorScheme.outlineVariant),
                  ),
                  child: ListView.separated(
                    padding: EdgeInsets.only(bottom: listBottomPadding),
                    itemCount: visibleSales.length,
                    separatorBuilder: (context, separatorIndex) =>
                        const Divider(height: 1),
                    itemBuilder: (context, index) {
                      final sale = visibleSales[index];
                      return _CompactSaleRow(
                        sale: sale,
                        onTap: () => context.go('/sales/detail/${sale.id}'),
                      );
                    },
                  ),
                ),
        ),
      ],
    );
  }
}

class _FinancialSummaryPanel extends StatelessWidget {
  const _FinancialSummaryPanel({
    required this.summary,
    required this.rangeLabel,
  });

  final SalesFinancialSummary summary;
  final String rangeLabel;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: theme.colorScheme.outlineVariant),
        boxShadow: [
          BoxShadow(
            color: theme.colorScheme.shadow.withValues(alpha: 0.06),
            blurRadius: 18,
            offset: const Offset(0, 8),
          ),
        ],
      ),
      child: SingleChildScrollView(
        child: _FinancialSummaryContent(
          summary: summary,
          rangeLabel: rangeLabel,
          showSheetHeader: false,
        ),
      ),
    );
  }
}

class _FinancialSummaryContent extends StatelessWidget {
  const _FinancialSummaryContent({
    required this.summary,
    required this.rangeLabel,
    required this.showSheetHeader,
  });

  final SalesFinancialSummary summary;
  final String rangeLabel;
  final bool showSheetHeader;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final dividerColor = theme.colorScheme.outlineVariant.withValues(
      alpha: 0.75,
    );

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        if (showSheetHeader) ...[
          Center(
            child: Container(
              width: 44,
              height: 4,
              decoration: BoxDecoration(
                color: theme.colorScheme.outlineVariant,
                borderRadius: BorderRadius.circular(999),
              ),
            ),
          ),
          const SizedBox(height: 18),
        ],
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              width: 36,
              height: 36,
              decoration: BoxDecoration(
                color: theme.colorScheme.primary.withValues(alpha: 0.12),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Icon(
                Icons.account_balance_wallet_outlined,
                size: 20,
                color: theme.colorScheme.primary,
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Resumen financiero',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: theme.textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w900,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    rangeLabel,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: theme.colorScheme.onSurfaceVariant,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
        const SizedBox(height: 16),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: theme.colorScheme.primaryContainer.withValues(alpha: 0.58),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Total vendido',
                style: theme.textTheme.labelMedium?.copyWith(
                  color: theme.colorScheme.onPrimaryContainer.withValues(
                    alpha: 0.76,
                  ),
                  fontWeight: FontWeight.w700,
                ),
              ),
              const SizedBox(height: 4),
              FittedBox(
                fit: BoxFit.scaleDown,
                alignment: Alignment.centerLeft,
                child: Text(
                  _formatDominicanAmount(summary.totalSold),
                  style: theme.textTheme.headlineSmall?.copyWith(
                    color: theme.colorScheme.onPrimaryContainer,
                    fontWeight: FontWeight.w900,
                  ),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        _FinancialAmountRow(
          icon: Icons.attach_money_rounded,
          label: 'Efectivo',
          amount: summary.totalCash,
          total: summary.totalSold,
        ),
        _FinancialAmountRow(
          icon: Icons.credit_card_outlined,
          label: 'Tarjeta',
          amount: summary.totalCard,
          total: summary.totalSold,
        ),
        _FinancialAmountRow(
          icon: Icons.account_balance_outlined,
          label: 'Transferencia',
          amount: summary.totalTransfer,
          total: summary.totalSold,
        ),
        _FinancialAmountRow(
          icon: Icons.pending_actions_outlined,
          label: 'Crédito',
          amount: summary.totalCredit,
          total: summary.totalSold,
        ),
        _FinancialAmountRow(
          icon: Icons.bookmark_border_rounded,
          label: 'Apartado',
          amount: summary.totalLayaway,
          total: summary.totalSold,
        ),
        _FinancialAmountRow(
          icon: Icons.more_horiz_rounded,
          label: 'Otros',
          amount: summary.totalOther,
          total: summary.totalSold,
        ),
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 10),
          child: Divider(height: 1, color: dividerColor),
        ),
        _FinancialMetricRow(
          icon: Icons.trending_up_outlined,
          label: 'Ganancia',
          value: _formatDominicanAmount(summary.totalProfit),
        ),
        _FinancialMetricRow(
          icon: Icons.receipt_long_outlined,
          label: 'Cantidad de ventas',
          value: '${summary.salesCount}',
        ),
        _FinancialMetricRow(
          icon: Icons.show_chart_rounded,
          label: 'Promedio por venta',
          value: _formatDominicanAmount(summary.averageSale),
        ),
        const SizedBox(height: 12),
        Text(
          'Calculado con las ventas del rango filtrado.',
          style: theme.textTheme.bodySmall?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
            fontWeight: FontWeight.w600,
          ),
        ),
      ],
    );
  }
}

class _FinancialAmountRow extends StatelessWidget {
  const _FinancialAmountRow({
    required this.icon,
    required this.label,
    required this.amount,
    required this.total,
  });

  final IconData icon;
  final String label;
  final double amount;
  final double total;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final ratio = total <= 0 ? 0.0 : (amount / total).clamp(0.0, 1.0);

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 7),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 18, color: theme.colorScheme.onSurfaceVariant),
              const SizedBox(width: 9),
              Expanded(
                child: Text(
                  label,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Flexible(
                child: Text(
                  _formatDominicanAmount(amount),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  textAlign: TextAlign.right,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    fontWeight: FontWeight.w900,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          ClipRRect(
            borderRadius: BorderRadius.circular(999),
            child: LinearProgressIndicator(
              value: ratio,
              minHeight: 4,
              backgroundColor: theme.colorScheme.surfaceContainerHighest,
            ),
          ),
        ],
      ),
    );
  }
}

class _FinancialMetricRow extends StatelessWidget {
  const _FinancialMetricRow({
    required this.icon,
    required this.label,
    required this.value,
  });

  final IconData icon;
  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 7),
      child: Row(
        children: [
          Icon(icon, size: 18, color: theme.colorScheme.onSurfaceVariant),
          const SizedBox(width: 9),
          Expanded(
            child: Text(
              label,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.bodyMedium?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
          const SizedBox(width: 8),
          Flexible(
            child: Text(
              value,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              textAlign: TextAlign.right,
              style: theme.textTheme.bodyMedium?.copyWith(
                fontWeight: FontWeight.w900,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _FloatingSummaryButton extends StatelessWidget {
  const _FloatingSummaryButton({required this.onPressed});

  final VoidCallback onPressed;

  @override
  Widget build(BuildContext context) {
    return FloatingActionButton.extended(
      heroTag: 'sales-financial-summary',
      onPressed: onPressed,
      icon: const Icon(Icons.account_balance_wallet_outlined),
      label: const Text('Resumen'),
    );
  }
}

void _showFinancialSummarySheet(
  BuildContext context, {
  required SalesFinancialSummary summary,
  required String rangeLabel,
}) {
  showModalBottomSheet<void>(
    context: context,
    useSafeArea: true,
    isScrollControlled: true,
    showDragHandle: false,
    builder: (context) {
      return Padding(
        padding: EdgeInsets.fromLTRB(
          18,
          14,
          18,
          18 + MediaQuery.viewInsetsOf(context).bottom,
        ),
        child: SingleChildScrollView(
          child: _FinancialSummaryContent(
            summary: summary,
            rangeLabel: rangeLabel,
            showSheetHeader: true,
          ),
        ),
      );
    },
  );
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
              'No hay ventas en este rango de fechas.',
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
    final paymentLabel = _translatePaymentMethod(sale.paymentMethod);
    final primaryLabel = _buildSalePrimaryLabel(sale);
    final productLabel = _buildSaleProductLabel(sale);
    final dateLabel = _formatSaleRowDate(sale.createdAt);
    final detailsLabel = [
      primaryLabel,
      dateLabel,
      paymentLabel,
    ].where((value) => value.trim().isNotEmpty).join(' • ');

    return InkWell(
      onTap: onTap,
      child: LayoutBuilder(
        builder: (context, constraints) {
          final isWide = constraints.maxWidth >= 720;
          return Padding(
            padding: EdgeInsets.symmetric(
              horizontal: isWide ? 16 : 12,
              vertical: isWide ? 12 : 10,
            ),
            child: Row(
              children: [
                Icon(
                  Icons.receipt_long_outlined,
                  size: 18,
                  color: theme.colorScheme.primary,
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: isWide
                      ? Row(
                          children: [
                            Expanded(
                              flex: 5,
                              child: _SaleRowProductText(productLabel),
                            ),
                            const SizedBox(width: 12),
                            Expanded(
                              flex: 4,
                              child: _SaleRowMetaText(detailsLabel),
                            ),
                          ],
                        )
                      : Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            _SaleRowProductText(productLabel),
                            const SizedBox(height: 3),
                            _SaleRowMetaText(detailsLabel),
                          ],
                        ),
                ),
                const SizedBox(width: 10),
                ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 140),
                  child: Text(
                    _formatDominicanAmount(sale.total),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    textAlign: TextAlign.right,
                    style: theme.textTheme.titleSmall?.copyWith(
                      fontWeight: FontWeight.w900,
                    ),
                  ),
                ),
              ],
            ),
          );
        },
      ),
    );
  }
}

class _SaleRowProductText extends StatelessWidget {
  const _SaleRowProductText(this.value);

  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Text(
      value,
      maxLines: 1,
      overflow: TextOverflow.ellipsis,
      style: theme.textTheme.bodyMedium?.copyWith(
        fontWeight: FontWeight.w900,
        color: theme.colorScheme.onSurface,
      ),
    );
  }
}

class _SaleRowMetaText extends StatelessWidget {
  const _SaleRowMetaText(this.value);

  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Text(
      value,
      maxLines: 1,
      overflow: TextOverflow.ellipsis,
      style: theme.textTheme.bodySmall?.copyWith(
        color: theme.colorScheme.onSurfaceVariant,
        fontWeight: FontWeight.w700,
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
  return 'Cliente general';
}

String _buildSaleProductLabel(SaleRow sale) {
  final names = sale.items
      .map(_saleRowItemProductName)
      .where((name) => name.isNotEmpty)
      .toList(growable: false);
  if (names.isEmpty) return 'Producto no disponible';

  final uniqueNames = <String>[];
  for (final name in names) {
    if (!uniqueNames.contains(name)) uniqueNames.add(name);
  }
  if (uniqueNames.length == 1) return uniqueNames.first;
  return '${uniqueNames.first} +${uniqueNames.length - 1} más';
}

String _saleRowItemProductName(SaleRowItem item) {
  final candidates = [item.productNameSnapshot, item.productName];
  for (final candidate in candidates) {
    final value = candidate?.trim();
    if (value != null && value.isNotEmpty) return value;
  }
  return '';
}

String _formatSaleRowDate(DateTime? value) {
  if (value == null) return 'Fecha no disponible';
  return DateFormat('dd/MM/yyyy hh:mm a').format(value.toLocal());
}

String _formatDominicanAmount(num value) {
  return 'RD\$${formatAccountingAmount(value)}';
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
          ? 'Método no especificado'
          : normalized;
  }
}

DateTime _salesDateOnly(DateTime value) {
  return DateTime(value.year, value.month, value.day);
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

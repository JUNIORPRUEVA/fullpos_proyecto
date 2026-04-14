import 'dart:async';
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../../core/config/app_config.dart';
import '../../../core/providers/sync_request_provider.dart';
import '../../../core/theme/app_colors.dart';
import '../../../core/utils/accounting_format.dart';
import '../../auth/data/auth_repository.dart';
import '../data/report_models.dart';
import '../data/reports_repository.dart';
import '../data/sale_realtime_service.dart';

class DashboardPage extends ConsumerStatefulWidget {
  const DashboardPage({super.key});

  @override
  ConsumerState<DashboardPage> createState() => _DashboardPageState();
}

class _DashboardPageState extends ConsumerState<DashboardPage>
    with WidgetsBindingObserver {
  StreamSubscription<SaleRealtimeMessage>? _saleRealtimeSubscription;
  bool _refreshInFlight = false;
  bool _reloadRequested = false;

  SalesSummary? _summary;
  List<SalesByDay> _byDay = const [];
  bool _loading = true;
  String _warningMessage = '';
  late DateTime _from;
  late DateTime _to;

  @override
  void initState() {
    super.initState();
    final now = DateTime.now();
    _from = DateTime(
      now.year,
      now.month,
      now.day,
    ).subtract(const Duration(days: 29));
    _to = now;
    WidgetsBinding.instance.addObserver(this);
    _load(showLoading: true);
    _saleRealtimeSubscription = ref
        .read(saleRealtimeServiceProvider)
        .stream
        .listen((_) => _load(showLoading: false));
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
      _load(showLoading: false);
    }
  }

  Future<void> _load({required bool showLoading}) async {
    if (_refreshInFlight) {
      _reloadRequested = true;
      return;
    }
    _refreshInFlight = true;
    _reloadRequested = false;

    if (showLoading && mounted) {
      setState(() {
        _loading = true;
        _warningMessage = '';
      });
    }

    final repo = ref.read(reportsRepositoryProvider);
    final formatter = DateFormat('yyyy-MM-dd');
    final warnings = <String>[];

    try {
      final results = await Future.wait<Object?>([
        _safeLoad<Object?>(
          loader: () =>
              repo.salesSummary(formatter.format(_from), formatter.format(_to)),
          fallback: const SalesSummary(total: 0, count: 0, average: 0),
          onError: () =>
              warnings.add('No se pudo cargar el resumen de ventas.'),
        ),
        _safeLoad<Object?>(
          loader: () =>
              repo.salesByDay(formatter.format(_from), formatter.format(_to)),
          fallback: const <SalesByDay>[],
          onError: () => warnings.add('No se pudo cargar la tendencia diaria.'),
        ),
      ]);

      if (!mounted) return;
      setState(() {
        _summary = results[0] as SalesSummary;
        _byDay = results[1] as List<SalesByDay>;
        _warningMessage = warnings.join(' ');
        _loading = false;
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _summary ??= const SalesSummary(total: 0, count: 0, average: 0);
        _warningMessage =
            'No se pudieron actualizar todos los datos, pero el panel sigue disponible.';
        _loading = false;
      });
    } finally {
      _refreshInFlight = false;
      if (_reloadRequested && mounted) {
        _reloadRequested = false;
        unawaited(_load(showLoading: false));
      }
    }
  }

  Future<T> _safeLoad<T>({
    required Future<T> Function() loader,
    required T fallback,
    required VoidCallback onError,
  }) async {
    try {
      return await loader();
    } catch (_) {
      onError();
      return fallback;
    }
  }

  void _updateRange(DateTime from, DateTime to) {
    setState(() {
      _from = from;
      _to = to;
    });
    _load(showLoading: true);
  }

  String _formatReportAmount(num value) {
    return 'RD\$ ${formatAccountingAmount(value)}';
  }

  Future<void> _showMetricPreview(
    BuildContext context, {
    required _MetricInfo metric,
    required bool isPhone,
    required double width,
  }) {
    final previewWidth = isPhone
        ? width - 12
        : width < 1100
        ? width * 0.86
        : math.min(width * 0.72, 960.0);

    return showGeneralDialog<void>(
      context: context,
      barrierLabel: 'Vista de tarjeta',
      barrierDismissible: true,
      barrierColor: Colors.black.withValues(alpha: 0.52),
      transitionDuration: const Duration(milliseconds: 260),
      pageBuilder: (dialogContext, animation, secondaryAnimation) {
        return SafeArea(
          child: Center(
            child: Padding(
              padding: EdgeInsets.symmetric(
                horizontal: isPhone ? 6 : 24,
                vertical: isPhone ? 18 : 28,
              ),
              child: Material(
                color: Colors.transparent,
                child: SizedBox(
                  width: previewWidth,
                  child: _MetricPreviewSheet(
                    metric: metric,
                    onClose: () => Navigator.of(dialogContext).pop(),
                  ),
                ),
              ),
            ),
          ),
        );
      },
      transitionBuilder: (context, animation, secondaryAnimation, child) {
        final curved = CurvedAnimation(
          parent: animation,
          curve: Curves.easeOutCubic,
          reverseCurve: Curves.easeInCubic,
        );
        return FadeTransition(
          opacity: curved,
          child: ScaleTransition(
            scale: Tween<double>(begin: 0.86, end: 1.0).animate(curved),
            child: SlideTransition(
              position: Tween<Offset>(
                begin: const Offset(0, 0.06),
                end: Offset.zero,
              ).animate(curved),
              child: child,
            ),
          ),
        );
      },
    );
  }

  void _applyQuickRange(int days) {
    final now = DateTime.now();
    final start = days == 0
        ? DateTime(now.year, now.month, now.day)
        : DateTime(
            now.year,
            now.month,
            now.day,
          ).subtract(Duration(days: days - 1));
    _updateRange(start, now);
  }

  void _applyPresetRange(_ReportRangeOption option) {
    final now = DateTime.now();
    switch (option) {
      case _ReportRangeOption.today:
        _applyQuickRange(0);
        return;
      case _ReportRangeOption.yesterday:
        final yesterday = DateTime(
          now.year,
          now.month,
          now.day,
        ).subtract(const Duration(days: 1));
        _updateRange(yesterday, yesterday);
        return;
      case _ReportRangeOption.week:
        _applyQuickRange(7);
        return;
      case _ReportRangeOption.custom:
        _openCustomRangeSheet();
        return;
    }
  }

  _ReportRangeOption _currentRangeOption() {
    final now = DateTime.now();
    final today = DateTime(now.year, now.month, now.day);
    final fromDay = DateTime(_from.year, _from.month, _from.day);
    final toDay = DateTime(_to.year, _to.month, _to.day);
    final yesterday = today.subtract(const Duration(days: 1));

    if (_isSameDate(fromDay, today) && _isSameDate(toDay, today)) {
      return _ReportRangeOption.today;
    }
    if (_isSameDate(fromDay, yesterday) && _isSameDate(toDay, yesterday)) {
      return _ReportRangeOption.yesterday;
    }
    if (_isSameDate(toDay, today) &&
        fromDay == today.subtract(const Duration(days: 6))) {
      return _ReportRangeOption.week;
    }
    return _ReportRangeOption.custom;
  }

  Future<void> _openCustomRangeSheet() async {
    var localFrom = DateTime(_from.year, _from.month, _from.day);
    var localTo = DateTime(_to.year, _to.month, _to.day);

    final picked = await showModalBottomSheet<DateTimeRange>(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) {
        return StatefulBuilder(
          builder: (context, setSheetState) {
            Future<void> pickDate({required bool isStart}) async {
              final initial = isStart ? localFrom : localTo;
              final selected = await showDatePicker(
                context: context,
                initialDate: initial,
                firstDate: DateTime.now().subtract(const Duration(days: 365)),
                lastDate: DateTime.now().add(const Duration(days: 1)),
              );
              if (selected == null) return;
              setSheetState(() {
                if (isStart) {
                  localFrom = DateTime(
                    selected.year,
                    selected.month,
                    selected.day,
                  );
                  if (localFrom.isAfter(localTo)) {
                    localTo = localFrom;
                  }
                } else {
                  localTo = DateTime(
                    selected.year,
                    selected.month,
                    selected.day,
                  );
                  if (localTo.isBefore(localFrom)) {
                    localFrom = localTo;
                  }
                }
              });
            }

            void applyInlinePreset(_CustomPreset preset) {
              final now = DateTime.now();
              setSheetState(() {
                switch (preset) {
                  case _CustomPreset.last15Days:
                    localTo = DateTime(now.year, now.month, now.day);
                    localFrom = localTo.subtract(const Duration(days: 14));
                    return;
                  case _CustomPreset.currentMonth:
                    localTo = DateTime(now.year, now.month, now.day);
                    localFrom = DateTime(now.year, now.month, 1);
                    return;
                }
              });
            }

            return FractionallySizedBox(
              heightFactor: 0.38,
              child: Container(
                decoration: const BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.vertical(top: Radius.circular(28)),
                ),
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(18, 18, 18, 18),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Center(
                        child: Container(
                          width: 44,
                          height: 5,
                          decoration: BoxDecoration(
                            color: Colors.black.withValues(alpha: 0.12),
                            borderRadius: BorderRadius.circular(999),
                          ),
                        ),
                      ),
                      const SizedBox(height: 16),
                      Text(
                        'Rango personalizado',
                        style: Theme.of(context).textTheme.titleMedium
                            ?.copyWith(fontWeight: FontWeight.w800),
                      ),
                      const SizedBox(height: 14),
                      Row(
                        children: [
                          Expanded(
                            child: _DateMiniCard(
                              label: 'Desde',
                              value: DateFormat('dd MMM').format(localFrom),
                              icon: Icons.calendar_today_outlined,
                              onTap: () => pickDate(isStart: true),
                            ),
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: _DateMiniCard(
                              label: 'Hasta',
                              value: DateFormat('dd MMM').format(localTo),
                              icon: Icons.event_outlined,
                              onTap: () => pickDate(isStart: false),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 14),
                      Row(
                        children: [
                          Expanded(
                            child: _PresetMiniChip(
                              label: '15 días',
                              onTap: () =>
                                  applyInlinePreset(_CustomPreset.last15Days),
                            ),
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: _PresetMiniChip(
                              label: 'Mes',
                              onTap: () =>
                                  applyInlinePreset(_CustomPreset.currentMonth),
                            ),
                          ),
                        ],
                      ),
                      const Spacer(),
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
                                Navigator.of(context).pop(
                                  DateTimeRange(start: localFrom, end: localTo),
                                );
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

    if (picked == null) return;
    _updateRange(picked.start, picked.end);
  }

  @override
  Widget build(BuildContext context) {
    ref.listen<SyncRequest>(syncRequestProvider, (previous, next) {
      if (previous?.revision == next.revision) return;
      if (!next.appliesTo('/dashboard')) return;
      unawaited(_load(showLoading: false));
    });

    final theme = Theme.of(context);
    final authState = ref.watch(authRepositoryProvider);
    final appConfig = ref.watch(appConfigProvider);
    final summary = _summary;
    final total = (summary?.total ?? 0).toDouble();
    final totalCost = (summary?.totalCost ?? 0).toDouble();
    final expensesTotal = (summary?.expenses ?? 0).toDouble();
    final profit = (summary?.profit ?? 0).toDouble();
    final margin = total > 0 ? (profit / total) * 100 : 0.0;
    final chartData = _byDay.length > 30
        ? _byDay.sublist(_byDay.length - 30)
        : _byDay;
    final averageDay = (summary?.average ?? 0).toDouble();
    final hasNoVisibleData = !_loading && chartData.isEmpty && total == 0;
    final peakDay = chartData.isEmpty
        ? null
        : chartData.reduce(
            (left, right) => right.total > left.total ? right : left,
          );
    final formatter = DateFormat('yyyy-MM-dd');
    final fromStr = formatter.format(_from);
    final toStr = formatter.format(_to);

    return LayoutBuilder(
      builder: (context, constraints) {
        final width = constraints.maxWidth;
        final isPhone = width < 700;
        final columns = width >= 1100 ? 3 : 3;
        final metricRatio = width >= 1100 ? 2.7 : 2.25;
        final chartHeight = width >= 1100
            ? 300.0
            : width >= 700
            ? 250.0
            : 290.0;
        final activeRange = _currentRangeOption();
        final metricItems = [
          _MetricInfo(
            title: 'Ventas',
            value: _formatReportAmount(total),
            caption: chartData.isEmpty
                ? 'Sin movimiento'
                : '${chartData.length} días medidos',
            icon: Icons.payments_outlined,
            color: theme.colorScheme.primary,
          ),
          _MetricInfo(
            title: 'Gastos',
            value: _formatReportAmount(expensesTotal),
            caption: expensesTotal == 0 ? 'Sin cargos' : 'Egresos del rango',
            icon: Icons.receipt_long_outlined,
            color: AppColors.warning,
          ),
          _MetricInfo(
            title: 'Ganancias',
            value: _formatReportAmount(profit),
            caption: '${margin.toStringAsFixed(1)}% margen',
            icon: Icons.trending_up_outlined,
            color: profit >= 0 ? AppColors.success : AppColors.danger,
          ),
        ];

        return SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(12, 6, 12, 12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (_loading)
                const Padding(
                  padding: EdgeInsets.only(bottom: 10),
                  child: LinearProgressIndicator(minHeight: 3),
                ),
              if (_warningMessage.isNotEmpty) ...[
                _WarningBanner(
                  message: _warningMessage,
                  onRetry: () => _load(showLoading: true),
                ),
                const SizedBox(height: 12),
              ],
              if (hasNoVisibleData) ...[
                _TenantHintBanner(
                  companyName: authState.companyName?.trim(),
                  companyRnc: authState.companyRnc?.trim(),
                  companyId: authState.companyId?.toString(),
                  serverUrl: appConfig.baseUrl,
                ),
                const SizedBox(height: 12),
              ],
              _SurfaceCard(
                padding: EdgeInsets.fromLTRB(
                  isPhone ? 8 : 12,
                  8,
                  isPhone ? 8 : 12,
                  8,
                ),
                child: _FilterBar(
                  from: _from,
                  to: _to,
                  activeOption: activeRange,
                  compact: isPhone,
                  onSelectOption: _applyPresetRange,
                ),
              ),
              const SizedBox(height: 12),
              isPhone
                  ? _MobileMetricStrip(
                      items: metricItems,
                      onTap: (index) {
                        _showMetricPreview(
                          context,
                          metric: metricItems[index],
                          isPhone: isPhone,
                          width: width,
                        );
                      },
                    )
                  : GridView.count(
                      crossAxisCount: columns,
                      childAspectRatio: metricRatio,
                      mainAxisSpacing: 12,
                      crossAxisSpacing: 12,
                      shrinkWrap: true,
                      physics: const NeverScrollableScrollPhysics(),
                      children: [
                        for (var index = 0; index < metricItems.length; index++)
                          _MetricCard(
                            title: metricItems[index].title,
                            value: metricItems[index].value,
                            caption: metricItems[index].caption,
                            icon: metricItems[index].icon,
                            color: metricItems[index].color,
                            emphasized: true,
                            onTap: () {
                              _showMetricPreview(
                                context,
                                metric: metricItems[index],
                                isPhone: isPhone,
                                width: width,
                              );
                            },
                          ),
                      ],
                    ),
              const SizedBox(height: 12),
              _SurfaceCard(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                'Ventas',
                                style: theme.textTheme.titleLarge?.copyWith(
                                  fontWeight: FontWeight.w800,
                                  letterSpacing: -0.3,
                                ),
                              ),
                              const SizedBox(height: 4),
                              Text(
                                chartData.isEmpty
                                    ? 'Sin datos recientes'
                                    : chartData.length == 1
                                    ? 'Hoy'
                                    : '$fromStr · $toStr',
                                style: theme.textTheme.bodyMedium?.copyWith(
                                  color: theme.colorScheme.onSurfaceVariant,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            ],
                          ),
                        ),
                        if (chartData.isNotEmpty)
                          FilledButton.tonalIcon(
                            onPressed: () {
                              context.go('/sales/list?from=$fromStr&to=$toStr');
                            },
                            icon: const Icon(Icons.visibility_outlined),
                            label: const Text('Detalle'),
                          ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    isPhone
                        ? Row(
                            children: [
                              Expanded(
                                child: _StatPill(
                                  label: 'Promedio',
                                  value: _formatReportAmount(averageDay),
                                  color: theme.colorScheme.primary,
                                  compact: true,
                                ),
                              ),
                              const SizedBox(width: 8),
                              Expanded(
                                child: _StatPill(
                                  label: 'Margen',
                                  value: '${margin.toStringAsFixed(1)}%',
                                  color: AppColors.success,
                                  compact: true,
                                ),
                              ),
                              const SizedBox(width: 8),
                              Expanded(
                                child: _StatPill(
                                  label: 'Pico',
                                  value: peakDay == null
                                      ? '--'
                                      : _formatDayLabel(peakDay.date),
                                  color: theme.colorScheme.secondary,
                                  compact: true,
                                ),
                              ),
                            ],
                          )
                        : Wrap(
                            spacing: 8,
                            runSpacing: 8,
                            children: [
                              _StatPill(
                                label: 'Promedio',
                                value: _formatReportAmount(averageDay),
                                color: theme.colorScheme.primary,
                              ),
                              _StatPill(
                                label: 'Margen',
                                value: '${margin.toStringAsFixed(1)}%',
                                color: AppColors.success,
                              ),
                              _StatPill(
                                label: 'Costo',
                                value: _formatReportAmount(totalCost),
                                color: AppColors.warning,
                              ),
                              _StatPill(
                                label: 'Pico',
                                value: peakDay == null
                                    ? '--'
                                    : '${_formatDayLabel(peakDay.date)} · ${_formatReportAmount(peakDay.total)}',
                                color: theme.colorScheme.secondary,
                              ),
                            ],
                          ),
                    const SizedBox(height: 14),
                    if (chartData.isEmpty)
                      const _EmptyState()
                    else
                      SizedBox(
                        height: chartHeight,
                        child: _SalesTrendChart(
                          data: chartData,
                          formatAmount: _formatReportAmount,
                        ),
                      ),
                  ],
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}

class _FilterBar extends StatelessWidget {
  const _FilterBar({
    required this.from,
    required this.to,
    required this.activeOption,
    required this.compact,
    required this.onSelectOption,
  });

  final DateTime from;
  final DateTime to;
  final _ReportRangeOption activeOption;
  final bool compact;
  final ValueChanged<_ReportRangeOption> onSelectOption;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final dateLabel =
        '${DateFormat('dd MMM').format(from)} · ${DateFormat('dd MMM').format(to)}';

    final buttons = const <({String label, _ReportRangeOption option})>[
      (label: 'Hoy', option: _ReportRangeOption.today),
      (label: 'Ayer', option: _ReportRangeOption.yesterday),
      (label: 'Semana', option: _ReportRangeOption.week),
      (label: 'Personalizado', option: _ReportRangeOption.custom),
    ];

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          padding: EdgeInsets.all(compact ? 3 : 4),
          decoration: BoxDecoration(
            color: theme.colorScheme.surfaceContainerLowest,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: theme.colorScheme.outlineVariant),
          ),
          child: Row(
            children: buttons
                .map(
                  (item) => Expanded(
                    child: _RangeSegmentButton(
                      label: item.label,
                      selected: activeOption == item.option,
                      compact: compact,
                      onTap: () => onSelectOption(item.option),
                    ),
                  ),
                )
                .toList(),
          ),
        ),
        if (!compact) ...[
          const SizedBox(height: 10),
          Text(
            dateLabel,
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ],
    );
  }
}

class _RangeSegmentButton extends StatelessWidget {
  const _RangeSegmentButton({
    required this.label,
    required this.selected,
    required this.compact,
    required this.onTap,
  });

  final String label;
  final bool selected;
  final bool compact;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return AnimatedContainer(
      duration: const Duration(milliseconds: 180),
      curve: Curves.easeOutCubic,
      margin: const EdgeInsets.symmetric(horizontal: 2),
      child: Material(
        color: selected ? theme.colorScheme.primary : Colors.transparent,
        borderRadius: BorderRadius.circular(12),
        child: InkWell(
          borderRadius: BorderRadius.circular(12),
          onTap: onTap,
          child: Padding(
            padding: EdgeInsets.symmetric(
              horizontal: 4,
              vertical: compact ? 8 : 9,
            ),
            child: Text(
              label,
              textAlign: TextAlign.center,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.labelLarge?.copyWith(
                color: selected
                    ? theme.colorScheme.onPrimary
                    : theme.colorScheme.onSurfaceVariant,
                fontWeight: FontWeight.w800,
                fontSize: compact ? 11.5 : 13,
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _SurfaceCard extends StatelessWidget {
  const _SurfaceCard({
    required this.child,
    this.padding = const EdgeInsets.all(16),
  });

  final Widget child;
  final EdgeInsetsGeometry padding;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      width: double.infinity,
      padding: padding,
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [
            theme.colorScheme.surface,
            theme.colorScheme.surfaceContainerLowest,
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: theme.colorScheme.outlineVariant),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.035),
            blurRadius: 12,
            offset: const Offset(0, 3),
          ),
        ],
      ),
      child: child,
    );
  }
}

class _WarningBanner extends StatelessWidget {
  const _WarningBanner({required this.message, required this.onRetry});

  final String message;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: AppColors.warning.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppColors.warning.withValues(alpha: 0.24)),
      ),
      child: Row(
        children: [
          const Icon(Icons.info_outline, color: AppColors.warning, size: 20),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              message,
              style: theme.textTheme.bodyMedium?.copyWith(height: 1.35),
            ),
          ),
          TextButton(onPressed: onRetry, child: const Text('Reintentar')),
        ],
      ),
    );
  }
}

class _TenantHintBanner extends StatelessWidget {
  const _TenantHintBanner({
    required this.companyName,
    required this.companyRnc,
    required this.companyId,
    required this.serverUrl,
  });

  final String? companyName;
  final String? companyRnc;
  final String? companyId;
  final String serverUrl;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final sessionParts = <String>[
      if (companyName != null && companyName!.isNotEmpty) companyName!,
      if (companyRnc != null && companyRnc!.isNotEmpty) 'RNC $companyRnc',
      if (companyId != null && companyId!.isNotEmpty) 'ID $companyId',
    ];

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
      decoration: BoxDecoration(
        color: theme.colorScheme.primary.withValues(alpha: 0.06),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: theme.colorScheme.primary.withValues(alpha: 0.16),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'No hubo movimientos en el rango actual',
            style: theme.textTheme.titleSmall?.copyWith(
              fontWeight: FontWeight.w800,
            ),
          ),
          const SizedBox(height: 6),
          Text(
            'La sesión activa está consultando esta empresa en la nube. Si otro admin sí ve ventas y este no, el problema suele ser la empresa asociada al usuario, no la pantalla.',
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
              height: 1.35,
            ),
          ),
          if (sessionParts.isNotEmpty) ...[
            const SizedBox(height: 10),
            Text(
              sessionParts.join(' · '),
              style: theme.textTheme.bodySmall?.copyWith(
                fontWeight: FontWeight.w700,
              ),
            ),
          ],
          const SizedBox(height: 4),
          Text(
            serverUrl,
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ),
    );
  }
}

class _MetricCard extends StatelessWidget {
  const _MetricCard({
    required this.title,
    required this.value,
    required this.caption,
    required this.icon,
    required this.color,
    this.emphasized = false,
    this.large = false,
    this.onTap,
  });

  final String title;
  final String value;
  final String caption;
  final IconData icon;
  final Color color;
  final bool emphasized;
  final bool large;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final content = Container(
      padding: EdgeInsets.symmetric(
        horizontal: large
            ? 26
            : emphasized
            ? 14
            : 12,
        vertical: large
            ? 26
            : emphasized
            ? 12
            : 11,
      ),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(
          large
              ? 22
              : emphasized
              ? 18
              : 16,
        ),
        border: Border.all(
          color: color.withValues(
            alpha: large
                ? 0.24
                : emphasized
                ? 0.18
                : 0.14,
          ),
        ),
        boxShadow: emphasized || large
            ? [
                BoxShadow(
                  color: color.withValues(alpha: large ? 0.12 : 0.08),
                  blurRadius: large ? 22 : 16,
                  offset: Offset(0, large ? 8 : 5),
                ),
              ]
            : null,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          Row(
            children: [
              Container(
                width: large
                    ? 56
                    : emphasized
                    ? 34
                    : 30,
                height: large
                    ? 56
                    : emphasized
                    ? 34
                    : 30,
                decoration: BoxDecoration(
                  color: color.withValues(alpha: 0.10),
                  borderRadius: BorderRadius.circular(large ? 18 : 11),
                ),
                child: Icon(
                  icon,
                  color: color,
                  size: large
                      ? 28
                      : emphasized
                      ? 18
                      : 16,
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  title,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.labelLarge?.copyWith(
                    color: color,
                    fontWeight: FontWeight.w800,
                    fontSize: large ? 19 : null,
                  ),
                ),
              ),
            ],
          ),
          SizedBox(height: large ? 22 : 10),
          FittedBox(
            fit: BoxFit.scaleDown,
            alignment: Alignment.centerLeft,
            child: Text(
              value,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.headlineSmall?.copyWith(
                fontWeight: FontWeight.w800,
                letterSpacing: -0.6,
                fontSize: large
                    ? 42
                    : emphasized
                    ? 22
                    : 18,
              ),
            ),
          ),
          SizedBox(height: large ? 12 : 4),
          Text(
            caption,
            maxLines: large ? 3 : 1,
            overflow: TextOverflow.ellipsis,
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
              fontWeight: FontWeight.w600,
              fontSize: large ? 15 : null,
            ),
          ),
          if (large) ...[
            const SizedBox(height: 18),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
              decoration: BoxDecoration(
                color: color.withValues(alpha: 0.08),
                borderRadius: BorderRadius.circular(14),
              ),
              child: Row(
                children: [
                  Icon(Icons.touch_app_outlined, size: 18, color: color),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'Toque fuera de la tarjeta para cerrarla.',
                      style: theme.textTheme.bodyMedium?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ],
      ),
    );

    if (onTap == null) {
      return content;
    }

    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(18),
        onTap: onTap,
        child: content,
      ),
    );
  }
}

class _StatPill extends StatelessWidget {
  const _StatPill({
    required this.label,
    required this.value,
    required this.color,
    this.compact = false,
  });

  final String label;
  final String value;
  final Color color;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: EdgeInsets.symmetric(
        horizontal: compact ? 10 : 12,
        vertical: compact ? 9 : 10,
      ),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: color.withValues(alpha: 0.18)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: theme.textTheme.labelMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            value,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: theme.textTheme.titleSmall?.copyWith(
              color: color,
              fontWeight: FontWeight.w800,
              fontSize: compact ? 13 : null,
            ),
          ),
        ],
      ),
    );
  }
}

class _MobileMetricStrip extends StatelessWidget {
  const _MobileMetricStrip({required this.items, required this.onTap});

  final List<_MetricInfo> items;
  final ValueChanged<int> onTap;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        for (var index = 0; index < items.length; index++) ...[
          Expanded(
            child: _MetricCard(
              title: items[index].title,
              value: items[index].value,
              caption: items[index].caption,
              icon: items[index].icon,
              color: items[index].color,
              emphasized: true,
              onTap: () => onTap(index),
            ),
          ),
          if (index != items.length - 1) const SizedBox(width: 8),
        ],
      ],
    );
  }
}

class _MetricPreviewSheet extends StatelessWidget {
  const _MetricPreviewSheet({required this.metric, required this.onClose});

  final _MetricInfo metric;
  final VoidCallback onClose;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final width = MediaQuery.sizeOf(context).width;
    final maxCardHeight = width < 700 ? 360.0 : 430.0;

    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [
            theme.colorScheme.surface,
            theme.colorScheme.surfaceContainerLowest,
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(30),
        border: Border.all(color: metric.color.withValues(alpha: 0.24)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.18),
            blurRadius: 36,
            offset: const Offset(0, 18),
          ),
        ],
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  'Vista ampliada',
                  style: theme.textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w800,
                    letterSpacing: -0.2,
                  ),
                ),
              ),
              IconButton(
                tooltip: 'Cerrar',
                onPressed: onClose,
                icon: const Icon(Icons.close_rounded),
              ),
            ],
          ),
          const SizedBox(height: 12),
          ConstrainedBox(
            constraints: BoxConstraints(maxHeight: maxCardHeight),
            child: SingleChildScrollView(
              child: _MetricCard(
                title: metric.title,
                value: metric.value,
                caption: metric.caption,
                icon: metric.icon,
                color: metric.color,
                emphasized: true,
                large: true,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _DateMiniCard extends StatelessWidget {
  const _DateMiniCard({
    required this.label,
    required this.value,
    required this.icon,
    required this.onTap,
  });

  final String label;
  final String value;
  final IconData icon;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return InkWell(
      borderRadius: BorderRadius.circular(18),
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
        decoration: BoxDecoration(
          color: theme.colorScheme.surfaceContainerLowest,
          borderRadius: BorderRadius.circular(18),
          border: Border.all(color: theme.colorScheme.outlineVariant),
        ),
        child: Row(
          children: [
            Icon(icon, size: 18, color: theme.colorScheme.primary),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    label,
                    style: theme.textTheme.labelMedium?.copyWith(
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                  const SizedBox(height: 3),
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
      ),
    );
  }
}

class _PresetMiniChip extends StatelessWidget {
  const _PresetMiniChip({required this.label, required this.onTap});

  final String label;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return OutlinedButton(
      onPressed: onTap,
      style: OutlinedButton.styleFrom(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 13),
        side: BorderSide(color: theme.colorScheme.outlineVariant),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      ),
      child: Text(label),
    );
  }
}

class _MetricInfo {
  const _MetricInfo({
    required this.title,
    required this.value,
    required this.caption,
    required this.icon,
    required this.color,
  });

  final String title;
  final String value;
  final String caption;
  final IconData icon;
  final Color color;
}

enum _ReportRangeOption { today, yesterday, week, custom }

enum _CustomPreset { last15Days, currentMonth }

class _EmptyState extends StatelessWidget {
  const _EmptyState();

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 28),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: Column(
        children: [
          Icon(
            Icons.show_chart_outlined,
            size: 28,
            color: theme.colorScheme.onSurfaceVariant,
          ),
          const SizedBox(height: 10),
          Text(
            'Sin ventas en el rango seleccionado.',
            style: theme.textTheme.titleSmall?.copyWith(
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            'Prueba con otro rango para ver el rendimiento diario.',
            textAlign: TextAlign.center,
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ),
    );
  }
}

class _SalesTrendChart extends StatefulWidget {
  const _SalesTrendChart({required this.data, required this.formatAmount});

  final List<SalesByDay> data;
  final String Function(num value) formatAmount;

  @override
  State<_SalesTrendChart> createState() => _SalesTrendChartState();
}

class _SalesTrendChartState extends State<_SalesTrendChart> {
  int? _selectedIndex;

  @override
  void initState() {
    super.initState();
    _selectedIndex = widget.data.isEmpty ? null : widget.data.length - 1;
  }

  @override
  void didUpdateWidget(covariant _SalesTrendChart oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.data.isEmpty) {
      _selectedIndex = null;
      return;
    }
    final previous = _selectedIndex ?? widget.data.length - 1;
    _selectedIndex = previous.clamp(0, widget.data.length - 1);
  }

  void _updateSelectedIndex(double localDx, double width) {
    if (widget.data.isEmpty || width <= 0) return;
    final segment = widget.data.length == 1
        ? width
        : width / (widget.data.length - 1);
    final raw = widget.data.length == 1 ? 0 : (localDx / segment).round();
    final nextIndex = raw.clamp(0, widget.data.length - 1);
    if (nextIndex == _selectedIndex) return;
    setState(() {
      _selectedIndex = nextIndex;
    });
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final data = widget.data;
    final formatAmount = widget.formatAmount;
    final maxValue = data.isEmpty
        ? 0.0
        : data.map((item) => item.total).fold<double>(0, math.max);
    final lastValue = data.isEmpty ? 0.0 : data.last.total;
    final totalValue = data.fold<double>(0, (sum, item) => sum + item.total);
    final averageValue = data.isEmpty ? 0.0 : totalValue / data.length;
    final peakValue = maxValue <= 0 ? 1.0 : maxValue;
    final axisValues = [peakValue, peakValue * 0.66, peakValue * 0.33, 0.0];

    return Container(
      padding: const EdgeInsets.fromLTRB(12, 12, 12, 10),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [
            theme.colorScheme.primary.withValues(alpha: 0.06),
            theme.colorScheme.surface,
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              _ChartSummaryChip(
                label: 'Cierre',
                value: formatAmount(lastValue),
                color: theme.colorScheme.primary,
              ),
              _ChartSummaryChip(
                label: 'Promedio',
                value: formatAmount(averageValue),
                color: AppColors.success,
              ),
              _ChartSummaryChip(
                label: 'Máximo',
                value: formatAmount(maxValue),
                color: theme.colorScheme.secondary,
              ),
            ],
          ),
          const SizedBox(height: 12),
          Expanded(
            child: Row(
              children: [
                SizedBox(
                  width: 78,
                  child: _ChartYAxis(
                    values: axisValues,
                    formatAmount: formatAmount,
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: LayoutBuilder(
                    builder: (context, chartConstraints) {
                      final chartWidth = chartConstraints.maxWidth;
                      return Column(
                        children: [
                          Expanded(
                            child: GestureDetector(
                              behavior: HitTestBehavior.opaque,
                              onTapDown: (details) => _updateSelectedIndex(
                                details.localPosition.dx,
                                chartWidth,
                              ),
                              onHorizontalDragStart: (details) =>
                                  _updateSelectedIndex(
                                    details.localPosition.dx,
                                    chartWidth,
                                  ),
                              onHorizontalDragUpdate: (details) =>
                                  _updateSelectedIndex(
                                    details.localPosition.dx,
                                    chartWidth,
                                  ),
                              child: Stack(
                                clipBehavior: Clip.none,
                                children: [
                                  Positioned.fill(
                                    child: CustomPaint(
                                      size: Size.infinite,
                                      painter: _SalesTrendPainter(
                                        data: data,
                                        lineColor: theme.colorScheme.primary,
                                        fillColor: theme.colorScheme.primary
                                            .withValues(alpha: 0.16),
                                        gridColor:
                                            theme.colorScheme.outlineVariant,
                                        highlightedIndex: _selectedIndex,
                                      ),
                                    ),
                                  ),
                                  if (_selectedIndex != null)
                                    _ChartTooltipOverlay(
                                      data: data,
                                      selectedIndex: _selectedIndex!,
                                      maxValue: peakValue,
                                      formatAmount: formatAmount,
                                    ),
                                ],
                              ),
                            ),
                          ),
                          const SizedBox(height: 10),
                          _ChartLabels(
                            data: data,
                            selectedIndex: _selectedIndex,
                          ),
                        ],
                      );
                    },
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

class _ChartSummaryChip extends StatelessWidget {
  const _ChartSummaryChip({
    required this.label,
    required this.value,
    required this.color,
  });

  final String label;
  final String value;
  final Color color;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withValues(alpha: 0.18)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            label,
            style: theme.textTheme.labelMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            value,
            style: theme.textTheme.titleSmall?.copyWith(
              color: color,
              fontWeight: FontWeight.w800,
            ),
          ),
        ],
      ),
    );
  }
}

class _ChartYAxis extends StatelessWidget {
  const _ChartYAxis({required this.values, required this.formatAmount});

  final List<double> values;
  final String Function(num value) formatAmount;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.end,
      children: [
        for (var index = 0; index < values.length; index++) ...[
          Text(
            formatAmount(values[index]),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
              fontWeight: FontWeight.w600,
            ),
          ),
          if (index != values.length - 1) const Spacer(),
        ],
      ],
    );
  }
}

class _ChartTooltipOverlay extends StatelessWidget {
  const _ChartTooltipOverlay({
    required this.data,
    required this.selectedIndex,
    required this.maxValue,
    required this.formatAmount,
  });

  final List<SalesByDay> data;
  final int selectedIndex;
  final double maxValue;
  final String Function(num value) formatAmount;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return LayoutBuilder(
      builder: (context, constraints) {
        const leftInset = 10.0;
        const topInset = 12.0;
        final usableWidth = constraints.maxWidth - (leftInset * 2);
        final usableHeight = constraints.maxHeight - (topInset * 2);
        final count = data.length;
        final item = data[selectedIndex];
        final x = count <= 1
            ? constraints.maxWidth / 2
            : leftInset + (usableWidth / (count - 1)) * selectedIndex;
        final y =
            topInset +
            usableHeight -
            ((item.total <= 0 ? 0.0 : item.total / maxValue) * usableHeight);
        final tooltipWidth = math.min(138.0, constraints.maxWidth - 8);
        final left = (x - tooltipWidth / 2).clamp(
          4.0,
          constraints.maxWidth - tooltipWidth - 4.0,
        );
        final top = (y - 64).clamp(4.0, constraints.maxHeight - 58.0);

        return Stack(
          children: [
            Positioned(
              left: x - 0.5,
              top: 6,
              bottom: 6,
              child: Container(
                width: 1,
                color: theme.colorScheme.primary.withValues(alpha: 0.22),
              ),
            ),
            Positioned(
              left: left,
              top: top,
              child: IgnorePointer(
                child: Container(
                  width: tooltipWidth,
                  padding: const EdgeInsets.symmetric(
                    horizontal: 10,
                    vertical: 8,
                  ),
                  decoration: BoxDecoration(
                    color: theme.colorScheme.surface,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: theme.colorScheme.outlineVariant),
                    boxShadow: [
                      BoxShadow(
                        color: theme.colorScheme.shadow.withValues(alpha: 0.10),
                        blurRadius: 16,
                        offset: const Offset(0, 8),
                      ),
                    ],
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        _formatDayLabel(item.date),
                        style: theme.textTheme.labelMedium?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        formatAmount(item.total),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: theme.textTheme.titleSmall?.copyWith(
                          color: theme.colorScheme.primary,
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        '${item.count} ventas',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ],
        );
      },
    );
  }
}

class _ChartLabels extends StatelessWidget {
  const _ChartLabels({required this.data, this.selectedIndex});

  final List<SalesByDay> data;
  final int? selectedIndex;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final visible = <int>{};
    if (data.length <= 6) {
      for (var index = 0; index < data.length; index++) {
        visible.add(index);
      }
    } else {
      visible.add(0);
      visible.add(data.length - 1);
      for (var step = 1; step <= 4; step++) {
        visible.add(((data.length - 1) * step / 5).round());
      }
    }

    return Row(
      children: data.asMap().entries.map((entry) {
        final index = entry.key;
        final item = entry.value;
        return Expanded(
          child: Text(
            visible.contains(index) ? _formatDayLabel(item.date) : '',
            textAlign: TextAlign.center,
            style: theme.textTheme.bodySmall?.copyWith(
              color: selectedIndex == index
                  ? theme.colorScheme.primary
                  : theme.colorScheme.onSurfaceVariant,
              fontWeight: FontWeight.w600,
            ),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
        );
      }).toList(),
    );
  }
}

class _SalesTrendPainter extends CustomPainter {
  _SalesTrendPainter({
    required this.data,
    required this.lineColor,
    required this.fillColor,
    required this.gridColor,
    this.highlightedIndex,
  });

  final List<SalesByDay> data;
  final Color lineColor;
  final Color fillColor;
  final Color gridColor;
  final int? highlightedIndex;

  @override
  void paint(Canvas canvas, Size size) {
    const left = 10.0;
    const top = 12.0;
    final width = size.width - (left * 2);
    final height = size.height - (top * 2);

    final gridPaint = Paint()
      ..color = gridColor.withValues(alpha: 0.45)
      ..strokeWidth = 1;

    for (var step = 0; step < 4; step++) {
      final y = top + (height / 3) * step;
      canvas.drawLine(Offset(left, y), Offset(size.width - left, y), gridPaint);
    }

    if (data.isEmpty) return;

    final maxValue = math.max(
      1.0,
      data.map((item) => item.total).fold<double>(0, (a, b) => math.max(a, b)),
    );

    if (data.length == 1) {
      final y = top + height - (data.first.total / maxValue) * height;
      final start = Offset(left, y);
      final end = Offset(size.width - left, y);
      final center = Offset(size.width / 2, y);

      final singleArea = Path()
        ..moveTo(start.dx, start.dy)
        ..lineTo(end.dx, end.dy)
        ..lineTo(end.dx, size.height - top)
        ..lineTo(start.dx, size.height - top)
        ..close();

      final fillPaint = Paint()
        ..shader = LinearGradient(
          colors: [fillColor, fillColor.withValues(alpha: 0.02)],
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
        ).createShader(Rect.fromLTWH(0, 0, size.width, size.height));

      canvas.drawPath(singleArea, fillPaint);

      final linePaint = Paint()
        ..color = lineColor
        ..strokeWidth = 3
        ..style = PaintingStyle.stroke
        ..strokeCap = StrokeCap.round;
      canvas.drawLine(start, end, linePaint);

      final glowPaint = Paint()
        ..color = lineColor.withValues(alpha: 0.14)
        ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 18);
      canvas.drawCircle(center, 11, glowPaint);

      final dotPaint = Paint()..color = lineColor;
      final dotStroke = Paint()
        ..color = Colors.white
        ..style = PaintingStyle.stroke
        ..strokeWidth = 3;
      canvas.drawCircle(center, 6, dotPaint);
      canvas.drawCircle(center, 6, dotStroke);

      if (highlightedIndex == 0) {
        final highlight = Paint()
          ..color = lineColor.withValues(alpha: 0.12)
          ..style = PaintingStyle.fill;
        canvas.drawCircle(center, 14, highlight);
      }
      return;
    }

    final dx = data.length == 1 ? 0.0 : width / (data.length - 1);
    final points = <Offset>[];

    for (var index = 0; index < data.length; index++) {
      final x = left + dx * index;
      final y = top + height - (data[index].total / maxValue) * height;
      points.add(Offset(x, y));
    }

    final linePath = Path()..moveTo(points.first.dx, points.first.dy);
    for (var index = 1; index < points.length; index++) {
      final previous = points[index - 1];
      final current = points[index];
      final controlX = (previous.dx + current.dx) / 2;
      linePath.cubicTo(
        controlX,
        previous.dy,
        controlX,
        current.dy,
        current.dx,
        current.dy,
      );
    }

    final areaPath = Path.from(linePath)
      ..lineTo(points.last.dx, size.height - top)
      ..lineTo(points.first.dx, size.height - top)
      ..close();

    final fillPaint = Paint()
      ..shader = LinearGradient(
        colors: [fillColor, fillColor.withValues(alpha: 0.02)],
        begin: Alignment.topCenter,
        end: Alignment.bottomCenter,
      ).createShader(Rect.fromLTWH(0, 0, size.width, size.height));

    canvas.drawPath(areaPath, fillPaint);

    final linePaint = Paint()
      ..color = lineColor
      ..strokeWidth = 3
      ..style = PaintingStyle.stroke
      ..strokeCap = StrokeCap.round;
    canvas.drawPath(linePath, linePaint);

    final dotPaint = Paint()..color = lineColor;
    final dotStroke = Paint()
      ..color = Colors.white
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2;
    final highlightPaint = Paint()
      ..color = lineColor.withValues(alpha: 0.12)
      ..style = PaintingStyle.fill;
    for (var index = 0; index < points.length; index++) {
      final point = points[index];
      final isHighlighted = highlightedIndex == index;
      if (isHighlighted) {
        canvas.drawCircle(point, 13, highlightPaint);
      }
      canvas.drawCircle(point, isHighlighted ? 5.5 : 4.5, dotPaint);
      canvas.drawCircle(point, isHighlighted ? 5.5 : 4.5, dotStroke);
    }
  }

  @override
  bool shouldRepaint(covariant _SalesTrendPainter oldDelegate) {
    return oldDelegate.data != data ||
        oldDelegate.lineColor != lineColor ||
        oldDelegate.fillColor != fillColor ||
        oldDelegate.gridColor != gridColor ||
        oldDelegate.highlightedIndex != highlightedIndex;
  }
}

String _formatDayLabel(String value) {
  final parsed = DateTime.tryParse(value);
  if (parsed == null) return value;
  return DateFormat('dd/MM').format(parsed);
}

bool _isSameDate(DateTime left, DateTime right) {
  return left.year == right.year &&
      left.month == right.month &&
      left.day == right.day;
}

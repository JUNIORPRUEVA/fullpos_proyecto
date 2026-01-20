import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';
import '../../auth/data/auth_repository.dart';
import '../../../core/network/unauthorized_exception.dart';
import '../data/report_models.dart';
import '../data/reports_repository.dart';

class DashboardPage extends ConsumerStatefulWidget {
  const DashboardPage({super.key});

  @override
  ConsumerState<DashboardPage> createState() => _DashboardPageState();
}

class _DashboardPageState extends ConsumerState<DashboardPage> {
  SalesSummary? _summary;
  List<SalesByDay> _byDay = const [];
  ExpensesSummary? _expensesSummary;
  List<ExpenseRow> _expenses = const [];
  bool _loading = true;
  bool _savingExpense = false;
  String _error = '';
  late DateTime _from;
  late DateTime _to;

  @override
  void initState() {
    super.initState();
    final now = DateTime.now();
    _to = now;
    _from = DateTime(now.year, now.month, 1);
    _load();
    ref.read(authRepositoryProvider.notifier).me();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = '';
    });
    final repo = ref.read(reportsRepositoryProvider);
    final formatter = DateFormat('yyyy-MM-dd');
    try {
      final fromStr = formatter.format(_from);
      final toStr = formatter.format(_to);

      final summaryFuture = repo.salesSummary(fromStr, toStr);
      final byDayFuture = repo.salesByDay(fromStr, toStr);
      final expensesSummaryFuture = repo.expensesSummary(fromStr, toStr);
      final expensesFuture = repo.expensesList(fromStr, toStr, pageSize: 50);

      final summary = await summaryFuture;
      final byDay = await byDayFuture;
      final expensesSummary = await expensesSummaryFuture;
      final expenses = await expensesFuture;

      setState(() {
        _summary = summary;
        _byDay = byDay;
        _expensesSummary = expensesSummary;
        _expenses = expenses.data;
        _loading = false;
      });
    } catch (e) {
      if (e is UnauthorizedException) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Sesión vencida. Entra de nuevo.')),
          );
        }
        await ref.read(authRepositoryProvider.notifier).logout();
        if (mounted) context.go('/login');
        return;
      }
      setState(() {
        _error = 'No se pudieron cargar los datos';
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final number = NumberFormat.currency(locale: 'es_DO', symbol: '\$');
    final expensesTotal = _expensesSummary?.total ?? 0;
    final profit = (_summary?.total ?? 0) - expensesTotal;

    return LayoutBuilder(
      builder: (context, constraints) {
        final dateFmt = DateFormat('yyyy-MM-dd');
        final chartHeight = (constraints.maxHeight * 0.35)
            .clamp(120.0, 220.0)
            .toDouble();
        final listHeight = math.max(200.0, constraints.maxHeight * 0.4);
        final expensesListHeight = math.max(
          180.0,
          constraints.maxHeight * 0.25,
        );

        return Padding(
          padding: const EdgeInsets.all(16),
          child: _loading
              ? const Center(child: CircularProgressIndicator())
              : _error.isNotEmpty
              ? Center(child: Text(_error))
              : SingleChildScrollView(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _ReportFilters(
                        from: _from,
                        to: _to,
                        onChange: (from, to) {
                          setState(() {
                            _from = from;
                            _to = to;
                          });
                          _load();
                        },
                      ),
                      const SizedBox(height: 12),
                      Wrap(
                        spacing: 12,
                        runSpacing: 12,
                        children: [
                          _MetricCard(
                            title: 'Ingresos',
                            value: _summary != null
                                ? number.format(_summary!.total)
                                : '--',
                            icon: Icons.payments_outlined,
                            color: Colors.lightBlueAccent,
                          ),
                          _MetricCard(
                            title: 'Ganancia',
                            value: number.format(profit),
                            icon: Icons.trending_up_outlined,
                            color: Colors.tealAccent,
                          ),
                          _MetricCard(
                            title: 'Gastos',
                            value: number.format(expensesTotal),
                            icon: Icons.outbond_outlined,
                            color: Colors.redAccent,
                            helper: _expensesSummary != null
                                ? '${_expensesSummary!.count} movimientos'
                                : 'Integra gastos para mostrar detalle',
                          ),
                          _MetricCard(
                            title: 'Cantidad de ventas',
                            value: _summary?.count.toString() ?? '--',
                            icon: Icons.receipt_long_outlined,
                            color: Colors.greenAccent,
                          ),
                          _MetricCard(
                            title: 'Promedio',
                            value: _summary != null
                                ? number.format(_summary!.average)
                                : '--',
                            icon: Icons.leaderboard_outlined,
                            color: Colors.orangeAccent,
                          ),
                        ],
                      ),
                      const SizedBox(height: 16),
                      Wrap(
                        alignment: WrapAlignment.spaceBetween,
                        crossAxisAlignment: WrapCrossAlignment.center,
                        runSpacing: 8,
                        children: [
                          Text(
                            'Ventas por dia',
                            style: theme.textTheme.titleMedium,
                          ),
                          TextButton.icon(
                            onPressed: () => context.go('/cash/closings'),
                            icon: const Icon(Icons.history),
                            label: const Text('Historial de movimientos'),
                          ),
                        ],
                      ),
                      const SizedBox(height: 8),
                      Card(
                        child: Padding(
                          padding: const EdgeInsets.all(12),
                          child: _byDay.isEmpty
                              ? const Center(
                                  child: Text('Sin ventas en el rango'),
                                )
                              : Column(
                                  crossAxisAlignment:
                                      CrossAxisAlignment.stretch,
                                  children: [
                                    SizedBox(
                                      height: chartHeight,
                                      child: _BarChart(data: _byDay),
                                    ),
                                    const SizedBox(height: 12),
                                    SizedBox(
                                      height: listHeight,
                                      child: ListView.builder(
                                        itemCount: _byDay.length,
                                        itemBuilder: (context, index) {
                                          final row = _byDay[index];
                                          return ListTile(
                                            title: Text(row.date),
                                            subtitle: Text(
                                              '${row.count} ventas',
                                            ),
                                            trailing: Text(
                                              number.format(row.total),
                                            ),
                                          );
                                        },
                                      ),
                                    ),
                                  ],
                                ),
                        ),
                      ),
                      const SizedBox(height: 16),
                      Card(
                        child: Padding(
                          padding: const EdgeInsets.all(12),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.stretch,
                            children: [
                              Wrap(
                                alignment: WrapAlignment.spaceBetween,
                                crossAxisAlignment: WrapCrossAlignment.center,
                                runSpacing: 8,
                                children: [
                                  Text(
                                    'Gastos',
                                    style: theme.textTheme.titleMedium,
                                  ),
                                  ElevatedButton.icon(
                                    onPressed: _savingExpense
                                        ? null
                                        : _openExpenseDialog,
                                    icon: const Icon(Icons.add),
                                    label: const Text('Registrar gasto'),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 8),
                              SizedBox(
                                height: expensesListHeight,
                                child: _expenses.isEmpty
                                    ? const Center(
                                        child: Text('Sin gastos en el rango'),
                                      )
                                    : ListView.separated(
                                        itemCount: _expenses.length,
                                        separatorBuilder: (context, index) =>
                                            const Divider(height: 1),
                                        itemBuilder: (context, index) {
                                          final exp = _expenses[index];
                                          final details = [
                                            dateFmt.format(exp.incurredAt),
                                            if ((exp.note ?? '').isNotEmpty)
                                              exp.note!,
                                            if (exp.createdBy != null)
                                              'Por ${exp.createdBy!.displayName ?? exp.createdBy!.username}',
                                          ];
                                          return ListTile(
                                            dense: true,
                                            title: Text(exp.category),
                                            subtitle: Text(details.join(' · ')),
                                            trailing: Text(
                                              number.format(exp.amount),
                                              style: theme.textTheme.bodyMedium
                                                  ?.copyWith(
                                                    fontWeight: FontWeight.w700,
                                                  ),
                                            ),
                                          );
                                        },
                                      ),
                              ),
                            ],
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

  Future<void> _openExpenseDialog() async {
    final amountCtrl = TextEditingController();
    final categoryCtrl = TextEditingController();
    final noteCtrl = TextEditingController();
    DateTime incurredAt = DateTime.now();

    final result = await showModalBottomSheet<bool>(
      context: context,
      isScrollControlled: true,
      builder: (ctx) {
        return Padding(
          padding: EdgeInsets.only(
            bottom: MediaQuery.of(ctx).viewInsets.bottom + 16,
            left: 16,
            right: 16,
            top: 16,
          ),
          child: StatefulBuilder(
            builder: (context, setModalState) {
              return Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Registrar gasto',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: amountCtrl,
                    keyboardType: const TextInputType.numberWithOptions(
                      decimal: true,
                    ),
                    decoration: const InputDecoration(labelText: 'Monto'),
                  ),
                  const SizedBox(height: 8),
                  TextField(
                    controller: categoryCtrl,
                    decoration: const InputDecoration(labelText: 'Categoria'),
                  ),
                  const SizedBox(height: 8),
                  TextField(
                    controller: noteCtrl,
                    decoration: const InputDecoration(
                      labelText: 'Nota (opcional)',
                    ),
                  ),
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      Expanded(
                        child: Text(
                          'Fecha: ${DateFormat('yyyy-MM-dd').format(incurredAt)}',
                        ),
                      ),
                      TextButton.icon(
                        onPressed: () async {
                          final picked = await showDatePicker(
                            context: context,
                            initialDate: incurredAt,
                            firstDate: DateTime.now().subtract(
                              const Duration(days: 365),
                            ),
                            lastDate: DateTime.now(),
                          );
                          if (picked != null) {
                            setModalState(() {
                              incurredAt = picked;
                            });
                          }
                        },
                        icon: const Icon(Icons.calendar_today),
                        label: const Text('Cambiar'),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  SizedBox(
                    width: double.infinity,
                    child: ElevatedButton.icon(
                      onPressed: _savingExpense
                          ? null
                          : () async {
                              final amount = double.tryParse(
                                amountCtrl.text.replaceAll(',', '.'),
                              );
                              final category = categoryCtrl.text.trim();
                              if (amount == null || amount <= 0) {
                                ScaffoldMessenger.of(ctx).showSnackBar(
                                  const SnackBar(
                                    content: Text('Ingresa un monto valido'),
                                  ),
                                );
                                return;
                              }
                              if (category.isEmpty) {
                                ScaffoldMessenger.of(ctx).showSnackBar(
                                  const SnackBar(
                                    content: Text('La categoria es requerida'),
                                  ),
                                );
                                return;
                              }
                              if (!mounted) {
                                return;
                              }
                              setState(() => _savingExpense = true);
                              try {
                                await ref
                                    .read(reportsRepositoryProvider)
                                    .createExpense(
                                      amount: amount,
                                      category: category,
                                      note: noteCtrl.text.trim().isEmpty
                                          ? null
                                          : noteCtrl.text.trim(),
                                      incurredAt: incurredAt,
                                    );
                                if (!mounted || !ctx.mounted) {
                                  return;
                                }
                                Navigator.of(ctx).pop(true);
                              } catch (_) {
                                if (ctx.mounted) {
                                  ScaffoldMessenger.of(ctx).showSnackBar(
                                    const SnackBar(
                                      content: Text(
                                        'No se pudo registrar el gasto. Intentalo de nuevo.',
                                      ),
                                    ),
                                  );
                                }
                              } finally {
                                if (mounted) {
                                  setState(() => _savingExpense = false);
                                }
                              }
                            },
                      icon: _savingExpense
                          ? const SizedBox(
                              height: 16,
                              width: 16,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            )
                          : const Icon(Icons.save),
                      label: const Text('Guardar'),
                    ),
                  ),
                ],
              );
            },
          ),
        );
      },
    );

    amountCtrl.dispose();
    categoryCtrl.dispose();
    noteCtrl.dispose();

    if (result == true && mounted) {
      _load();
    }
  }
}

class _ReportFilters extends StatelessWidget {
  const _ReportFilters({
    required this.from,
    required this.to,
    required this.onChange,
  });

  final DateTime from;
  final DateTime to;
  final void Function(DateTime, DateTime) onChange;

  @override
  Widget build(BuildContext context) {
    final fmt = DateFormat('yyyy-MM-dd');
    return Row(
      children: [
        Expanded(
          child: OutlinedButton.icon(
            icon: const Icon(Icons.calendar_month),
            label: Text('Rango: ${fmt.format(from)} · ${fmt.format(to)}'),
            onPressed: () async {
              final picked = await showDateRangePicker(
                context: context,
                firstDate: DateTime.now().subtract(const Duration(days: 365)),
                lastDate: DateTime.now().add(const Duration(days: 1)),
                initialDateRange: DateTimeRange(start: from, end: to),
              );
              if (picked != null) {
                onChange(picked.start, picked.end);
              }
            },
          ),
        ),
      ],
    );
  }
}

class _MetricCard extends StatelessWidget {
  const _MetricCard({
    required this.title,
    required this.value,
    required this.icon,
    required this.color,
    this.helper,
  });

  final String title;
  final String value;
  final IconData icon;
  final Color color;
  final String? helper;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: 220,
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(icon, color: color, size: 26),
              const SizedBox(height: 12),
              Text(title, style: Theme.of(context).textTheme.bodyMedium),
              const SizedBox(height: 4),
              Text(
                value,
                style: Theme.of(
                  context,
                ).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w800),
              ),
              if (helper != null)
                Padding(
                  padding: const EdgeInsets.only(top: 4),
                  child: Text(
                    helper!,
                    style: Theme.of(
                      context,
                    ).textTheme.bodySmall?.copyWith(color: Colors.grey),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }
}

class _BarChart extends StatelessWidget {
  const _BarChart({required this.data});

  final List<SalesByDay> data;

  @override
  Widget build(BuildContext context) {
    final maxValue = data
        .map((e) => e.total)
        .fold<double>(0, (prev, el) => el > prev ? el : prev);
    return LayoutBuilder(
      builder: (context, constraints) {
        const textSpace = 26.0;
        final double barWidth =
            ((constraints.maxWidth) / data.length.clamp(3, 12))
                .clamp(12.0, 56.0)
                .toDouble();
        final double maxBarHeight = (constraints.maxHeight - textSpace)
            .clamp(0.0, constraints.maxHeight)
            .toDouble();
        return Row(
          crossAxisAlignment: CrossAxisAlignment.end,
          children: data.map((item) {
            final double height = maxValue > 0
                ? (item.total / maxValue) * maxBarHeight
                : 0.0;
            return Padding(
              padding: const EdgeInsets.symmetric(horizontal: 4),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  Container(
                    width: barWidth,
                    height: height,
                    decoration: BoxDecoration(
                      color: Theme.of(context).colorScheme.primary,
                      borderRadius: BorderRadius.circular(6),
                    ),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    item.date,
                    style: Theme.of(context).textTheme.bodySmall,
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            );
          }).toList(),
        );
      },
    );
  }
}

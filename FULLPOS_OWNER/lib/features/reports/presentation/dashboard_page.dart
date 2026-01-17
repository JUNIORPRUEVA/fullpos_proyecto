import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';
import '../../auth/data/auth_repository.dart';
import '../data/reports_repository.dart';
import '../data/report_models.dart';

class DashboardPage extends ConsumerStatefulWidget {
  const DashboardPage({super.key});

  @override
  ConsumerState<DashboardPage> createState() => _DashboardPageState();
}

class _DashboardPageState extends ConsumerState<DashboardPage> {
  SalesSummary? _summary;
  List<SalesByDay> _byDay = const [];
  bool _loading = true;
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
    // refresh profile
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
      final summary = await repo.salesSummary(formatter.format(_from), formatter.format(_to));
      final byDay = await repo.salesByDay(formatter.format(_from), formatter.format(_to));
      setState(() {
        _summary = summary;
        _byDay = byDay;
        _loading = false;
      });
    } catch (e) {
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

    return Padding(
      padding: const EdgeInsets.all(16),
      child: _loading
          ? const Center(child: CircularProgressIndicator())
          : _error.isNotEmpty
              ? Center(child: Text(_error))
              : Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Wrap(
                      spacing: 12,
                      runSpacing: 12,
                      children: [
                        _MetricCard(
                          title: 'Total vendido',
                          value: _summary != null ? number.format(_summary!.total) : '--',
                          icon: Icons.payments_outlined,
                          color: Colors.lightBlueAccent,
                        ),
                        _MetricCard(
                          title: 'Cantidad de ventas',
                          value: _summary?.count.toString() ?? '--',
                          icon: Icons.receipt_long_outlined,
                          color: Colors.greenAccent,
                        ),
                        _MetricCard(
                          title: 'Promedio',
                          value: _summary != null ? number.format(_summary!.average) : '--',
                          icon: Icons.leaderboard_outlined,
                          color: Colors.orangeAccent,
                        ),
                      ],
                    ),
                    const SizedBox(height: 16),
                    Text('Ventas por día', style: theme.textTheme.titleMedium),
                    const SizedBox(height: 8),
                    Expanded(
                      child: Card(
                        child: Padding(
                          padding: const EdgeInsets.all(12),
                          child: _byDay.isEmpty
                              ? const Center(child: Text('Sin ventas en el rango'))
                              : ListView.builder(
                                  itemCount: _byDay.length,
                                  itemBuilder: (context, index) {
                                    final row = _byDay[index];
                                    return ListTile(
                                      title: Text(row.date),
                                      subtitle: Text('${row.count} ventas'),
                                      trailing: Text(number.format(row.total)),
                                    );
                                  },
                                ),
                        ),
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
    required this.icon,
    required this.color,
  });

  final String title;
  final String value;
  final IconData icon;
  final Color color;

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
                style: Theme.of(context).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w800),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';
import '../../auth/data/auth_repository.dart';
import '../../../core/network/unauthorized_exception.dart';
import '../../reports/data/report_models.dart';
import '../../reports/data/reports_repository.dart';
import 'cash_closing_detail_page.dart';

class CashClosingsPage extends ConsumerStatefulWidget {
  const CashClosingsPage({super.key});

  @override
  ConsumerState<CashClosingsPage> createState() => _CashClosingsPageState();
}

class _CashClosingsPageState extends ConsumerState<CashClosingsPage> {
  List<CashClosing> _rows = const [];
  bool _loading = true;
  String? _error;
  late DateTime _from;
  late DateTime _to;

  @override
  void initState() {
    super.initState();
    final now = DateTime.now();
    _to = now;
    _from = now.subtract(const Duration(days: 60));
    _load();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    final repo = ref.read(reportsRepositoryProvider);
    final fmt = DateFormat('yyyy-MM-dd');
    try {
      final data = await repo.cashClosings(fmt.format(_from), fmt.format(_to));
      setState(() {
        _rows = data;
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
        _error = 'No se pudieron cargar los cierres';
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final number = NumberFormat.currency(locale: 'es_DO', symbol: '\$');
    final fmt = DateFormat('yyyy-MM-dd HH:mm');
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _Filters(
            from: _from,
            to: _to,
            onDateChanged: (from, to) {
              setState(() {
                _from = from;
                _to = to;
              });
              _load();
            },
            onRefresh: _load,
          ),
          const SizedBox(height: 12),
          Expanded(
            child: _loading
                ? const Center(child: CircularProgressIndicator())
                : _error != null
                ? Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Text(
                        _error!,
                        style: Theme.of(context).textTheme.bodyMedium,
                      ),
                      const SizedBox(height: 8),
                      OutlinedButton.icon(
                        onPressed: _load,
                        icon: const Icon(Icons.refresh),
                        label: const Text('Reintentar'),
                      ),
                    ],
                  )
                : Card(
                    child: _rows.isEmpty
                        ? const Center(
                            child: Padding(
                              padding: EdgeInsets.all(16),
                              child: Text(
                                'Sin cierres en el rango seleccionado',
                              ),
                            ),
                          )
                        : ListView.separated(
                            itemCount: _rows.length,
                            separatorBuilder: (context, separatorIndex) =>
                                const Divider(height: 1),
                            itemBuilder: (context, index) {
                              final row = _rows[index];
                              final closedLabel = row.closedAt != null
                                  ? fmt.format(row.closedAt!)
                                  : 'Abierto';
                              final dateLabel = row.closedAt != null
                                  ? DateFormat(
                                      'yyyy-MM-dd',
                                    ).format(row.closedAt!)
                                  : 'N/D';
                              return ListTile(
                                leading: const Icon(Icons.lock_clock_outlined),
                                title: Text('${row.userName} - $closedLabel'),
                                subtitle: Text(
                                  'Ventas: ${row.salesCount} - Cajero: ${row.userName} - Fecha: $dateLabel',
                                ),
                                trailing: Column(
                                  mainAxisAlignment: MainAxisAlignment.center,
                                  crossAxisAlignment: CrossAxisAlignment.end,
                                  children: [
                                    Text(number.format(row.totalSales)),
                                    if (row.difference != null)
                                      Text(
                                        'Dif: ${number.format(row.difference)}',
                                        style: TextStyle(
                                          color: (row.difference ?? 0) >= 0
                                              ? Colors.greenAccent
                                              : Colors.redAccent,
                                          fontSize: 12,
                                        ),
                                      ),
                                  ],
                                ),
                                onTap: () => Navigator.of(context).push(
                                  MaterialPageRoute(
                                    builder: (_) =>
                                        CashClosingDetailPage(id: row.id),
                                  ),
                                ),
                              );
                            },
                          ),
                  ),
          ),
        ],
      ),
    );
  }
}

class _Filters extends StatelessWidget {
  const _Filters({
    required this.from,
    required this.to,
    required this.onDateChanged,
    required this.onRefresh,
  });
  final DateTime from;
  final DateTime to;
  final void Function(DateTime from, DateTime to) onDateChanged;
  final VoidCallback onRefresh;

  @override
  Widget build(BuildContext context) {
    final fmt = DateFormat('yyyy-MM-dd');
    return Row(
      children: [
        Expanded(
          child: OutlinedButton.icon(
            icon: const Icon(Icons.calendar_today),
            label: Text('Desde ${fmt.format(from)} - Hasta ${fmt.format(to)}'),
            onPressed: () async {
              final picked = await showDateRangePicker(
                context: context,
                firstDate: DateTime.now().subtract(const Duration(days: 365)),
                lastDate: DateTime.now().add(const Duration(days: 1)),
                initialDateRange: DateTimeRange(start: from, end: to),
              );
              if (picked != null) onDateChanged(picked.start, picked.end);
            },
          ),
        ),
        const SizedBox(width: 12),
        ElevatedButton.icon(
          onPressed: onRefresh,
          icon: const Icon(Icons.filter_list),
          label: const Text('Aplicar'),
          style: ElevatedButton.styleFrom(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
          ),
        ),
      ],
    );
  }
}

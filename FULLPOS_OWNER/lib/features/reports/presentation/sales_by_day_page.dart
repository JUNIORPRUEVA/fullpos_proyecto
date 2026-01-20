import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';
import '../../auth/data/auth_repository.dart';
import '../../../core/network/unauthorized_exception.dart';
import '../data/report_models.dart';
import '../data/reports_repository.dart';

class SalesByDayPage extends ConsumerStatefulWidget {
  const SalesByDayPage({super.key});

  @override
  ConsumerState<SalesByDayPage> createState() => _SalesByDayPageState();
}

class _SalesByDayPageState extends ConsumerState<SalesByDayPage> {
  List<SalesByDay> _rows = const [];
  bool _loading = true;
  String? _error;
  late DateTime _from;
  late DateTime _to;

  @override
  void initState() {
    super.initState();
    final now = DateTime.now();
    _to = now;
    _from = now.subtract(const Duration(days: 30));
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
      final data = await repo.salesByDay(fmt.format(_from), fmt.format(_to));
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
        _error = 'Error cargando ventas por dia';
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final number = NumberFormat.currency(locale: 'es_DO', symbol: '\$');
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        children: [
          _RangeFilter(
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
          Expanded(
            child: _loading
                ? const Center(child: CircularProgressIndicator())
                : _error != null
                ? Center(child: Text(_error!))
                : Card(
                    child: ListView.separated(
                      itemCount: _rows.length,
                      separatorBuilder: (context, separatorIndex) =>
                          const Divider(height: 1),
                      itemBuilder: (context, index) {
                        final row = _rows[index];
                        return ListTile(
                          leading: const Icon(Icons.calendar_today_outlined),
                          title: Text(row.date),
                          subtitle: Text('${row.count} ventas'),
                          trailing: Text(number.format(row.total)),
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

class _RangeFilter extends StatelessWidget {
  const _RangeFilter({
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
            icon: const Icon(Icons.filter_alt_outlined),
            label: Text('Rango: ${fmt.format(from)} • ${fmt.format(to)}'),
            onPressed: () async {
              final picked = await showDateRangePicker(
                context: context,
                firstDate: DateTime.now().subtract(const Duration(days: 365)),
                lastDate: DateTime.now().add(const Duration(days: 1)),
                initialDateRange: DateTimeRange(start: from, end: to),
              );
              if (picked != null) onChange(picked.start, picked.end);
            },
          ),
        ),
      ],
    );
  }
}

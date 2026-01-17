import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';
import '../../reports/data/reports_repository.dart';
import '../../reports/data/report_models.dart';

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
      setState(() {
        _error = 'Error cargando cierres';
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final number = NumberFormat.currency(locale: 'es_DO', symbol: '\$');
    return Padding(
      padding: const EdgeInsets.all(16),
      child: _loading
          ? const Center(child: CircularProgressIndicator())
          : _error != null
              ? Center(child: Text(_error!))
              : Card(
                  child: ListView.separated(
                    itemCount: _rows.length,
                    separatorBuilder: (_, __) => const Divider(height: 1),
                    itemBuilder: (context, index) {
                      final row = _rows[index];
                      return ListTile(
                        leading: const Icon(Icons.lock_clock_outlined),
                        title: Text(
                          '${row.userName} • ${row.closedAt != null ? DateFormat('yyyy-MM-dd HH:mm').format(row.closedAt!) : 'Abierto'}',
                        ),
                        subtitle: Text('Ventas: ${row.salesCount}'),
                        trailing: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          crossAxisAlignment: CrossAxisAlignment.end,
                          children: [
                            Text(number.format(row.totalSales)),
                            if (row.difference != null)
                              Text(
                                'Dif: ${number.format(row.difference)}',
                                style: TextStyle(
                                  color: (row.difference ?? 0) >= 0 ? Colors.greenAccent : Colors.redAccent,
                                  fontSize: 12,
                                ),
                              ),
                          ],
                        ),
                        onTap: () => context.go('/cash/closing/${row.id}'),
                      );
                    },
                  ),
                ),
    );
  }
}

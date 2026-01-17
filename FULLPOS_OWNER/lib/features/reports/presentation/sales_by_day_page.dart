import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';
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
      setState(() {
        _error = 'Error cargando ventas por día';
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
                        leading: const Icon(Icons.calendar_today_outlined),
                        title: Text(row.date),
                        subtitle: Text('${row.count} ventas'),
                        trailing: Text(number.format(row.total)),
                      );
                    },
                  ),
                ),
    );
  }
}

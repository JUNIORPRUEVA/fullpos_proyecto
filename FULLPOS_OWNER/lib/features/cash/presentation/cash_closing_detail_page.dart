import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';
import '../../reports/data/report_models.dart';
import '../../reports/data/reports_repository.dart';

class CashClosingDetailPage extends ConsumerStatefulWidget {
  const CashClosingDetailPage({super.key, required this.id});

  final int id;

  @override
  ConsumerState<CashClosingDetailPage> createState() => _CashClosingDetailPageState();
}

class _CashClosingDetailPageState extends ConsumerState<CashClosingDetailPage> {
  CashClosingDetail? _detail;
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    final repo = ref.read(reportsRepositoryProvider);
    try {
      final detail = await repo.cashClosingDetail(widget.id);
      setState(() {
        _detail = detail;
        _loading = false;
      });
    } catch (e) {
      setState(() {
        _error = 'Error cargando cierre';
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final number = NumberFormat.currency(locale: 'es_DO', symbol: '\$');
    final fmt = DateFormat('yyyy-MM-dd HH:mm');
    return Scaffold(
      appBar: AppBar(title: Text('Cierre #${widget.id}')),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : _error != null
              ? Center(child: Text(_error!))
              : _detail == null
                  ? const Center(child: Text('Sin datos'))
                  : Padding(
                      padding: const EdgeInsets.all(16),
                      child: ListView(
                        children: [
                          Card(
                            child: Padding(
                              padding: const EdgeInsets.all(12),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text('Resumen de Caja', style: Theme.of(context).textTheme.titleMedium),
                                  const SizedBox(height: 8),
                                  Wrap(
                                    spacing: 12,
                                    runSpacing: 12,
                                    children: [
                                      _InfoChip('Abierto', _detail!.session.openedAt != null ? fmt.format(_detail!.session.openedAt!) : 'N/D'),
                                      _InfoChip('Cerrado', _detail!.session.closedAt != null ? fmt.format(_detail!.session.closedAt!) : 'N/D'),
                                      _InfoChip('Inicial', number.format(_detail!.session.initialAmount ?? 0)),
                                      _InfoChip('Cierre', number.format(_detail!.session.closingAmount ?? 0)),
                                      _InfoChip('Esperado', number.format(_detail!.session.expectedCash ?? 0)),
                                      _InfoChip('Diferencia', number.format(_detail!.session.difference ?? 0)),
                                    ],
                                  ),
                                ],
                              ),
                            ),
                          ),
                          const SizedBox(height: 12),
                          Card(
                            child: Padding(
                              padding: const EdgeInsets.all(12),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text('Ventas', style: Theme.of(context).textTheme.titleMedium),
                                  const SizedBox(height: 8),
                                  ..._detail!.sales.map(
                                    (s) => ListTile(
                                      dense: true,
                                      title: Text('Venta #${s.id}'),
                                      subtitle: Text(s.createdAt != null ? fmt.format(s.createdAt!) : 'N/D'),
                                      trailing: Text(number.format(s.total)),
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                          const SizedBox(height: 12),
                          Card(
                            child: Padding(
                              padding: const EdgeInsets.all(12),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text('Movimientos de Caja', style: Theme.of(context).textTheme.titleMedium),
                                  const SizedBox(height: 8),
                                  ..._detail!.movements.map(
                                    (m) => ListTile(
                                      dense: true,
                                      leading: Icon(
                                        m.type == 'retiro' ? Icons.remove_circle_outline : Icons.add_circle_outline,
                                        color: m.type == 'retiro' ? Colors.redAccent : Colors.greenAccent,
                                      ),
                                      title: Text(m.note ?? m.type),
                                      subtitle: Text(m.createdAt != null ? fmt.format(m.createdAt!) : 'N/D'),
                                      trailing: Text(number.format(m.amount)),
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
  }
}

class _InfoChip extends StatelessWidget {
  const _InfoChip(this.label, this.value);
  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Chip(
      label: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: const TextStyle(fontSize: 11, color: Colors.white70)),
          Text(value, style: const TextStyle(fontWeight: FontWeight.w700)),
        ],
      ),
    );
  }
}

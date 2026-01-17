import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';
import '../data/report_models.dart';
import '../data/reports_repository.dart';

class SalesListPage extends ConsumerStatefulWidget {
  const SalesListPage({super.key});

  @override
  ConsumerState<SalesListPage> createState() => _SalesListPageState();
}

class _SalesListPageState extends ConsumerState<SalesListPage> {
  PaginatedSales? _page;
  bool _loading = true;
  String? _error;
  int _currentPage = 1;
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

  Future<void> _load({int page = 1}) async {
    setState(() {
      _loading = true;
      _error = null;
    });
    final repo = ref.read(reportsRepositoryProvider);
    final fmt = DateFormat('yyyy-MM-dd');
    try {
      final data = await repo.salesList(fmt.format(_from), fmt.format(_to), page: page);
      setState(() {
        _page = data;
        _currentPage = page;
        _loading = false;
      });
    } catch (e) {
      setState(() {
        _error = 'Error cargando ventas';
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
              : Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Text('Ventas (rango 30 días)', style: Theme.of(context).textTheme.titleMedium),
                        Row(
                          children: [
                            IconButton(
                              icon: const Icon(Icons.chevron_left),
                              onPressed: _currentPage > 1 ? () => _load(page: _currentPage - 1) : null,
                            ),
                            Text('Página $_currentPage'),
                            IconButton(
                              icon: const Icon(Icons.chevron_right),
                              onPressed: ((_page?.data.length ?? 0) >= (_page?.pageSize ?? 20))
                                  ? () => _load(page: _currentPage + 1)
                                  : null,
                            ),
                          ],
                        )
                      ],
                    ),
                    const SizedBox(height: 8),
                    Expanded(
                      child: Card(
                        child: ListView.separated(
                          itemCount: _page?.data.length ?? 0,
                          separatorBuilder: (_, __) => const Divider(height: 1),
                          itemBuilder: (context, index) {
                            final sale = _page!.data[index];
                            return ListTile(
                              title: Text('${sale.localCode} - ${sale.paymentMethod ?? 'N/D'}'),
                              subtitle: Text(
                                sale.createdAt != null
                                    ? DateFormat('yyyy-MM-dd HH:mm').format(sale.createdAt!)
                                    : 'Fecha N/D',
                              ),
                              trailing: Text(number.format(sale.total)),
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

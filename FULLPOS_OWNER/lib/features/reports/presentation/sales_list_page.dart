import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';
import '../../auth/data/auth_repository.dart';
import '../../../core/network/unauthorized_exception.dart';
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
      final data = await repo.salesList(
        fmt.format(_from),
        fmt.format(_to),
        page: page,
      );
      setState(() {
        _page = data;
        _currentPage = page;
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
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _SalesFilters(
            from: _from,
            to: _to,
            onChange: (from, to) {
              setState(() {
                _from = from;
                _to = to;
              });
              _load(page: 1);
            },
          ),
          const SizedBox(height: 12),
          Expanded(
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
                          Text(
                            'Ventas',
                            style: Theme.of(context).textTheme.titleMedium,
                          ),
                          Row(
                            children: [
                              IconButton(
                                icon: const Icon(Icons.chevron_left),
                                onPressed: _currentPage > 1
                                    ? () => _load(page: _currentPage - 1)
                                    : null,
                              ),
                              Text('Página $_currentPage'),
                              IconButton(
                                icon: const Icon(Icons.chevron_right),
                                onPressed:
                                    ((_page?.data.length ?? 0) >=
                                        (_page?.pageSize ?? 20))
                                    ? () => _load(page: _currentPage + 1)
                                    : null,
                              ),
                            ],
                          ),
                        ],
                      ),
                      const SizedBox(height: 8),
                      Expanded(
                        child: Card(
                          child: ListView.separated(
                            itemCount: _page?.data.length ?? 0,
                            separatorBuilder: (context, separatorIndex) =>
                                const Divider(height: 1),
                            itemBuilder: (context, index) {
                              final sale = _page!.data[index];
                              return ListTile(
                                leading: const Icon(
                                  Icons.receipt_long_outlined,
                                ),
                                title: Text(
                                  '${sale.localCode} • ${sale.paymentMethod ?? 'N/D'}',
                                ),
                                subtitle: Text(
                                  sale.createdAt != null
                                      ? DateFormat(
                                          'yyyy-MM-dd HH:mm',
                                        ).format(sale.createdAt!)
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
          ),
        ],
      ),
    );
  }
}

class _SalesFilters extends StatelessWidget {
  const _SalesFilters({
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
            icon: const Icon(Icons.date_range),
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

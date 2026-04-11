import 'dart:async';
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';

import '../../../core/theme/app_colors.dart';
import '../../products/data/product_models.dart';
import '../../products/data/product_realtime_service.dart';
import '../../products/data/products_repository.dart';

class InventoryPage extends ConsumerStatefulWidget {
  const InventoryPage({super.key});

  @override
  ConsumerState<InventoryPage> createState() => _InventoryPageState();
}

class _InventoryPageState extends ConsumerState<InventoryPage>
    with WidgetsBindingObserver {
  final TextEditingController _searchCtrl = TextEditingController();
  Timer? _debounce;
  StreamSubscription<ProductRealtimeMessage>? _productRealtimeSubscription;
  bool _outOfStockOnly = false;
  bool _reloadRequested = false;

  bool _loading = true;
  String? _error;
  List<Product> _all = const [];

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _productRealtimeSubscription = ref
      .read(productRealtimeServiceProvider)
      .stream
      .listen((_) => _load(showLoading: false));
    _load(showLoading: true);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _debounce?.cancel();
    _productRealtimeSubscription?.cancel();
    _searchCtrl.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _load(showLoading: false);
    }
  }

  Future<void> _load({required bool showLoading}) async {
    if (_reloadRequested && showLoading) {
      _reloadRequested = false;
    }
    if (showLoading && mounted) {
      setState(() {
        _loading = true;
        _error = null;
      });
    }

    if (_loading && !showLoading) {
      _reloadRequested = true;
      return;
    }

    final repo = ref.read(productsRepositoryProvider);

    try {
      const pageSize = 100;
      var page = 1;
      final items = <Product>[];
      while (true) {
        final res = await repo.list(page: page, pageSize: pageSize);
        items.addAll(res.data);
        final loaded = items.length;
        if (loaded >= res.total) break;
        if (res.data.length < pageSize) break;
        page++;
        // Small yield to avoid blocking UI in huge catalogs.
        await Future<void>.delayed(const Duration(milliseconds: 1));
      }

      if (!mounted) return;
      items.sort(
        (a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()),
      );
      setState(() {
        _all = items;
        if (showLoading) _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        if (showLoading) {
          _error = 'No se pudo cargar el inventario.';
          _loading = false;
        }
      });
    } finally {
      if (_reloadRequested && mounted) {
        _reloadRequested = false;
        unawaited(_load(showLoading: false));
      }
    }
  }

  List<Product> get _filtered {
    final q = _searchCtrl.text.trim().toLowerCase();
    var list = _all;
    if (q.isNotEmpty) {
      list = list
          .where(
            (p) =>
                p.name.toLowerCase().contains(q) ||
                p.code.toLowerCase().contains(q),
          )
          .toList();
    }
    if (_outOfStockOnly) {
      list = list.where((p) => p.stock <= 0).toList();
    }
    return list;
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final currency = NumberFormat.currency(locale: 'es_DO', symbol: '\$');
    final filtered = _filtered;

    final totalUnits = filtered.fold<double>(0, (sum, p) => sum + p.stock);
    final totalCost = filtered.fold<double>(
      0,
      (sum, p) => sum + (p.stock * p.cost),
    );
    final potentialSales = filtered.fold<double>(
      0,
      (sum, p) => sum + (p.stock * p.price),
    );
    final potentialProfit = potentialSales - totalCost;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Inventario'),
        actions: [
          IconButton(
            tooltip: 'Actualizar',
            onPressed: () => _load(showLoading: true),
            icon: const Icon(Icons.refresh),
          ),
        ],
      ),
      body: SafeArea(
        child: Column(
          children: [
            _buildToolbar(theme),
            Expanded(
              child: _loading
                  ? const Center(child: CircularProgressIndicator())
                  : _error != null
                  ? Center(child: Text(_error!))
                  : LayoutBuilder(
                      builder: (context, constraints) {
                        final listHeight = math.max(
                          240.0,
                          constraints.maxHeight - 180,
                        );
                        return SingleChildScrollView(
                          padding: const EdgeInsets.all(16),
                          child: ConstrainedBox(
                            constraints: BoxConstraints(
                              minHeight: constraints.maxHeight,
                            ),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Wrap(
                                  spacing: 12,
                                  runSpacing: 12,
                                  children: [
                                    _StatCard(
                                      title: 'Inversión',
                                      value: currency.format(totalCost),
                                      icon: Icons.savings_outlined,
                                      color: AppColors.success,
                                    ),
                                    _StatCard(
                                      title: 'Unidades',
                                      value: totalUnits.toStringAsFixed(0),
                                      icon: Icons.format_list_numbered,
                                      color: theme.colorScheme.primary,
                                    ),
                                    _StatCard(
                                      title: 'Venta potencial',
                                      value: currency.format(potentialSales),
                                      icon: Icons.trending_up,
                                      color: AppColors.warning,
                                    ),
                                    _StatCard(
                                      title: 'Ganancia potencial',
                                      value: currency.format(potentialProfit),
                                      icon: Icons.stacked_line_chart,
                                      color: potentialProfit >= 0
                                          ? AppColors.success
                                          : AppColors.danger,
                                    ),
                                  ],
                                ),
                                const SizedBox(height: 12),
                                SizedBox(
                                  height: listHeight,
                                  child: Card(
                                    clipBehavior: Clip.antiAlias,
                                    child: filtered.isEmpty
                                        ? const Center(
                                            child: Text(
                                              'Sin productos para el filtro actual.',
                                            ),
                                          )
                                        : ListView.separated(
                                            itemCount: filtered.length,
                                            separatorBuilder:
                                                (context, index) =>
                                                    const Divider(height: 1),
                                            itemBuilder: (context, index) {
                                              final item = filtered[index];
                                              final isOut = item.stock <= 0;
                                              return ListTile(
                                                dense: true,
                                                leading: CircleAvatar(
                                                  backgroundColor: isOut
                                                      ? theme.colorScheme.error
                                                    .withValues(alpha: 0.15)
                                                      : theme
                                                            .colorScheme
                                                            .primary
                                                    .withValues(alpha: 0.12),
                                                  child: Text(
                                                    item.code.isNotEmpty
                                                        ? item.code
                                                              .trim()
                                                              .substring(
                                                                0,
                                                                math.min(
                                                                  2,
                                                                  item
                                                                      .code
                                                                      .length,
                                                                ),
                                                              )
                                                              .toUpperCase()
                                                        : '--',
                                                  ),
                                                ),
                                                title: Text(
                                                  item.name,
                                                  maxLines: 1,
                                                  overflow:
                                                      TextOverflow.ellipsis,
                                                ),
                                                subtitle: Text(
                                                  'Código: ${item.code} • Stock: ${item.stock.toStringAsFixed(0)}',
                                                ),
                                                trailing: Column(
                                                  mainAxisAlignment:
                                                      MainAxisAlignment.center,
                                                  crossAxisAlignment:
                                                      CrossAxisAlignment.end,
                                                  children: [
                                                    Text(
                                                      'Costo: ${currency.format(item.cost)}',
                                                      style: theme
                                                          .textTheme
                                                          .bodySmall,
                                                    ),
                                                    Text(
                                                      'Precio: ${currency.format(item.price)}',
                                                      style: theme
                                                          .textTheme
                                                          .bodySmall
                                                          ?.copyWith(
                                                            color: theme
                                                                .colorScheme
                                                                .primary,
                                                            fontWeight:
                                                                FontWeight.w600,
                                                          ),
                                                    ),
                                                  ],
                                                ),
                                              );
                                            },
                                          ),
                                  ),
                                ),
                              ],
                            ),
                          ),
                        );
                      },
                    ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildToolbar(ThemeData theme) {
    return Container(
      padding: const EdgeInsets.fromLTRB(12, 8, 12, 8),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface.withValues(alpha: 0.85),
        boxShadow: [
          BoxShadow(
            color: theme.colorScheme.onSurface.withValues(alpha: 0.10),
            blurRadius: 10,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Row(
        children: [
          Expanded(
            child: TextField(
              controller: _searchCtrl,
              decoration: InputDecoration(
                hintText: 'Buscar por nombre o código',
                prefixIcon: const Icon(Icons.search),
                suffixIcon: _searchCtrl.text.trim().isEmpty
                    ? null
                    : IconButton(
                        tooltip: 'Limpiar',
                        icon: const Icon(Icons.close),
                        onPressed: () {
                          _searchCtrl.clear();
                          setState(() {});
                        },
                      ),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(14),
                ),
                contentPadding: const EdgeInsets.symmetric(
                  horizontal: 12,
                  vertical: 12,
                ),
              ),
              onChanged: (_) {
                _debounce?.cancel();
                _debounce = Timer(const Duration(milliseconds: 120), () {
                  if (mounted) setState(() {});
                });
              },
            ),
          ),
          const SizedBox(width: 10),
          FilterChip(
            label: const Text('Agotados'),
            selected: _outOfStockOnly,
            onSelected: (v) => setState(() => _outOfStockOnly = v),
          ),
        ],
      ),
    );
  }
}

class _StatCard extends StatelessWidget {
  const _StatCard({
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
      width: 200,
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(14),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(icon, color: color),
              const SizedBox(height: 10),
              Text(title, style: Theme.of(context).textTheme.bodyMedium),
              const SizedBox(height: 4),
              Text(
                value,
                style: Theme.of(
                  context,
                ).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.bold),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

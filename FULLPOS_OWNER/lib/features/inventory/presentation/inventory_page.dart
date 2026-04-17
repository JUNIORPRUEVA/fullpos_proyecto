import 'dart:async';
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/providers/sync_request_provider.dart';
import '../../../core/utils/accounting_format.dart';
import '../../../core/theme/app_colors.dart';
import '../../categories/data/categories_repository.dart';
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
  String? _selectedCategory;
  bool _reloadRequested = false;

  bool _loading = true;
  String? _error;
  List<Product> _all = const [];
  List<String> _syncedCategories = const [];

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

  String? _normalizeCategory(String? value) {
    final normalized = value?.trim();
    if (normalized == null || normalized.isEmpty) return null;
    return normalized;
  }

  List<String> get _availableCategories {
    final categories = {
      ..._all
          .map((product) => _normalizeCategory(product.category))
          .whereType<String>(),
      ..._syncedCategories.map(_normalizeCategory).whereType<String>(),
    }.toList()..sort((a, b) => a.toLowerCase().compareTo(b.toLowerCase()));
    return categories;
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
    final categoriesRepo = ref.read(categoriesRepositoryProvider);

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

      final syncedCategories = await categoriesRepo.list();

      if (!mounted) return;
      items.sort(
        (a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()),
      );
      setState(() {
        _all = items;
        _syncedCategories = syncedCategories;
        if (_selectedCategory != null &&
            !_availableCategories.contains(_selectedCategory)) {
          _selectedCategory = null;
        }
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
                p.code.toLowerCase().contains(q) ||
                (_normalizeCategory(p.category)?.toLowerCase().contains(q) ??
                    false),
          )
          .toList();
    }
    if (_selectedCategory != null) {
      list = list
          .where((p) => _normalizeCategory(p.category) == _selectedCategory)
          .toList();
    }
    if (_outOfStockOnly) {
      list = list.where((p) => p.stock <= 0).toList();
    }
    return list;
  }

  Future<void> _showMetricPreview(
    BuildContext context, {
    required _InventoryMetric metric,
  }) async {
    await showDialog<void>(
      context: context,
      barrierColor: Colors.black.withAlpha((0.38 * 255).round()),
      builder: (context) {
        return Dialog(
          insetPadding: const EdgeInsets.symmetric(
            horizontal: 24,
            vertical: 24,
          ),
          backgroundColor: Colors.transparent,
          elevation: 0,
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 520),
            child: _StatCard(
              title: metric.title,
              value: metric.value,
              icon: metric.icon,
              color: metric.color,
              large: true,
            ),
          ),
        );
      },
    );
  }

  Future<void> _showProductDetail(BuildContext context, Product item) async {
    final theme = Theme.of(context);
    final category = _normalizeCategory(item.category);
    final detailRows = <({String label, String value})>[
      (label: 'Nombre', value: item.name),
      (label: 'Codigo', value: item.code.isEmpty ? '--' : item.code),
      (label: 'Stock', value: item.stock.toStringAsFixed(0)),
      (label: 'Costo', value: formatAccountingAmount(item.cost)),
      (label: 'Precio', value: formatAccountingAmount(item.price)),
      if (category != null) (label: 'Categoria', value: category),
      if (item.description != null && item.description!.trim().isNotEmpty)
        (label: 'Descripcion', value: item.description!.trim()),
    ];

    await showDialog<void>(
      context: context,
      barrierColor: Colors.black.withAlpha((0.34 * 255).round()),
      builder: (dialogContext) {
        return Dialog(
          insetPadding: const EdgeInsets.symmetric(
            horizontal: 20,
            vertical: 24,
          ),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(22),
          ),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 420),
            child: Padding(
              padding: const EdgeInsets.fromLTRB(18, 18, 18, 14),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Expanded(
                        child: Text(
                          'Detalle del producto',
                          style: theme.textTheme.titleMedium?.copyWith(
                            fontWeight: FontWeight.w800,
                          ),
                        ),
                      ),
                      IconButton(
                        tooltip: 'Cerrar',
                        onPressed: () => Navigator.of(dialogContext).pop(),
                        icon: const Icon(Icons.close_rounded),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Flexible(
                    child: SingleChildScrollView(
                      child: Column(
                        children: [
                          for (final row in detailRows)
                            _InventoryDetailRow(
                              label: row.label,
                              value: row.value,
                            ),
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    ref.listen<SyncRequest>(syncRequestProvider, (previous, next) {
      if (previous?.revision == next.revision) return;
      if (!next.appliesTo('/inventory')) return;
      unawaited(_load(showLoading: true));
    });

    final theme = Theme.of(context);
    final filtered = _filtered;
    final totalProducts = filtered.length;

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

    final metricItems = [
      _InventoryMetric(
        title: 'Productos',
        value: totalProducts.toString(),
        icon: Icons.inventory_2_outlined,
        color: theme.colorScheme.secondary,
      ),
      _InventoryMetric(
        title: 'Inversión',
        value: formatAccountingAmount(totalCost),
        icon: Icons.savings_outlined,
        color: AppColors.success,
      ),
      _InventoryMetric(
        title: 'Unidades',
        value: totalUnits.toStringAsFixed(0),
        icon: Icons.format_list_numbered,
        color: theme.colorScheme.primary,
      ),
      _InventoryMetric(
        title: 'Venta potencial',
        value: formatAccountingAmount(potentialSales),
        icon: Icons.trending_up,
        color: AppColors.warning,
      ),
      _InventoryMetric(
        title: 'Ganancia potencial',
        value: formatAccountingAmount(potentialProfit),
        icon: Icons.stacked_line_chart,
        color: potentialProfit >= 0 ? AppColors.success : AppColors.danger,
      ),
    ];

    return Scaffold(
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
                          constraints.maxHeight - 260,
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
                                Row(
                                  children: [
                                    Expanded(
                                      child: _StatCard(
                                        title: metricItems[0].title,
                                        value: metricItems[0].value,
                                        icon: metricItems[0].icon,
                                        color: metricItems[0].color,
                                        onTap: () => _showMetricPreview(
                                          context,
                                          metric: metricItems[0],
                                        ),
                                      ),
                                    ),
                                    const SizedBox(width: 12),
                                    Expanded(
                                      child: _StatCard(
                                        title: metricItems[1].title,
                                        value: metricItems[1].value,
                                        icon: metricItems[1].icon,
                                        color: metricItems[1].color,
                                        onTap: () => _showMetricPreview(
                                          context,
                                          metric: metricItems[1],
                                        ),
                                      ),
                                    ),
                                    const SizedBox(width: 12),
                                    Expanded(
                                      child: _StatCard(
                                        title: metricItems[2].title,
                                        value: metricItems[2].value,
                                        icon: metricItems[2].icon,
                                        color: metricItems[2].color,
                                        onTap: () => _showMetricPreview(
                                          context,
                                          metric: metricItems[2],
                                        ),
                                      ),
                                    ),
                                  ],
                                ),
                                const SizedBox(height: 12),
                                Row(
                                  children: [
                                    Expanded(
                                      child: _StatCard(
                                        title: metricItems[3].title,
                                        value: metricItems[3].value,
                                        icon: metricItems[3].icon,
                                        color: metricItems[3].color,
                                        onTap: () => _showMetricPreview(
                                          context,
                                          metric: metricItems[3],
                                        ),
                                      ),
                                    ),
                                    const SizedBox(width: 12),
                                    Expanded(
                                      child: _StatCard(
                                        title: metricItems[4].title,
                                        value: metricItems[4].value,
                                        icon: metricItems[4].icon,
                                        color: metricItems[4].color,
                                        onTap: () => _showMetricPreview(
                                          context,
                                          metric: metricItems[4],
                                        ),
                                      ),
                                    ),
                                  ],
                                ),
                                const SizedBox(height: 16),
                                Text(
                                  'Productos',
                                  style: theme.textTheme.titleMedium?.copyWith(
                                    fontWeight: FontWeight.w800,
                                  ),
                                ),
                                const SizedBox(height: 10),
                                SizedBox(
                                  height: listHeight,
                                  child: Card(
                                    clipBehavior: Clip.antiAlias,
                                    child: Column(
                                      children: [
                                        Container(
                                          padding: const EdgeInsets.fromLTRB(
                                            12,
                                            10,
                                            12,
                                            8,
                                          ),
                                          color: theme
                                              .colorScheme
                                              .surfaceContainerLow,
                                          child: Row(
                                            children: [
                                              Expanded(
                                                flex: 6,
                                                child: Text(
                                                  'Producto',
                                                  style: theme
                                                      .textTheme
                                                      .labelMedium
                                                      ?.copyWith(
                                                        fontWeight:
                                                            FontWeight.w800,
                                                      ),
                                                ),
                                              ),
                                              const SizedBox(width: 10),
                                              SizedBox(
                                                width: 52,
                                                child: Text(
                                                  'Stock',
                                                  textAlign: TextAlign.center,
                                                  style: theme
                                                      .textTheme
                                                      .labelMedium
                                                      ?.copyWith(
                                                        fontWeight:
                                                            FontWeight.w800,
                                                      ),
                                                ),
                                              ),
                                              const SizedBox(width: 10),
                                              SizedBox(
                                                width: 92,
                                                child: Text(
                                                  'Costo',
                                                  textAlign: TextAlign.right,
                                                  style: theme
                                                      .textTheme
                                                      .labelMedium
                                                      ?.copyWith(
                                                        fontWeight:
                                                            FontWeight.w800,
                                                      ),
                                                ),
                                              ),
                                            ],
                                          ),
                                        ),
                                        Expanded(
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
                                                          const Divider(
                                                            height: 1,
                                                          ),
                                                  itemBuilder: (context, index) {
                                                    final item =
                                                        filtered[index];
                                                    final isOut =
                                                        item.stock <= 0;
                                                    return InkWell(
                                                      onTap: () =>
                                                          _showProductDetail(
                                                            context,
                                                            item,
                                                          ),
                                                      child: Padding(
                                                        padding:
                                                            const EdgeInsets.symmetric(
                                                              horizontal: 12,
                                                              vertical: 11,
                                                            ),
                                                        child: Row(
                                                          children: [
                                                            Expanded(
                                                              flex: 6,
                                                              child: Text(
                                                                item.name,
                                                                maxLines: 1,
                                                                overflow:
                                                                    TextOverflow
                                                                        .ellipsis,
                                                                style: theme
                                                                    .textTheme
                                                                    .bodyMedium
                                                                    ?.copyWith(
                                                                      fontWeight:
                                                                          FontWeight
                                                                              .w700,
                                                                    ),
                                                              ),
                                                            ),
                                                            const SizedBox(
                                                              width: 10,
                                                            ),
                                                            SizedBox(
                                                              width: 52,
                                                              child: Text(
                                                                item.stock
                                                                    .toStringAsFixed(
                                                                      0,
                                                                    ),
                                                                textAlign:
                                                                    TextAlign
                                                                        .center,
                                                                style: theme
                                                                    .textTheme
                                                                    .bodySmall
                                                                    ?.copyWith(
                                                                      color:
                                                                          isOut
                                                                          ? theme.colorScheme.error
                                                                          : theme.colorScheme.onSurface,
                                                                      fontWeight:
                                                                          FontWeight
                                                                              .w700,
                                                                    ),
                                                              ),
                                                            ),
                                                            const SizedBox(
                                                              width: 10,
                                                            ),
                                                            SizedBox(
                                                              width: 92,
                                                              child: Text(
                                                                formatAccountingAmount(
                                                                  item.cost,
                                                                ),
                                                                textAlign:
                                                                    TextAlign
                                                                        .right,
                                                                maxLines: 1,
                                                                overflow:
                                                                    TextOverflow
                                                                        .ellipsis,
                                                                style: theme
                                                                    .textTheme
                                                                    .bodySmall
                                                                    ?.copyWith(
                                                                      fontWeight:
                                                                          FontWeight
                                                                              .w700,
                                                                      color: theme
                                                                          .colorScheme
                                                                          .onSurfaceVariant,
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
    const allCategoriesValue = '__all_categories__';

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
          PopupMenuButton<String>(
            tooltip: 'Filtrar por categoría',
            offset: const Offset(0, 48),
            onSelected: (value) {
              setState(() {
                _selectedCategory = value == allCategoriesValue ? null : value;
              });
            },
            itemBuilder: (context) => [
              CheckedPopupMenuItem<String>(
                value: allCategoriesValue,
                checked: _selectedCategory == null,
                child: const Text('Todas las categorías'),
              ),
              ..._availableCategories.map(
                (category) => CheckedPopupMenuItem<String>(
                  value: category,
                  checked: _selectedCategory == category,
                  child: Text(category),
                ),
              ),
            ],
            child: Container(
              height: 44,
              padding: const EdgeInsets.symmetric(horizontal: 12),
              decoration: BoxDecoration(
                color: theme.colorScheme.surfaceContainer,
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: theme.colorScheme.outlineVariant),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    Icons.category_outlined,
                    size: 18,
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                  if (_selectedCategory != null) ...[
                    const SizedBox(width: 6),
                    ConstrainedBox(
                      constraints: const BoxConstraints(maxWidth: 96),
                      child: Text(
                        _selectedCategory!,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: theme.textTheme.labelMedium?.copyWith(
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ),
                  ],
                ],
              ),
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
    this.large = false,
    this.onTap,
  });

  final String title;
  final String value;
  final IconData icon;
  final Color color;
  final bool large;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final content = Card(
      child: Padding(
        padding: EdgeInsets.all(large ? 22 : 14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, color: color, size: large ? 28 : 24),
            SizedBox(height: large ? 14 : 10),
            Text(
              title,
              style: theme.textTheme.bodyMedium?.copyWith(
                fontWeight: FontWeight.w700,
                color: color,
              ),
            ),
            SizedBox(height: large ? 10 : 4),
            FittedBox(
              fit: BoxFit.scaleDown,
              alignment: Alignment.centerLeft,
              child: Text(
                value,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: theme.textTheme.titleLarge?.copyWith(
                  fontWeight: FontWeight.bold,
                  fontSize: large ? 34 : null,
                ),
              ),
            ),
          ],
        ),
      ),
    );

    if (onTap == null) {
      return content;
    }

    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: onTap,
        child: content,
      ),
    );
  }
}

class _InventoryDetailRow extends StatelessWidget {
  const _InventoryDetailRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 92,
            child: Text(
              label,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              value,
              style: theme.textTheme.bodyMedium?.copyWith(
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _InventoryMetric {
  const _InventoryMetric({
    required this.title,
    required this.value,
    required this.icon,
    required this.color,
  });

  final String title;
  final String value;
  final IconData icon;
  final Color color;
}

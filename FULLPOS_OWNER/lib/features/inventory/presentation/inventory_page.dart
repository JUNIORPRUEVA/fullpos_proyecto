import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/providers/sync_request_provider.dart';
import '../../../core/theme/app_colors.dart';
import '../../../core/utils/accounting_format.dart';
import '../../categories/data/categories_repository.dart';
import '../../products/data/product_models.dart';
import '../../products/data/product_realtime_service.dart';
import '../../products/data/products_repository.dart';

class InventoryPageController extends ChangeNotifier {
  InventoryPageController({TextEditingController? searchController})
    : searchController = searchController ?? TextEditingController() {
    this.searchController.addListener(notifyListeners);
  }

  final TextEditingController searchController;
  List<String> _categories = <String>[];
  String? _selectedCategory;
  bool _outOfStockOnly = false;

  ValueChanged<String>? onSearchChanged;
  ValueChanged<String?>? onCategorySelected;
  ValueChanged<bool>? onOutOfStockChanged;

  List<String> get categories => _categories;
  String? get selectedCategory => _selectedCategory;
  bool get outOfStockOnly => _outOfStockOnly;
  bool get hasSearchQuery => searchController.text.trim().isNotEmpty;
  bool get hasActiveFilter => _selectedCategory != null || _outOfStockOnly;

  void applySearchChange(String value) {
    onSearchChanged?.call(value);
    notifyListeners();
  }

  void clearSearch() {
    if (searchController.text.isEmpty) return;
    searchController.clear();
    onSearchChanged?.call('');
    notifyListeners();
  }

  void selectCategory(String? value) {
    onCategorySelected?.call(value);
    notifyListeners();
  }

  void toggleOutOfStock(bool value) {
    onOutOfStockChanged?.call(value);
    notifyListeners();
  }

  void updateState({
    required List<String> categories,
    required String? selectedCategory,
    required bool outOfStockOnly,
  }) {
    _categories = List<String>.unmodifiable(categories);
    _selectedCategory = selectedCategory;
    _outOfStockOnly = outOfStockOnly;
    notifyListeners();
  }

  @override
  void dispose() {
    searchController.removeListener(notifyListeners);
    searchController.dispose();
    super.dispose();
  }
}

class InventoryPage extends ConsumerStatefulWidget {
  const InventoryPage({
    super.key,
    this.controller,
    this.showEmbeddedToolbar = true,
  });

  final InventoryPageController? controller;
  final bool showEmbeddedToolbar;

  @override
  ConsumerState<InventoryPage> createState() => _InventoryPageState();
}

class _InventoryPageState extends ConsumerState<InventoryPage>
    with WidgetsBindingObserver {
  late final TextEditingController _searchCtrl =
      widget.controller?.searchController ?? TextEditingController();
  Timer? _debounce;
  StreamSubscription<ProductRealtimeMessage>? _productRealtimeSubscription;
  bool _outOfStockOnly = false;
  String? _selectedCategory;
  bool _reloadRequested = false;

  bool _loading = true;
  String? _error;
  List<Product> _all = <Product>[];
  List<String> _syncedCategories = <String>[];

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    final controller = widget.controller;
    if (controller != null) {
      controller.onSearchChanged = (_) {
        _debounce?.cancel();
        _debounce = Timer(const Duration(milliseconds: 160), () {
          if (mounted) setState(() {});
        });
      };
      controller.onCategorySelected = _selectCategory;
      controller.onOutOfStockChanged = (value) {
        setState(() {
          _outOfStockOnly = value;
        });
        _syncControllerState();
      };
    }
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
    if (widget.controller == null) {
      _searchCtrl.dispose();
    }
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

  void _syncControllerState() {
    widget.controller?.updateState(
      categories: _availableCategories,
      selectedCategory: _selectedCategory,
      outOfStockOnly: _outOfStockOnly,
    );
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
      _syncControllerState();
    } catch (_) {
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
    list.sort((a, b) {
      final byName = a.name.toLowerCase().compareTo(b.name.toLowerCase());
      if (byName != 0) return byName;
      return a.code.toLowerCase().compareTo(b.code.toLowerCase());
    });
    return list;
  }

  void _selectCategory(String? category) {
    setState(() {
      _selectedCategory = category;
    });
    _syncControllerState();
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

    final highlightItems = [
      _InventoryMetric(
        title: 'Productos',
        value: totalProducts.toString(),
        icon: Icons.inventory_2_outlined,
        color: theme.colorScheme.secondary,
      ),
      _InventoryMetric(
        title: 'Unidades',
        value: totalUnits.toStringAsFixed(0),
        icon: Icons.format_list_numbered,
        color: theme.colorScheme.primary,
      ),
    ];

    final metricItems = [
      _InventoryMetric(
        title: 'Inversion',
        value: formatAccountingAmount(totalCost),
        icon: Icons.savings_outlined,
        color: AppColors.success,
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
        child: _loading
            ? const Center(child: CircularProgressIndicator())
            : _error != null
            ? Center(child: Text(_error!))
            : RefreshIndicator(
                onRefresh: () => _load(showLoading: true),
                child: CustomScrollView(
                  physics: const AlwaysScrollableScrollPhysics(),
                  slivers: [
                    SliverPadding(
                      padding: const EdgeInsets.fromLTRB(14, 10, 14, 0),
                      sliver: SliverToBoxAdapter(
                        child: Column(
                          children: [
                            Row(
                              children: [
                                for (
                                  var index = 0;
                                  index < highlightItems.length;
                                  index++
                                ) ...[
                                  if (index > 0) const SizedBox(width: 10),
                                  Expanded(
                                    child: _InventoryCompactStat(
                                      title: highlightItems[index].title,
                                      value: highlightItems[index].value,
                                      icon: highlightItems[index].icon,
                                      color: highlightItems[index].color,
                                    ),
                                  ),
                                ],
                              ],
                            ),
                            const SizedBox(height: 10),
                            _InventoryMetricStrip(items: metricItems),
                            const SizedBox(height: 16),
                            Row(
                              children: [
                                Expanded(
                                  child: Column(
                                    crossAxisAlignment:
                                        CrossAxisAlignment.start,
                                    children: [
                                      Text(
                                        'Productos',
                                        style: theme.textTheme.titleMedium
                                            ?.copyWith(
                                              color: const Color(0xFF172033),
                                              fontWeight: FontWeight.w900,
                                              letterSpacing: -0.4,
                                            ),
                                      ),
                                      const SizedBox(height: 2),
                                      Text(
                                        _selectedCategory == null
                                            ? 'Vista general del inventario'
                                            : 'Categoria: ${_selectedCategory!}',
                                        style: theme.textTheme.bodySmall
                                            ?.copyWith(
                                              color: const Color(0xFF7C8799),
                                              fontWeight: FontWeight.w700,
                                            ),
                                      ),
                                    ],
                                  ),
                                ),
                                if (_outOfStockOnly)
                                  Container(
                                    padding: const EdgeInsets.symmetric(
                                      horizontal: 12,
                                      vertical: 8,
                                    ),
                                    decoration: BoxDecoration(
                                      color: theme.colorScheme.error.withValues(
                                        alpha: 0.08,
                                      ),
                                      borderRadius: BorderRadius.circular(14),
                                      border: Border.all(
                                        color: theme.colorScheme.error
                                            .withValues(alpha: 0.14),
                                      ),
                                    ),
                                    child: Text(
                                      'Solo agotados',
                                      style: theme.textTheme.labelMedium
                                          ?.copyWith(
                                            color: theme.colorScheme.error,
                                            fontWeight: FontWeight.w800,
                                          ),
                                    ),
                                  ),
                              ],
                            ),
                            const SizedBox(height: 12),
                          ],
                        ),
                      ),
                    ),
                    if (filtered.isEmpty)
                      const SliverPadding(
                        padding: EdgeInsets.fromLTRB(14, 0, 14, 20),
                        sliver: SliverToBoxAdapter(
                          child: _InventoryEmptyState(),
                        ),
                      )
                    else ...[
                      SliverPadding(
                        padding: const EdgeInsets.fromLTRB(14, 0, 14, 20),
                        sliver: SliverToBoxAdapter(
                          child: _InventoryTableSection(
                            products: filtered,
                            onTapProduct: (product) =>
                                _showProductDetail(context, product),
                          ),
                        ),
                      ),
                    ],
                  ],
                ),
              ),
      ),
    );
  }
}

class _InventoryMetricStrip extends StatelessWidget {
  const _InventoryMetricStrip({required this.items});

  final List<_InventoryMetric> items;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      child: Row(
        children: [
          for (var index = 0; index < items.length; index++) ...[
            if (index > 0) const SizedBox(width: 10),
            Container(
              width: 194,
              padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
              decoration: BoxDecoration(
                color: theme.colorScheme.surface,
                borderRadius: BorderRadius.circular(16),
                border: Border.all(
                  color: items[index].color.withValues(alpha: 0.14),
                ),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(
                        items[index].icon,
                        size: 16,
                        color: items[index].color,
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          items[index].title,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: theme.textTheme.labelLarge?.copyWith(
                            color: const Color(0xFF6F7789),
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  Text(
                    items[index].value,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: theme.textTheme.titleLarge?.copyWith(
                      color: const Color(0xFF172033),
                      fontWeight: FontWeight.w900,
                      letterSpacing: -0.6,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ],
      ),
    );
  }
}

class _InventoryCompactStat extends StatelessWidget {
  const _InventoryCompactStat({
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
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: color.withValues(alpha: 0.14)),
      ),
      child: Row(
        children: [
          Container(
            width: 34,
            height: 34,
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.10),
              borderRadius: BorderRadius.circular(11),
            ),
            child: Icon(icon, color: color, size: 18),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: theme.textTheme.labelMedium?.copyWith(
                    color: const Color(0xFF778196),
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  value,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.titleMedium?.copyWith(
                    color: const Color(0xFF172033),
                    fontWeight: FontWeight.w900,
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

class _InventoryTableSection extends StatelessWidget {
  const _InventoryTableSection({
    required this.products,
    required this.onTapProduct,
  });

  final List<Product> products;
  final ValueChanged<Product> onTapProduct;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Container(
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(
          color: theme.colorScheme.outlineVariant.withValues(alpha: 0.62),
        ),
      ),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
        child: ConstrainedBox(
          constraints: const BoxConstraints(minWidth: 894),
          child: Column(
            children: [
              const _InventoryTableHeader(),
              for (var index = 0; index < products.length; index++)
                _InventoryTableRow(
                  product: products[index],
                  onTap: () => onTapProduct(products[index]),
                  showDivider: index != products.length - 1,
                ),
            ],
          ),
        ),
      ),
    );
  }
}

class _InventoryTableHeader extends StatelessWidget {
  const _InventoryTableHeader();

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.fromLTRB(14, 0, 14, 10),
      decoration: BoxDecoration(
        border: Border(
          bottom: BorderSide(
            color: Theme.of(
              context,
            ).colorScheme.outlineVariant.withValues(alpha: 0.62),
          ),
        ),
      ),
      child: const Row(
        children: [
          _InventoryHeaderCell(label: 'Producto', width: 260),
          _InventoryHeaderCell(label: 'Codigo', width: 100),
          _InventoryHeaderCell(label: 'Categoria', width: 140),
          _InventoryHeaderCell(label: 'Stock', width: 64, alignEnd: true),
          _InventoryHeaderCell(label: 'Costo', width: 104, alignEnd: true),
          _InventoryHeaderCell(label: 'Precio', width: 104, alignEnd: true),
          _InventoryHeaderCell(
            label: 'Valor stock',
            width: 122,
            alignEnd: true,
          ),
        ],
      ),
    );
  }
}

class _InventoryTableRow extends StatelessWidget {
  const _InventoryTableRow({
    required this.product,
    required this.onTap,
    required this.showDivider,
  });

  final Product product;
  final VoidCallback onTap;
  final bool showDivider;

  String? _normalizeCategory(String? value) {
    final normalized = value?.trim();
    if (normalized == null || normalized.isEmpty) return null;
    return normalized;
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isOut = product.stock <= 0;

    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
          decoration: BoxDecoration(
            border: showDivider
                ? Border(
                    bottom: BorderSide(
                      color: theme.colorScheme.outlineVariant.withValues(
                        alpha: 0.42,
                      ),
                    ),
                  )
                : null,
          ),
          child: Row(
            children: [
              _InventoryRowCell(
                width: 260,
                child: Text(
                  product.name,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: const Color(0xFF172033),
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
              _InventoryRowCell(
                width: 100,
                child: Text(
                  product.code.isEmpty ? '--' : product.code,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: const Color(0xFF5C6780),
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
              _InventoryRowCell(
                width: 140,
                child: Text(
                  _normalizeCategory(product.category) ?? '--',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: const Color(0xFF5C6780),
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
              _InventoryRowCell(
                width: 64,
                alignEnd: true,
                child: Text(
                  product.stock.toStringAsFixed(0),
                  textAlign: TextAlign.right,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: isOut
                        ? theme.colorScheme.error
                        : const Color(0xFF172033),
                    fontWeight: FontWeight.w800,
                  ),
                ),
              ),
              _InventoryRowCell(
                width: 104,
                alignEnd: true,
                child: Text(
                  formatAccountingAmount(product.cost),
                  textAlign: TextAlign.right,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: const Color(0xFF5C6780),
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
              _InventoryRowCell(
                width: 104,
                alignEnd: true,
                child: Text(
                  formatAccountingAmount(product.price),
                  textAlign: TextAlign.right,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.primary,
                    fontWeight: FontWeight.w800,
                  ),
                ),
              ),
              _InventoryRowCell(
                width: 122,
                alignEnd: true,
                child: Text(
                  formatAccountingAmount(product.stock * product.cost),
                  textAlign: TextAlign.right,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: AppColors.warning,
                    fontWeight: FontWeight.w800,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _InventoryHeaderCell extends StatelessWidget {
  const _InventoryHeaderCell({
    required this.label,
    required this.width,
    this.alignEnd = false,
  });

  final String label;
  final double width;
  final bool alignEnd;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: width,
      child: Text(
        label,
        textAlign: alignEnd ? TextAlign.right : TextAlign.left,
        style: Theme.of(context).textTheme.labelMedium?.copyWith(
          color: const Color(0xFF6F7789),
          fontWeight: FontWeight.w800,
        ),
      ),
    );
  }
}

class _InventoryRowCell extends StatelessWidget {
  const _InventoryRowCell({
    required this.width,
    required this.child,
    this.alignEnd = false,
  });

  final double width;
  final Widget child;
  final bool alignEnd;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: width,
      child: Align(
        alignment: alignEnd ? Alignment.centerRight : Alignment.centerLeft,
        child: child,
      ),
    );
  }
}

class _InventoryEmptyState extends StatelessWidget {
  const _InventoryEmptyState();

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 30),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(22),
        border: Border.all(
          color: theme.colorScheme.outlineVariant.withValues(alpha: 0.72),
        ),
      ),
      child: Column(
        children: [
          Icon(
            Icons.inventory_2_outlined,
            size: 28,
            color: theme.colorScheme.onSurfaceVariant,
          ),
          const SizedBox(height: 10),
          Text(
            'No hay productos para este filtro.',
            style: theme.textTheme.titleSmall?.copyWith(
              fontWeight: FontWeight.w800,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            'Prueba con otra busqueda o cambia la categoria seleccionada.',
            textAlign: TextAlign.center,
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ],
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

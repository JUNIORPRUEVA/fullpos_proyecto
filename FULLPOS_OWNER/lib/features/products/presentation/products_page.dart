import 'dart:async';
import 'dart:io';
import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:image_gallery_saver_plus/image_gallery_saver_plus.dart';
import 'package:permission_handler/permission_handler.dart';
import '../../../core/config/app_config.dart';
import '../../../core/providers/sync_request_provider.dart';
import '../../../core/utils/accounting_format.dart';
import '../../auth/data/auth_repository.dart';
import '../data/product_models.dart';
import '../data/product_realtime_service.dart';
import '../data/products_repository.dart';

class ProductsPageController {
  ProductsPageController({TextEditingController? searchController})
    : searchController = searchController ?? TextEditingController();

  final TextEditingController searchController;

  VoidCallback? onSearch;
  ValueChanged<String>? onChanged;

  void dispose() {
    searchController.dispose();
  }
}

class ProductsPage extends ConsumerStatefulWidget {
  const ProductsPage({
    super.key,
    this.controller,
    this.showEmbeddedToolbar = true,
  });

  final ProductsPageController? controller;
  final bool showEmbeddedToolbar;

  @override
  ConsumerState<ProductsPage> createState() => _ProductsPageState();
}

class _ProductsPageState extends ConsumerState<ProductsPage>
    with WidgetsBindingObserver {
  late final TextEditingController _searchCtrl =
      widget.controller?.searchController ?? TextEditingController();
  Timer? _searchDebounce;
  Timer? _autoRefreshTimer;
  StreamSubscription<ProductRealtimeMessage>? _productRealtimeSubscription;
  bool _refreshInFlight = false;
  bool _reloadRequested = false;
  List<Product> _allProducts = const [];
  List<Product> _products = const [];
  bool _loading = true;
  String? _error;
  String? _selectedCategory;

  static const Duration _autoRefreshInterval = Duration(seconds: 30);

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);

    final controller = widget.controller;
    if (controller != null) {
      controller.onSearch = () => _load(showLoading: true);
      controller.onChanged = (value) {
        _searchDebounce?.cancel();
        _searchDebounce = Timer(
          const Duration(milliseconds: 300),
          () => _load(showLoading: true),
        );
      };
    }

    _load(showLoading: true);
    _autoRefreshTimer = Timer.periodic(_autoRefreshInterval, (_) {
      // Silent refresh so UI doesn't flicker.
      _load(showLoading: false);
    });
    _productRealtimeSubscription = ref
        .read(productRealtimeServiceProvider)
        .stream
        .listen((message) {
          _applyRealtimeProductEvent(message);
          unawaited(_load(showLoading: false));
        });
  }

  @override
  void dispose() {
    if (widget.controller == null) {
      _searchCtrl.dispose();
    }
    _searchDebounce?.cancel();
    _autoRefreshTimer?.cancel();
    _productRealtimeSubscription?.cancel();
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _load(showLoading: false);
    }
  }

  void _applyFilters() {
    final query = _searchCtrl.text.trim().toLowerCase();
    var list = _allProducts;
    if (query.isNotEmpty) {
      list = list
          .where(
            (p) =>
                p.name.toLowerCase().contains(query) ||
                p.code.toLowerCase().contains(query) ||
                (p.description?.toLowerCase().contains(query) ?? false) ||
                (_normalizeCategory(
                      p.category,
                    )?.toLowerCase().contains(query) ??
                    false),
          )
          .toList();
    }
    if (_selectedCategory != null) {
      list = list
          .where((p) => _normalizeCategory(p.category) == _selectedCategory)
          .toList();
    }
    setState(() {
      _products = list;
    });
  }

  List<String> get _availableCategories {
    final categories =
        _allProducts
            .map((product) => _normalizeCategory(product.category))
            .whereType<String>()
            .toSet()
            .toList()
          ..sort((a, b) => a.toLowerCase().compareTo(b.toLowerCase()));
    return categories;
  }

  String? _normalizeCategory(String? value) {
    final normalized = value?.trim();
    if (normalized == null || normalized.isEmpty) return null;
    return normalized;
  }

  void _selectCategory(String? category) {
    setState(() {
      _selectedCategory = category;
    });
    _applyFilters();
  }

  void _applyRealtimeProductEvent(ProductRealtimeMessage message) {
    if (!mounted) return;

    final incoming = message.product;
    final isDelete =
        message.type == 'product.deleted' || incoming.deletedAt != null;

    setState(() {
      final next = List<Product>.from(_allProducts);
      final index = next.indexWhere((item) => item.id == incoming.id);

      if (isDelete || !incoming.isActive) {
        if (index >= 0) {
          next.removeAt(index);
        }
      } else if (index >= 0) {
        next[index] = incoming;
      } else {
        next.insert(0, incoming);
      }

      next.sort((a, b) {
        final aUpdated =
            a.updatedAt ??
            a.createdAt ??
            DateTime.fromMillisecondsSinceEpoch(0);
        final bUpdated =
            b.updatedAt ??
            b.createdAt ??
            DateTime.fromMillisecondsSinceEpoch(0);
        final cmp = bUpdated.compareTo(aUpdated);
        if (cmp != 0) return cmp;
        return b.id.compareTo(a.id);
      });

      _allProducts = List<Product>.unmodifiable(next);
    });

    _applyFilters();
  }

  Future<void> _load({required bool showLoading}) async {
    if (_refreshInFlight) {
      _reloadRequested = true;
      return;
    }
    _refreshInFlight = true;
    _reloadRequested = false;

    if (showLoading && mounted) {
      setState(() {
        _loading = true;
        _error = null;
      });
    }

    final repo = ref.read(productsRepositoryProvider);
    try {
      final result = await repo.list(
        search: _searchCtrl.text.trim(),
        pageSize: 100,
      );
      if (!mounted) return;
      setState(() {
        _allProducts = result.data;
        if (_selectedCategory != null &&
            !_availableCategories.contains(_selectedCategory)) {
          _selectedCategory = null;
        }
        if (showLoading) _loading = false;
      });
      _applyFilters();
    } catch (_) {
      if (!mounted) return;
      setState(() {
        // En auto-refresh silencioso, no tapar datos existentes.
        if (showLoading) {
          _error = 'No se pudieron cargar los productos';
          _loading = false;
        }
      });
    } finally {
      _refreshInFlight = false;
      if (_reloadRequested && mounted) {
        _reloadRequested = false;
        unawaited(_load(showLoading: false));
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    ref.listen<SyncRequest>(syncRequestProvider, (previous, next) {
      if (previous?.revision == next.revision) return;
      if (!next.appliesTo('/products')) return;
      unawaited(_load(showLoading: true));
    });

    final authState = ref.watch(authRepositoryProvider);
    final appConfig = ref.watch(appConfigProvider);

    return Scaffold(
      body: SafeArea(
        child: Column(
          children: [
            if (widget.showEmbeddedToolbar)
              _CatalogToolbar(
                searchController: _searchCtrl,
                categories: _availableCategories,
                selectedCategory: _selectedCategory,
                onSearch: () => _load(showLoading: true),
                onChanged: (value) {
                  _searchDebounce?.cancel();
                  _searchDebounce = Timer(
                    const Duration(milliseconds: 300),
                    () => _load(showLoading: true),
                  );
                },
                onCategorySelected: _selectCategory,
              ),
            Expanded(
              child: _loading
                  ? const Center(child: CircularProgressIndicator())
                  : _error != null
                  ? Center(child: Text(_error!))
                  : _products.isEmpty
                  ? _CatalogEmptyState(
                      companyName: authState.companyName?.trim(),
                      companyRnc: authState.companyRnc?.trim(),
                      companyId: authState.companyId?.toString(),
                      serverUrl: appConfig.baseUrl,
                      onRefresh: () => _load(showLoading: true),
                    )
                  : RefreshIndicator(
                      onRefresh: () => _load(showLoading: true),
                      child: LayoutBuilder(
                        builder: (context, constraints) {
                          return GridView.builder(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 12,
                              vertical: 10,
                            ),
                            itemCount: _products.length,
                            gridDelegate:
                                const SliverGridDelegateWithFixedCrossAxisCount(
                                  crossAxisCount: 2,
                                  crossAxisSpacing: 12,
                                  mainAxisSpacing: 12,
                                  childAspectRatio: 0.75,
                                ),
                            itemBuilder: (context, index) {
                              final product = _products[index];
                              return _ProductCard(
                                product: product,
                                onTap: () => Navigator.of(context).push(
                                  PageRouteBuilder(
                                    pageBuilder: (context, animation, _) =>
                                        FadeTransition(
                                          opacity: animation,
                                          child: _ProductDetailPage(
                                            product: product,
                                          ),
                                        ),
                                  ),
                                ),
                              );
                            },
                          );
                        },
                      ),
                    ),
            ),
          ],
        ),
      ),
    );
  }
}

class _CatalogEmptyState extends StatelessWidget {
  const _CatalogEmptyState({
    required this.companyName,
    required this.companyRnc,
    required this.companyId,
    required this.serverUrl,
    required this.onRefresh,
  });

  final String? companyName;
  final String? companyRnc;
  final String? companyId;
  final String serverUrl;
  final Future<void> Function() onRefresh;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return RefreshIndicator(
      onRefresh: onRefresh,
      child: LayoutBuilder(
        builder: (context, constraints) {
          return ListView(
            physics: const AlwaysScrollableScrollPhysics(),
            padding: const EdgeInsets.all(24),
            children: [
              ConstrainedBox(
                constraints: BoxConstraints(
                  minHeight: constraints.maxHeight - 48,
                ),
                child: Center(
                  child: Container(
                    constraints: const BoxConstraints(maxWidth: 620),
                    padding: const EdgeInsets.all(20),
                    decoration: BoxDecoration(
                      color: theme.colorScheme.surface,
                      borderRadius: BorderRadius.circular(20),
                      border: Border.all(
                        color: theme.colorScheme.outlineVariant,
                      ),
                    ),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Icon(
                              Icons.inventory_2_outlined,
                              color: theme.colorScheme.primary,
                              size: 26,
                            ),
                            const SizedBox(width: 10),
                            Expanded(
                              child: Text(
                                'No hay productos para esta sesión',
                                style: theme.textTheme.titleLarge?.copyWith(
                                  fontWeight: FontWeight.w800,
                                ),
                              ),
                            ),
                          ],
                        ),
                        Text(
                          'La app sí cargó correctamente, pero el backend respondió un catálogo vacío para la empresa autenticada.',
                          style: theme.textTheme.bodyMedium?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                            height: 1.35,
                          ),
                        ),
                        const SizedBox(height: 16),
                        Wrap(
                          spacing: 8,
                          runSpacing: 8,
                          children: [
                            if (companyName != null && companyName!.isNotEmpty)
                              _InfoChip(label: 'Empresa', value: companyName!),
                            if (companyRnc != null && companyRnc!.isNotEmpty)
                              _InfoChip(label: 'RNC', value: companyRnc!),
                            if (companyId != null && companyId!.isNotEmpty)
                              _InfoChip(label: 'ID empresa', value: companyId!),
                          ],
                        ),
                        const SizedBox(height: 12),
                        _InfoChip(label: 'Servidor', value: serverUrl),
                        const SizedBox(height: 16),
                        Text(
                          'Si otro admin sí ve datos y este no, casi seguro ambos usuarios no están ligados a la misma empresa en la nube.',
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                            height: 1.35,
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ],
          );
        },
      ),
    );
  }
}

class _InfoChip extends StatelessWidget {
  const _InfoChip({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerLow,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: RichText(
        text: TextSpan(
          style: theme.textTheme.bodyMedium,
          children: [
            TextSpan(
              text: '$label: ',
              style: TextStyle(
                color: theme.colorScheme.onSurfaceVariant,
                fontWeight: FontWeight.w700,
              ),
            ),
            TextSpan(
              text: value,
              style: TextStyle(
                color: theme.colorScheme.onSurface,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _CatalogToolbar extends StatelessWidget {
  const _CatalogToolbar({
    required this.searchController,
    required this.categories,
    required this.selectedCategory,
    required this.onSearch,
    required this.onChanged,
    required this.onCategorySelected,
  });

  final TextEditingController searchController;
  final List<String> categories;
  final String? selectedCategory;
  final VoidCallback onSearch;
  final ValueChanged<String> onChanged;
  final ValueChanged<String?> onCategorySelected;

  static const _allCategoriesValue = '__all_categories__';

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.fromLTRB(12, 6, 12, 4),
      child: Row(
        children: [
          Expanded(
            child: Container(
              height: 42,
              decoration: BoxDecoration(
                color: theme.colorScheme.surface,
                borderRadius: BorderRadius.circular(12),
                boxShadow: [
                  BoxShadow(
                    color: theme.colorScheme.shadow.withValues(alpha: 0.08),
                    blurRadius: 16,
                    offset: const Offset(0, 4),
                  ),
                ],
              ),
              child: TextField(
                controller: searchController,
                onSubmitted: (_) => onSearch(),
                onChanged: onChanged,
                textInputAction: TextInputAction.search,
                decoration: InputDecoration(
                  hintText: 'Buscar producto...',
                  hintStyle: theme.textTheme.bodyMedium?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                  prefixIcon: Icon(
                    Icons.search_rounded,
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                  suffixIcon: searchController.text.isEmpty
                      ? null
                      : IconButton(
                          tooltip: 'Limpiar búsqueda',
                          icon: Icon(
                            Icons.close_rounded,
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                          onPressed: () {
                            searchController.clear();
                            onChanged('');
                            onSearch();
                          },
                        ),
                  border: InputBorder.none,
                  contentPadding: const EdgeInsets.symmetric(
                    horizontal: 12,
                    vertical: 10,
                  ),
                ),
              ),
            ),
          ),
          const SizedBox(width: 8),
          PopupMenuButton<String>(
            tooltip: 'Filtrar por categoría',
            offset: const Offset(0, 48),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(14),
            ),
            color: theme.colorScheme.surface,
            surfaceTintColor: Colors.transparent,
            onSelected: (value) {
              onCategorySelected(value == _allCategoriesValue ? null : value);
            },
            itemBuilder: (context) => [
              CheckedPopupMenuItem<String>(
                value: _allCategoriesValue,
                checked: selectedCategory == null,
                child: const Text('Todas las categorías'),
              ),
              ...categories.map(
                (category) => CheckedPopupMenuItem<String>(
                  value: category,
                  checked: selectedCategory == category,
                  child: Text(category),
                ),
              ),
            ],
            child: Ink(
              height: 42,
              width: 42,
              decoration: BoxDecoration(
                color: theme.colorScheme.surfaceContainer,
                borderRadius: BorderRadius.circular(12),
              ),
              child: Icon(
                Icons.filter_list_rounded,
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _ProductCard extends StatelessWidget {
  const _ProductCard({required this.product, required this.onTap});

  final Product product;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final hasImage = product.imageUrl != null && product.imageUrl!.isNotEmpty;

    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(16),
        splashColor: theme.colorScheme.primary.withValues(alpha: 0.1),
        highlightColor: Colors.transparent,
        child: Ink(
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(16),
            color: theme.colorScheme.surface,
            boxShadow: [
              BoxShadow(
                color: theme.colorScheme.shadow.withValues(alpha: 0.07),
                blurRadius: 20,
                offset: const Offset(0, 5),
              ),
            ],
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Expanded(
                flex: 7,
                child: Stack(
                  fit: StackFit.expand,
                  children: [
                    ClipRRect(
                      borderRadius: const BorderRadius.vertical(
                        top: Radius.circular(16),
                      ),
                      child: hasImage
                          ? Hero(
                              tag: 'product-image-${product.id}',
                              child: Image.network(
                                product.imageUrl!,
                                fit: BoxFit.cover,
                                errorBuilder: (context, error, stackTrace) {
                                  return _ProductCardPlaceholder(
                                    product: product,
                                  );
                                },
                              ),
                            )
                          : _ProductCardPlaceholder(product: product),
                    ),
                    Positioned(
                      top: 10,
                      left: 10,
                      right: 10,
                      child: Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 10,
                          vertical: 6,
                        ),
                        decoration: BoxDecoration(
                          color: Colors.black.withValues(alpha: 0.48),
                          borderRadius: BorderRadius.circular(10),
                        ),
                        child: Row(
                          children: [
                            Expanded(
                              child: Text(
                                'Codigo: ${product.code}',
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: const TextStyle(
                                  color: Colors.white,
                                  fontSize: 11.5,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                            ),
                            const SizedBox(width: 8),
                            Text(
                              'Stock: ${product.stock.toStringAsFixed(0)}',
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: const TextStyle(
                                color: Colors.white,
                                fontSize: 11.5,
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                    Positioned(
                      bottom: 0,
                      left: 0,
                      right: 0,
                      child: Container(
                        padding: const EdgeInsets.fromLTRB(12, 20, 12, 10),
                        decoration: BoxDecoration(
                          gradient: LinearGradient(
                            colors: [
                              Colors.black.withValues(alpha: 0.7),
                              Colors.black.withValues(alpha: 0),
                            ],
                            begin: Alignment.bottomCenter,
                            end: Alignment.topCenter,
                          ),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Precio: ${formatAccountingAmount(product.price)}',
                              style: const TextStyle(
                                color: Colors.white,
                                fontWeight: FontWeight.bold,
                                fontSize: 15,
                              ),
                            ),
                            const SizedBox(height: 2),
                            Text(
                              'Costo: ${formatAccountingAmount(product.cost)}',
                              style: TextStyle(
                                color: Colors.white.withValues(alpha: 0.85),
                                fontWeight: FontWeight.w500,
                                fontSize: 12,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              Padding(
                padding: const EdgeInsets.fromLTRB(12, 10, 12, 12),
                child: Text(
                  product.name,
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    fontWeight: FontWeight.w500,
                    color: theme.colorScheme.onSurface,
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

class _ProductCardPlaceholder extends StatelessWidget {
  const _ProductCardPlaceholder({required this.product});

  final Product product;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return DecoratedBox(
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [
            theme.colorScheme.surfaceContainerHighest,
            theme.colorScheme.surfaceContainer,
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
      ),
      child: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.inventory_2_rounded,
              size: 30,
              color: theme.colorScheme.primary,
            ),
            const SizedBox(height: 8),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Text(
                product.code,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                textAlign: TextAlign.center,
                style: theme.textTheme.labelLarge?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _ProductDetailPage extends StatelessWidget {
  const _ProductDetailPage({required this.product});

  final Product product;

  @override
  Widget build(BuildContext context) {
    return _ProductDetailBody(product: product);
  }
}

class _ProductDetailBody extends StatefulWidget {
  const _ProductDetailBody({required this.product});

  final Product product;

  @override
  State<_ProductDetailBody> createState() => _ProductDetailBodyState();
}

class _ProductDetailBodyState extends State<_ProductDetailBody> {
  bool _downloading = false;

  Product get product => widget.product;

  bool get _hasImage =>
      product.imageUrl != null && product.imageUrl!.trim().isNotEmpty;

  Future<bool> _requestGalleryPermissionIfNeeded() async {
    if (kIsWeb) return false;
    try {
      if (Platform.isAndroid) {
        // Android: en 13+ existe READ_MEDIA_IMAGES; en versiones viejas se usa STORAGE.
        // Para guardar (MediaStore) usualmente no hace falta, pero pedimos para compatibilidad.
        PermissionStatus status;
        try {
          status = await Permission.photos.request();
        } catch (_) {
          status = PermissionStatus.denied;
        }

        if (status.isGranted || status.isLimited) return true;

        // Fallback legacy.
        final legacy = await Permission.storage.request();
        return legacy.isGranted || legacy.isLimited;
      }
      if (Platform.isIOS) {
        // iOS: para guardar en galería, photosAddOnly suele ser el permiso correcto.
        PermissionStatus status;
        try {
          status = await Permission.photosAddOnly.request();
        } catch (_) {
          status = await Permission.photos.request();
        }
        return status.isGranted || status.isLimited;
      }
    } catch (_) {
      // Ignorar: intentaremos guardar igual.
    }
    return true;
  }

  Future<void> _downloadImageToGallery() async {
    if (!_hasImage) return;
    if (_downloading) return;
    if (kIsWeb) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Descarga no disponible en Web.')),
      );
      return;
    }

    setState(() => _downloading = true);
    try {
      if (mounted) {
        final messenger = ScaffoldMessenger.of(context);
        messenger.hideCurrentSnackBar();
        messenger.showSnackBar(
          const SnackBar(
            content: Text('Guardando imagen en la galería...'),
            duration: Duration(seconds: 2),
          ),
        );
      }

      final granted = await _requestGalleryPermissionIfNeeded();
      if (!granted) {
        if (!mounted) return;
        final messenger = ScaffoldMessenger.of(context);
        messenger.showSnackBar(
          const SnackBar(
            content: Text(
              'Permiso de galería requerido para guardar la imagen. Actívalo en Ajustes e intenta nuevamente.',
            ),
          ),
        );
        return;
      }

      final url = product.imageUrl!.trim();
      final dio = Dio();
      final res = await dio.get<List<int>>(
        url,
        options: Options(responseType: ResponseType.bytes),
      );
      final bytes = Uint8List.fromList(res.data ?? const <int>[]);
      if (bytes.isEmpty) throw Exception('No se pudo descargar la imagen');

      final result = await ImageGallerySaverPlus.saveImage(
        bytes,
        quality: 95,
        name: 'fullpos_product_${product.id}',
      );

      final ok = (result['isSuccess'] == true) || (result['success'] == true);
      final location =
          (result['filePath'] ??
                  result['path'] ??
                  result['fileUri'] ??
                  result['uri'])
              ?.toString()
              .trim();
      final message = ok
          ? 'Imagen guardada en la galería.'
          : 'No se pudo guardar la imagen en la galería.';
      if (!mounted) return;
      final messenger = ScaffoldMessenger.of(context);
      messenger.hideCurrentSnackBar();
      messenger.showSnackBar(
        SnackBar(
          content: Text(
            (ok && location != null && location.isNotEmpty)
                ? '$message\nUbicación: $location'
                : message,
          ),
          duration: const Duration(seconds: 6),
          action: (ok && location != null && location.isNotEmpty)
              ? SnackBarAction(
                  label: 'Copiar',
                  onPressed: () async {
                    await Clipboard.setData(ClipboardData(text: location));
                  },
                )
              : null,
        ),
      );
    } catch (e) {
      if (!mounted) return;
      // Si el permiso está bloqueado permanentemente, dar una guía clara.
      try {
        final permanentlyDenied = Platform.isIOS
            ? await Permission.photos.isPermanentlyDenied
            : await Permission.storage.isPermanentlyDenied;
        if (permanentlyDenied) {
          if (!mounted) return;
          final messenger = ScaffoldMessenger.of(context);
          messenger.showSnackBar(
            const SnackBar(
              content: Text(
                'No se puede guardar porque el permiso está bloqueado. Ve a Ajustes y habilita acceso a Fotos/Almacenamiento.',
              ),
            ),
          );
          return;
        }
      } catch (_) {
        // Ignore.
      }
      if (!mounted) return;
      final messenger = ScaffoldMessenger.of(context);
      messenger.showSnackBar(
        const SnackBar(
          content: Text(
            'No se pudo descargar la imagen. Verifica tu conexión e intenta de nuevo.',
          ),
        ),
      );
    } finally {
      if (mounted) setState(() => _downloading = false);
    }
  }

  void _openImageViewer() {
    if (!_hasImage) return;
    Navigator.of(context).push(
      PageRouteBuilder(
        pageBuilder: (context, animation, _) => FadeTransition(
          opacity: animation,
          child: _ProductImageViewerPage(
            productId: product.id,
            imageUrl: product.imageUrl!.trim(),
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      backgroundColor: Colors.black,
      body: LayoutBuilder(
        builder: (context, constraints) {
          final availableHeight = constraints.maxHeight;
          final imageHeight = availableHeight * 0.8;
          final infoHeight = availableHeight - imageHeight;

          return Stack(
            children: [
              Positioned.fill(
                child: GestureDetector(
                  onTap: _openImageViewer,
                  child: _hasImage
                      ? Hero(
                          tag: 'product-image-${product.id}',
                          child: Image.network(
                            product.imageUrl!,
                            fit: BoxFit.cover,
                            errorBuilder: (context, error, stackTrace) {
                              return Container(
                                color: theme.colorScheme.surfaceContainerHighest,
                                child: const Center(
                                  child: Icon(
                                    Icons.image_not_supported,
                                    size: 48,
                                  ),
                                ),
                              );
                            },
                          ),
                        )
                      : Container(
                          color: theme.colorScheme.surfaceContainerHighest,
                          child: const Center(
                            child: Icon(
                              Icons.image_not_supported,
                              size: 48,
                            ),
                          ),
                        ),
                ),
              ),
              Positioned.fill(
                child: DecoratedBox(
                  decoration: BoxDecoration(
                    gradient: LinearGradient(
                      begin: Alignment.topCenter,
                      end: Alignment.bottomCenter,
                      colors: [
                        Colors.black.withValues(alpha: 0.18),
                        Colors.transparent,
                        Colors.black.withValues(alpha: 0.28),
                        Colors.black.withValues(alpha: 0.84),
                      ],
                      stops: const [0, 0.22, 0.56, 1],
                    ),
                  ),
                ),
              ),
              Positioned(
                top: 0,
                left: 0,
                right: 0,
                height: imageHeight,
                child: IgnorePointer(
                  ignoring: true,
                  child: DecoratedBox(
                    decoration: BoxDecoration(
                      gradient: LinearGradient(
                        begin: Alignment.bottomCenter,
                        end: Alignment.topCenter,
                        colors: [
                          Colors.transparent,
                          Colors.transparent,
                          Colors.black.withValues(alpha: 0.10),
                        ],
                      ),
                    ),
                  ),
                ),
              ),
              SafeArea(
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(16, 12, 16, 18),
                  child: Stack(
                    children: [
                      Align(
                        alignment: Alignment.topLeft,
                        child: Material(
                          color: Colors.black.withValues(alpha: 0.45),
                          borderRadius: BorderRadius.circular(999),
                          child: InkWell(
                            borderRadius: BorderRadius.circular(999),
                            onTap: () => Navigator.of(context).maybePop(),
                            child: const Padding(
                              padding: EdgeInsets.all(12),
                              child: Icon(
                                Icons.arrow_back_rounded,
                                color: Colors.white,
                                size: 22,
                              ),
                            ),
                          ),
                        ),
                      ),
                      Align(
                        alignment: Alignment.topRight,
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          crossAxisAlignment: CrossAxisAlignment.end,
                          children: [
                            AnimatedScale(
                              duration: const Duration(milliseconds: 120),
                              scale: _downloading ? 0.98 : 1,
                              child: Material(
                                color: Colors.black.withValues(alpha: 0.45),
                                borderRadius: BorderRadius.circular(999),
                                child: InkWell(
                                  borderRadius: BorderRadius.circular(999),
                                  onTap: _hasImage
                                      ? _downloadImageToGallery
                                      : null,
                                  child: Padding(
                                    padding: const EdgeInsets.all(12),
                                    child: _downloading
                                        ? const SizedBox(
                                            width: 18,
                                            height: 18,
                                            child: CircularProgressIndicator(
                                              strokeWidth: 2,
                                              color: Colors.white,
                                            ),
                                          )
                                        : const Icon(
                                            Icons.download_rounded,
                                            color: Colors.white,
                                            size: 20,
                                          ),
                                  ),
                                ),
                              ),
                            ),
                            const SizedBox(height: 8),
                            Material(
                              color: Colors.black.withValues(alpha: 0.32),
                              borderRadius: BorderRadius.circular(999),
                              child: InkWell(
                                borderRadius: BorderRadius.circular(999),
                                onTap: _hasImage ? _openImageViewer : null,
                                child: const Padding(
                                  padding: EdgeInsets.all(10),
                                  child: Icon(
                                    Icons.photo_size_select_large_rounded,
                                    color: Colors.white,
                                    size: 18,
                                  ),
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                      Positioned(
                        left: 0,
                        right: 0,
                        bottom: 0,
                        child: Container(
                          padding: const EdgeInsets.fromLTRB(18, 18, 18, 16),
                          constraints: BoxConstraints(
                            minHeight: infoHeight,
                          ),
                          decoration: BoxDecoration(
                            borderRadius: BorderRadius.circular(24),
                            color: Colors.black.withValues(alpha: 0.24),
                            border: Border.all(
                              color: Colors.white.withValues(alpha: 0.12),
                            ),
                          ),
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                product.name,
                                maxLines: 2,
                                overflow: TextOverflow.ellipsis,
                                style: theme.textTheme.headlineSmall?.copyWith(
                                  color: Colors.white,
                                  fontWeight: FontWeight.w900,
                                  height: 1.05,
                                ),
                              ),
                              const SizedBox(height: 14),
                              Row(
                                children: [
                                  Expanded(
                                    child: _DetailOverlayValue(
                                      label: 'Precio',
                                      value: formatAccountingAmount(product.price),
                                      emphasized: true,
                                    ),
                                  ),
                                  const SizedBox(width: 10),
                                  Expanded(
                                    child: _DetailOverlayValue(
                                      label: 'Costo',
                                      value: formatAccountingAmount(product.cost),
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 10),
                              Row(
                                children: [
                                  Expanded(
                                    child: _DetailOverlayValue(
                                      label: 'Stock',
                                      value: product.stock.toStringAsFixed(0),
                                    ),
                                  ),
                                  const SizedBox(width: 10),
                                  Expanded(
                                    child: _DetailOverlayValue(
                                      label: 'Codigo',
                                      value: product.code,
                                    ),
                                  ),
                                ],
                              ),
                            ],
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          );
        },
      ),
    );
  }
}

class _DetailOverlayValue extends StatelessWidget {
  const _DetailOverlayValue({
    required this.label,
    required this.value,
    this.emphasized = false,
  });

  final String label;
  final String value;
  final bool emphasized;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: emphasized
            ? Colors.white.withValues(alpha: 0.16)
            : Colors.white.withValues(alpha: 0.10),
        borderRadius: BorderRadius.circular(14),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: theme.textTheme.labelMedium?.copyWith(
              color: Colors.white.withValues(alpha: 0.78),
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            value,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: theme.textTheme.titleMedium?.copyWith(
              color: Colors.white,
              fontWeight: emphasized ? FontWeight.w900 : FontWeight.w800,
              letterSpacing: -0.2,
            ),
          ),
        ],
      ),
    );
  }
}

class _ProductImageViewerPage extends StatelessWidget {
  const _ProductImageViewerPage({
    required this.productId,
    required this.imageUrl,
  });

  final int productId;
  final String imageUrl;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      body: SafeArea(
        child: Stack(
          children: [
            Positioned.fill(
              child: GestureDetector(
                onTap: () => Navigator.of(context).pop(),
                child: Center(
                  child: Hero(
                    tag: 'product-image-$productId',
                    child: Image.network(
                      imageUrl,
                      fit: BoxFit.contain,
                    ),
                  ),
                ),
              ),
            ),
            Positioned(
              top: 12,
              left: 12,
              child: Material(
                color: Colors.black.withValues(alpha: 0.45),
                borderRadius: BorderRadius.circular(999),
                child: InkWell(
                  borderRadius: BorderRadius.circular(999),
                  onTap: () => Navigator.of(context).pop(),
                  child: const Padding(
                    padding: EdgeInsets.all(10),
                    child: Icon(
                      Icons.arrow_back_rounded,
                      color: Colors.white,
                      size: 20,
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

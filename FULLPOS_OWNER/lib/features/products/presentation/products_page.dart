import 'dart:async';
import 'dart:io';
import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:image_gallery_saver_plus/image_gallery_saver_plus.dart';
import 'package:permission_handler/permission_handler.dart';
import '../../../core/theme/app_colors.dart';
import '../data/product_models.dart';
import '../data/product_realtime_service.dart';
import '../data/products_repository.dart';

class ProductsPageController {
  ProductsPageController({TextEditingController? searchController})
    : searchController = searchController ?? TextEditingController();

  final TextEditingController searchController;

  VoidCallback? onSearch;
  ValueChanged<String>? onChanged;
  void Function(BuildContext context)? onFilter;

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
  double? _minPrice;
  double? _maxPrice;
  double? _minCost;
  double? _maxCost;

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
      controller.onFilter = (context) => _openFilters(context);
    }

    _load(showLoading: true);
    _autoRefreshTimer = Timer.periodic(_autoRefreshInterval, (_) {
      // Silent refresh so UI doesn't flicker.
      _load(showLoading: false);
    });
    _productRealtimeSubscription = ref
        .read(productRealtimeServiceProvider)
        .stream
        .listen((_) => _load(showLoading: false));
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
                p.code.toLowerCase().contains(query),
          )
          .toList();
    }
    if (_minPrice != null) {
      list = list.where((p) => p.price >= _minPrice!).toList();
    }
    if (_maxPrice != null) {
      list = list.where((p) => p.price <= _maxPrice!).toList();
    }
    if (_minCost != null) {
      list = list.where((p) => p.cost >= _minCost!).toList();
    }
    if (_maxCost != null) {
      list = list.where((p) => p.cost <= _maxCost!).toList();
    }
    setState(() {
      _products = list;
    });
  }

  Future<void> _openFilters(BuildContext context) async {
    await showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (_) {
        return Padding(
          padding: EdgeInsets.only(
            bottom: MediaQuery.of(context).viewInsets.bottom,
          ),
          child: _FilterSheet(
            minPrice: _minPrice,
            maxPrice: _maxPrice,
            minCost: _minCost,
            maxCost: _maxCost,
            onApply: (minP, maxP, minC, maxC) {
              _minPrice = minP;
              _maxPrice = maxP;
              _minCost = minC;
              _maxCost = maxC;
              _applyFilters();
            },
          ),
        );
      },
    );
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
    return Scaffold(
      body: SafeArea(
        child: Column(
          children: [
            if (widget.showEmbeddedToolbar)
              _CatalogToolbar(
                searchController: _searchCtrl,
                onSearch: () => _load(showLoading: true),
                onChanged: (value) {
                  _searchDebounce?.cancel();
                  _searchDebounce = Timer(
                    const Duration(milliseconds: 300),
                    () => _load(showLoading: true),
                  );
                },
                onFilter: () => _openFilters(context),
              ),
            Expanded(
              child: _loading
                  ? const Center(child: CircularProgressIndicator())
                  : _error != null
                  ? Center(child: Text(_error!))
                  : RefreshIndicator(
                      onRefresh: () => _load(showLoading: true),
                      child: LayoutBuilder(
                        builder: (context, constraints) {
                          final crossAxisCount = constraints.maxWidth > 1300
                              ? 5
                              : constraints.maxWidth > 1100
                              ? 4
                              : constraints.maxWidth > 800
                              ? 3
                              : 2;
                          return GridView.builder(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 6,
                              vertical: 6,
                            ),
                            itemCount: _products.length,
                            gridDelegate:
                                SliverGridDelegateWithFixedCrossAxisCount(
                                  crossAxisCount: crossAxisCount,
                                  crossAxisSpacing: 6,
                                  mainAxisSpacing: 6,
                                  childAspectRatio: 0.92,
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

class _CatalogToolbar extends StatelessWidget {
  const _CatalogToolbar({
    required this.searchController,
    required this.onSearch,
    required this.onChanged,
    required this.onFilter,
  });

  final TextEditingController searchController;
  final VoidCallback onSearch;
  final ValueChanged<String> onChanged;
  final VoidCallback onFilter;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.fromLTRB(12, 4, 12, 4),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface.withAlpha((0.85 * 255).round()),
        boxShadow: [
          BoxShadow(
            color: theme.colorScheme.onSurface.withAlpha((0.15 * 255).round()),
            blurRadius: 10,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Row(
        children: [
          Expanded(
            child: TextField(
              controller: searchController,
              onSubmitted: (_) => onSearch(),
              onChanged: onChanged,
              decoration: InputDecoration(
                hintText: 'Buscar por nombre o codigo',
                prefixIcon: const Icon(Icons.search),
                suffixIcon: IconButton(
                  icon: const Icon(Icons.close),
                  onPressed: () {
                    searchController.clear();
                    onSearch();
                  },
                ),
                contentPadding: const EdgeInsets.symmetric(
                  vertical: 10,
                  horizontal: 12,
                ),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                ),
              ),
            ),
          ),
          const SizedBox(width: 10),
          ElevatedButton.icon(
            style: ElevatedButton.styleFrom(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
            ),
            onPressed: onFilter,
            icon: const Icon(Icons.filter_alt_outlined, size: 18),
            label: const Text('Filtros'),
          ),
        ],
      ),
    );
  }
}

class _FilterSheet extends StatefulWidget {
  const _FilterSheet({
    required this.minPrice,
    required this.maxPrice,
    required this.minCost,
    required this.maxCost,
    required this.onApply,
  });

  final double? minPrice;
  final double? maxPrice;
  final double? minCost;
  final double? maxCost;
  final void Function(
    double? minPrice,
    double? maxPrice,
    double? minCost,
    double? maxCost,
  )
  onApply;

  @override
  State<_FilterSheet> createState() => _FilterSheetState();
}

class _FilterSheetState extends State<_FilterSheet> {
  late final TextEditingController _minPriceCtrl;
  late final TextEditingController _maxPriceCtrl;
  late final TextEditingController _minCostCtrl;
  late final TextEditingController _maxCostCtrl;

  @override
  void initState() {
    super.initState();
    _minPriceCtrl = TextEditingController(
      text: widget.minPrice?.toString() ?? '',
    );
    _maxPriceCtrl = TextEditingController(
      text: widget.maxPrice?.toString() ?? '',
    );
    _minCostCtrl = TextEditingController(
      text: widget.minCost?.toString() ?? '',
    );
    _maxCostCtrl = TextEditingController(
      text: widget.maxCost?.toString() ?? '',
    );
  }

  @override
  void dispose() {
    _minPriceCtrl.dispose();
    _maxPriceCtrl.dispose();
    _minCostCtrl.dispose();
    _maxCostCtrl.dispose();
    super.dispose();
  }

  double? _parse(String text) {
    final t = text.trim();
    if (t.isEmpty) return null;
    return double.tryParse(t);
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Text(
                'Filtros',
                style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
              ),
              const Spacer(),
              IconButton(
                icon: const Icon(Icons.close),
                onPressed: () => Navigator.of(context).pop(),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _minPriceCtrl,
                  keyboardType: const TextInputType.numberWithOptions(
                    decimal: true,
                  ),
                  decoration: const InputDecoration(labelText: 'Precio minimo'),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: TextField(
                  controller: _maxPriceCtrl,
                  keyboardType: const TextInputType.numberWithOptions(
                    decimal: true,
                  ),
                  decoration: const InputDecoration(labelText: 'Precio maximo'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _minCostCtrl,
                  keyboardType: const TextInputType.numberWithOptions(
                    decimal: true,
                  ),
                  decoration: const InputDecoration(labelText: 'Costo minimo'),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: TextField(
                  controller: _maxCostCtrl,
                  keyboardType: const TextInputType.numberWithOptions(
                    decimal: true,
                  ),
                  decoration: const InputDecoration(labelText: 'Costo maximo'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              onPressed: () {
                widget.onApply(
                  _parse(_minPriceCtrl.text),
                  _parse(_maxPriceCtrl.text),
                  _parse(_minCostCtrl.text),
                  _parse(_maxCostCtrl.text),
                );
                Navigator.of(context).pop();
              },
              icon: const Icon(Icons.check),
              label: const Text('Aplicar'),
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

    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(14),
      splashColor: theme.colorScheme.primary.withAlpha((0.18 * 255).round()),
      highlightColor: theme.colorScheme.primary.withAlpha((0.08 * 255).round()),
      child: Ink(
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(14),
          color: theme.colorScheme.surfaceContainerHighest.withAlpha(
            (0.9 * 255).round(),
          ),
          border: Border.all(
            color: theme.colorScheme.onSurface.withAlpha((0.06 * 255).round()),
          ),
        ),
        child: Stack(
          children: [
            if (hasImage)
              Positioned.fill(
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(14),
                  child: Hero(
                    tag: 'product-image-${product.id}',
                    child: Image.network(
                      product.imageUrl!,
                      fit: BoxFit.cover,
                      errorBuilder: (context, error, stackTrace) => Container(
                        color: theme.colorScheme.surfaceContainerHighest,
                      ),
                    ),
                  ),
                ),
              ),
            if (hasImage)
              Positioned.fill(
                child: DecoratedBox(
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(14),
                    gradient: LinearGradient(
                      colors: [
                        theme.colorScheme.onSurface.withAlpha(
                          (0.40 * 255).round(),
                        ),
                        theme.colorScheme.onSurface.withAlpha(
                          (0.18 * 255).round(),
                        ),
                      ],
                      begin: Alignment.topCenter,
                      end: Alignment.bottomCenter,
                    ),
                  ),
                ),
              ),
            Positioned(
              top: 10,
              left: 10,
              right: 10,
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      product.name,
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                      style: theme.textTheme.titleSmall?.copyWith(
                        color: AppColors.textLight,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ),
                  if (product.isDemo)
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 7,
                        vertical: 3,
                      ),
                      decoration: BoxDecoration(
                        color: AppColors.warning.withAlpha((0.9 * 255).round()),
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: const Text(
                        'DEMO',
                        style: TextStyle(
                          color: AppColors.textLight,
                          fontSize: 11,
                        ),
                      ),
                    ),
                ],
              ),
            ),
            Positioned(
              left: 10,
              bottom: 10,
              right: 10,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    product.code,
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: AppColors.textSecondary,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Wrap(
                    spacing: 8,
                    runSpacing: 4,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    children: [
                      Text(
                        '\$${product.price.toStringAsFixed(2)}',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: theme.textTheme.titleSmall?.copyWith(
                          color: AppColors.textLight,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      Text(
                        'Costo: \$${product.cost.toStringAsFixed(2)}',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: AppColors.textSecondary,
                        ),
                      ),
                      Text(
                        'Stock: ${product.stock.toStringAsFixed(0)}',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        textAlign: TextAlign.end,
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: AppColors.textSecondary,
                        ),
                      ),
                    ],
                  ),
                ],
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
        opaque: false,
        barrierColor: Colors.black.withAlpha((0.88 * 255).round()),
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
    final nameStyle = theme.textTheme.titleLarge?.copyWith(
      fontWeight: FontWeight.w800,
    );

    final moneyStyle = theme.textTheme.titleMedium?.copyWith(
      fontWeight: FontWeight.w800,
    );
    final subtle = theme.colorScheme.onSurface.withAlpha((0.72 * 255).round());

    return Scaffold(
      appBar: AppBar(title: const Text('Detalle de producto')),
      body: SafeArea(
        child: LayoutBuilder(
          builder: (context, constraints) {
            return Column(
              children: [
                Expanded(
                  flex: 3,
                  child: Padding(
                    padding: const EdgeInsets.fromLTRB(16, 16, 16, 10),
                    child: ClipRRect(
                      borderRadius: BorderRadius.circular(18),
                      child: Stack(
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
                                        errorBuilder:
                                            (context, error, stackTrace) =>
                                                Container(
                                                  color: theme
                                                      .colorScheme
                                                      .surfaceContainerHighest,
                                                  child: const Center(
                                                    child: Icon(
                                                      Icons.image_not_supported,
                                                      size: 48,
                                                    ),
                                                  ),
                                                ),
                                      ),
                                    )
                                  : Container(
                                      color: theme
                                          .colorScheme
                                          .surfaceContainerHighest,
                                      child: const Center(
                                        child: Icon(
                                          Icons.image_not_supported,
                                          size: 48,
                                        ),
                                      ),
                                    ),
                            ),
                          ),
                          Positioned(
                            top: 12,
                            right: 12,
                            child: AnimatedScale(
                              duration: const Duration(milliseconds: 120),
                              scale: _downloading ? 0.98 : 1,
                              child: Material(
                                color: Colors.black.withAlpha(
                                  (0.42 * 255).round(),
                                ),
                                borderRadius: BorderRadius.circular(999),
                                child: InkWell(
                                  borderRadius: BorderRadius.circular(999),
                                  onTap: _hasImage
                                      ? _downloadImageToGallery
                                      : null,
                                  child: Padding(
                                    padding: const EdgeInsets.all(10),
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
                          ),
                          Positioned(
                            left: 0,
                            right: 0,
                            bottom: 0,
                            child: Container(
                              padding: const EdgeInsets.fromLTRB(
                                12,
                                20,
                                12,
                                12,
                              ),
                              decoration: BoxDecoration(
                                gradient: LinearGradient(
                                  begin: Alignment.topCenter,
                                  end: Alignment.bottomCenter,
                                  colors: [
                                    Colors.transparent,
                                    Colors.black.withAlpha(
                                      (0.55 * 255).round(),
                                    ),
                                  ],
                                ),
                              ),
                              child: Text(
                                product.code,
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: theme.textTheme.bodyMedium?.copyWith(
                                  color: Colors.white.withAlpha(
                                    (0.9 * 255).round(),
                                  ),
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
                Expanded(
                  flex: 1,
                  child: Padding(
                    padding: const EdgeInsets.fromLTRB(18, 8, 18, 16),
                    child: SingleChildScrollView(
                      physics: const ClampingScrollPhysics(),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          Text(
                            product.name,
                            maxLines: 2,
                            overflow: TextOverflow.ellipsis,
                            style: nameStyle,
                          ),
                          const SizedBox(height: 10),
                          Row(
                            mainAxisAlignment: MainAxisAlignment.spaceBetween,
                            children: [
                              Text(
                                'Precio: \$${product.price.toStringAsFixed(2)}',
                                style: moneyStyle,
                              ),
                              Text(
                                'Costo: \$${product.cost.toStringAsFixed(2)}',
                                style: theme.textTheme.bodyLarge?.copyWith(
                                  color: subtle,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 10),
                          Text(
                            'Stock: ${product.stock.toStringAsFixed(0)}',
                            style: theme.textTheme.bodyMedium?.copyWith(
                              color: subtle,
                            ),
                          ),
                          const SizedBox(height: 10),
                          if (product.description != null &&
                              product.description!.trim().isNotEmpty)
                            Card(
                              margin: EdgeInsets.zero,
                              child: Padding(
                                padding: const EdgeInsets.all(12),
                                child: Text(product.description!.trim()),
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
      backgroundColor: Colors.transparent,
      body: SafeArea(
        child: Stack(
          children: [
            Positioned.fill(
              child: GestureDetector(
                onTap: () => Navigator.of(context).pop(),
                child: Center(
                  child: Hero(
                    tag: 'product-image-$productId',
                    child: InteractiveViewer(
                      minScale: 0.9,
                      maxScale: 4.0,
                      child: ClipRRect(
                        borderRadius: BorderRadius.circular(16),
                        child: Image.network(imageUrl, fit: BoxFit.contain),
                      ),
                    ),
                  ),
                ),
              ),
            ),
            Positioned(
              top: 14,
              left: 14,
              child: Material(
                color: Colors.black.withAlpha((0.45 * 255).round()),
                borderRadius: BorderRadius.circular(999),
                child: InkWell(
                  borderRadius: BorderRadius.circular(999),
                  onTap: () => Navigator.of(context).pop(),
                  child: const Padding(
                    padding: EdgeInsets.all(10),
                    child: Icon(Icons.close, color: Colors.white),
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

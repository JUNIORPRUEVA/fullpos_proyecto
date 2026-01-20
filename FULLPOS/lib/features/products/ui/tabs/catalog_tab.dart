import 'dart:async';

import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../../data/categories_repository.dart';
import '../../data/products_repository.dart';
import '../../data/suppliers_repository.dart';
import '../../models/category_model.dart';
import '../../models/product_model.dart';
import '../../models/supplier_model.dart';
import '../../../../core/constants/app_colors.dart';
import '../../../auth/data/auth_repository.dart';
import '../../../settings/data/user_model.dart';
import '../../utils/products_exporter.dart';
import '../../utils/catalog_pdf_launcher.dart';
import '../dialogs/product_details_dialog.dart';
import '../dialogs/product_filters_dialog.dart';
import '../dialogs/product_form_dialog.dart';
import '../widgets/product_card.dart';

/// Tab de Catálogo de Productos
class CatalogTab extends StatefulWidget {
  const CatalogTab({super.key});

  @override
  State<CatalogTab> createState() => _CatalogTabState();
}

class _CatalogTabState extends State<CatalogTab> {
  final ProductsRepository _productsRepo = ProductsRepository();
  final CategoriesRepository _categoriesRepo = CategoriesRepository();
  final SuppliersRepository _suppliersRepo = SuppliersRepository();

  final TextEditingController _searchController = TextEditingController();
  Timer? _debounce;

  List<ProductModel> _products = [];
  List<CategoryModel> _categories = [];
  List<SupplierModel> _suppliers = [];
  bool _isLoading = false;
  ProductFilters? _currentFilters;

  bool _isAdmin = false;
  UserPermissions _permissions = UserPermissions.cashier();

  Future<void> _exportProductsToExcel() async {
    try {
      final products = await _productsRepo.getAll();
      final file = await ProductsExporter.exportProductsToExcel(
        products: products,
        includePurchasePrice: _isAdmin || _permissions.canViewPurchasePrice,
      );

      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Excel exportado: ${file.path}'),
          backgroundColor: AppColors.success,
        ),
      );
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Error al exportar Excel: $e'),
          backgroundColor: AppColors.error,
        ),
      );
    }
  }

  Future<void> _exportProductsCatalogPdf() async {
    await CatalogPdfLauncher.open(context);
  }

  @override
  void initState() {
    super.initState();
    _loadData();
    _searchController.addListener(_onSearchChanged);
  }

  @override
  void dispose() {
    _searchController.dispose();
    _debounce?.cancel();
    super.dispose();
  }

  void _onSearchChanged() {
    if (_debounce?.isActive ?? false) _debounce!.cancel();
    _debounce = Timer(const Duration(milliseconds: 500), () {
      _loadProducts();
    });
  }

  Future<void> _loadData() async {
    setState(() => _isLoading = true);
    try {
      final permsResults = await Future.wait([
        AuthRepository.getCurrentPermissions(),
        AuthRepository.isAdmin(),
      ]);
      _permissions = permsResults[0] as UserPermissions;
      _isAdmin = permsResults[1] as bool;

      final results = await Future.wait([
        _categoriesRepo.getAll(),
        _suppliersRepo.getAll(),
      ]);

      _categories = results[0] as List<CategoryModel>;
      _suppliers = results[1] as List<SupplierModel>;

      await _loadProducts();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Error al cargar datos: $e')));
      }
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  Future<void> _loadProducts() async {
    try {
      final query = _searchController.text.trim();
      final products = query.isEmpty
          ? await _productsRepo.getAll(filters: _currentFilters)
          : await _productsRepo.search(query, filters: _currentFilters);

      if (mounted) {
        setState(() => _products = products);
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error al cargar productos: $e')),
        );
      }
    }
  }

  Future<void> _showFilters() async {
    final filters = await showDialog<ProductFilters>(
      context: context,
      builder: (context) => ProductFiltersDialog(
        initialFilters: _currentFilters,
        categories: _categories,
        suppliers: _suppliers,
      ),
    );

    if (filters != null) {
      setState(() => _currentFilters = filters);
      _loadProducts();
    }
  }

  Future<void> _showProductForm([ProductModel? product]) async {
    final result = await showDialog<bool>(
      context: context,
      builder: (context) => ProductFormDialog(
        product: product,
        categories: _categories,
        suppliers: _suppliers,
      ),
    );

    if (result == true) {
      _loadProducts();
    }
  }

  void _showProductDetails(ProductModel product) {
    final showPurchasePrice = _isAdmin || _permissions.canViewPurchasePrice;
    final showProfit = _isAdmin || _permissions.canViewProfit;

    showDialog(
      context: context,
      builder: (context) => ProductDetailsDialog(
        product: product,
        categoryName: _getCategoryName(product.categoryId),
        supplierName: _getSupplierName(product.supplierId),
        showPurchasePrice: showPurchasePrice,
        showProfit: showProfit,
      ),
    );
  }

  Future<void> _toggleActive(ProductModel product) async {
    try {
      await _productsRepo.toggleActive(product.id!, !product.isActive);
      _loadProducts();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              product.isActive ? 'Producto desactivado' : 'Producto activado',
            ),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Error: $e')));
      }
    }
  }

  Future<void> _softDelete(ProductModel product) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(
          product.isDeleted ? 'Restaurar Producto' : 'Eliminar Producto',
        ),
        content: Text(
          product.isDeleted
              ? '¿Desea restaurar "${product.name}"?'
              : '¿Está seguro de eliminar "${product.name}"?',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancelar'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(product.isDeleted ? 'Restaurar' : 'Eliminar'),
          ),
        ],
      ),
    );

    if (confirm == true) {
      try {
        if (product.isDeleted) {
          await _productsRepo.restore(product.id!);
        } else {
          await _productsRepo.softDelete(product.id!);
        }
        _loadProducts();
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(
                product.isDeleted
                    ? 'Producto restaurado'
                    : 'Producto eliminado',
              ),
            ),
          );
        }
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(
            context,
          ).showSnackBar(SnackBar(content: Text('Error: $e')));
        }
      }
    }
  }

  String? _getCategoryName(int? categoryId) {
    if (categoryId == null) return null;
    try {
      return _categories.firstWhere((c) => c.id == categoryId).name;
    } catch (_) {
      return null;
    }
  }

  String? _getSupplierName(int? supplierId) {
    if (supplierId == null) return null;
    try {
      return _suppliers.firstWhere((s) => s.id == supplierId).name;
    } catch (_) {
      return null;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        // Barra de búsqueda y filtros
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
          child: Material(
            elevation: 1,
            borderRadius: BorderRadius.circular(12),
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              child: Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _searchController,
                      decoration: InputDecoration(
                        isDense: true,
                        hintText: 'Buscar por codigo o nombre...',
                        prefixIcon: const Icon(Icons.search),
                        suffixIcon: _searchController.text.isNotEmpty
                            ? IconButton(
                                icon: const Icon(Icons.clear),
                                onPressed: () {
                                  _searchController.clear();
                                  _loadProducts();
                                },
                              )
                            : null,
                        border: InputBorder.none,
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  IconButton(
                    icon: Icon(
                      Icons.filter_list,
                      color: _currentFilters?.hasFilters == true
                          ? Colors.blue
                          : null,
                    ),
                    onPressed: _showFilters,
                    tooltip: 'Filtros',
                  ),
                  IconButton(
                    icon: const Icon(Icons.add),
                    onPressed: (_isAdmin || _permissions.canEditProducts)
                        ? () => _showProductForm()
                        : null,
                    tooltip: 'Nuevo Producto',
                  ),
                  IconButton(
                    icon: const Icon(Icons.table_view),
                    onPressed: _exportProductsToExcel,
                    tooltip: 'Exportar a Excel',
                  ),
                  IconButton(
                    icon: const Icon(Icons.picture_as_pdf),
                    onPressed: _exportProductsCatalogPdf,
                    tooltip: 'Catalogo PDF',
                  ),
                ],
              ),
            ),
          ),
        ),
        // Lista de productos
        Expanded(
          child: _isLoading
              ? const Center(child: CircularProgressIndicator())
              : _products.isEmpty
              ? Center(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(
                        Icons.inventory_2_outlined,
                        size: 64,
                        color: Colors.grey[400],
                      ),
                      const SizedBox(height: 16),
                      Text(
                        _searchController.text.isNotEmpty
                            ? 'No se encontraron productos'
                            : 'No hay productos registrados',
                        style: TextStyle(fontSize: 18, color: Colors.grey[600]),
                      ),
                      const SizedBox(height: 8),
                      ElevatedButton.icon(
                        onPressed: (_isAdmin || _permissions.canEditProducts)
                            ? () => _showProductForm()
                            : null,
                        icon: const Icon(Icons.add),
                        label: const Text('Crear Primer Producto'),
                      ),
                    ],
                  ),
                )
              : RefreshIndicator(
                  onRefresh: _loadProducts,
                  child: ListView.builder(
                    itemCount: _products.length,
                    itemBuilder: (context, index) {
                      final product = _products[index];
                      return ProductCard(
                        product: product,
                        categoryName: _getCategoryName(product.categoryId),
                        supplierName: _getSupplierName(product.supplierId),
                        onTap: () => _showProductDetails(product),
                        onEdit: (_isAdmin || _permissions.canEditProducts)
                            ? () => _showProductForm(product)
                            : null,
                        onDelete: (_isAdmin || _permissions.canDeleteProducts)
                            ? () => _softDelete(product)
                            : null,
                        onToggleActive: (_isAdmin || _permissions.canEditProducts)
                            ? () => _toggleActive(product)
                            : null,
                        onAddStock: (_isAdmin || _permissions.canAdjustStock)
                            ? () async {
                          final result = await context.push(
                            '/products/add-stock/${product.id}',
                          );
                          // Si retorna true, significa que se agregó stock
                          if (result == true) {
                            await _loadProducts();
                          }
                        } : null,
                        showPurchasePrice:
                            _isAdmin || _permissions.canViewPurchasePrice,
                        showProfit: _isAdmin || _permissions.canViewProfit,
                      );
                    },
                  ),
                ),
        ),
      ],
    );
  }
}

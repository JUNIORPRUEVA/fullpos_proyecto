import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../data/products_repository.dart';
import '../../models/product_model.dart';
import '../../../auth/data/auth_repository.dart';
import '../../../settings/data/user_model.dart';
import '../dialogs/product_details_dialog.dart';
import '../widgets/kpi_card.dart';
import '../widgets/compact_product_card.dart';

/// Tab de Inventario con KPIs y alertas
class InventoryTab extends StatefulWidget {
  const InventoryTab({super.key});

  @override
  State<InventoryTab> createState() => _InventoryTabState();
}

class _InventoryTabState extends State<InventoryTab> {
  final ProductsRepository _productsRepo = ProductsRepository();

  bool _isLoading = false;
  bool _isAdmin = false;
  UserPermissions _permissions = UserPermissions.cashier();
  double _totalInventoryValue = 0;
  double _totalPotentialRevenue = 0;
  double _totalPotentialProfit = 0;
  int _lowStockCount = 0;
  int _outOfStockCount = 0;
  List<ProductModel> _lowStockProducts = [];
  List<ProductModel> _outOfStockProducts = [];

  @override
  void initState() {
    super.initState();
    Future.microtask(() async {
      await _loadPermissions();
      await _loadInventoryData();
    });
  }

  Future<void> _loadPermissions() async {
    final permissions = await AuthRepository.getCurrentPermissions();
    final isAdmin = await AuthRepository.isAdmin();
    if (mounted) {
      setState(() {
        _permissions = permissions;
        _isAdmin = isAdmin;
      });
    }
  }

  Future<void> _loadInventoryData() async {
    setState(() => _isLoading = true);
    try {
      final results = await Future.wait([
        _productsRepo.calculateTotalInventoryValue(),
        _productsRepo.calculateTotalPotentialRevenue(),
        _productsRepo.calculateTotalPotentialProfit(),
        _productsRepo.getLowStock(),
        _productsRepo.getOutOfStock(),
      ]);

      _totalInventoryValue = results[0] as double;
      _totalPotentialRevenue = results[1] as double;
      _totalPotentialProfit = results[2] as double;
      _lowStockProducts = results[3] as List<ProductModel>;
      _outOfStockProducts = results[4] as List<ProductModel>;
      _lowStockCount = _lowStockProducts.length;
      _outOfStockCount = _outOfStockProducts.length;
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error al cargar inventario: $e')),
        );
      }
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  void _showLowStockDetails() {
    final showPurchasePrice = _isAdmin || _permissions.canViewPurchasePrice;
    final showProfit = _isAdmin || _permissions.canViewProfit;
    final canAdjustStock = _isAdmin || _permissions.canAdjustStock;

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (context) => DraggableScrollableSheet(
        initialChildSize: 0.7,
        maxChildSize: 0.9,
        minChildSize: 0.5,
        expand: false,
        builder: (context, scrollController) => Column(
          children: [
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.orange[50],
                borderRadius: const BorderRadius.vertical(
                  top: Radius.circular(20),
                ),
              ),
              child: Row(
                children: [
                  const Icon(Icons.warning, color: Colors.orange, size: 32),
                  const SizedBox(width: 12),
                  const Text(
                    'Productos con Stock Bajo',
                    style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
                  ),
                  const Spacer(),
                  IconButton(
                    icon: const Icon(Icons.close),
                    onPressed: () => Navigator.pop(context),
                  ),
                ],
              ),
            ),
            Expanded(
              child: ListView.builder(
                controller: scrollController,
                itemCount: _lowStockProducts.length,
                itemBuilder: (context, index) {
                  final product = _lowStockProducts[index];
                  return CompactProductCard(
                    product: product,
                    onTap: () {
                      Navigator.pop(context);
                      _showProductDetails(product);
                    },
                    onAddStockTap: canAdjustStock ? () async {
                      Navigator.pop(context);
                      final result = await context.push(
                        '/products/add-stock/${product.id}',
                      );
                      // Si retorna true, recargar datos
                      if (result == true && mounted) {
                        await _loadInventoryData();
                      }
                    } : null,
                    showPurchasePrice: showPurchasePrice,
                    showProfit: showProfit,
                  );
                },
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _showOutOfStockDetails() {
    final showPurchasePrice = _isAdmin || _permissions.canViewPurchasePrice;
    final showProfit = _isAdmin || _permissions.canViewProfit;
    final canAdjustStock = _isAdmin || _permissions.canAdjustStock;

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (context) => DraggableScrollableSheet(
        initialChildSize: 0.7,
        maxChildSize: 0.9,
        minChildSize: 0.5,
        expand: false,
        builder: (context, scrollController) => Column(
          children: [
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.red[50],
                borderRadius: const BorderRadius.vertical(
                  top: Radius.circular(20),
                ),
              ),
              child: Row(
                children: [
                  const Icon(Icons.error, color: Colors.red, size: 32),
                  const SizedBox(width: 12),
                  const Text(
                    'Productos Agotados',
                    style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
                  ),
                  const Spacer(),
                  IconButton(
                    icon: const Icon(Icons.close),
                    onPressed: () => Navigator.pop(context),
                  ),
                ],
              ),
            ),
            Expanded(
              child: ListView.builder(
                controller: scrollController,
                itemCount: _outOfStockProducts.length,
                itemBuilder: (context, index) {
                  final product = _outOfStockProducts[index];
                  return CompactProductCard(
                    product: product,
                    onTap: () {
                      Navigator.pop(context);
                      _showProductDetails(product);
                    },
                    onAddStockTap: canAdjustStock ? () async {
                      Navigator.pop(context);
                      final result = await context.push(
                        '/products/add-stock/${product.id}',
                      );
                      // Si retorna true, recargar datos
                      if (result == true && mounted) {
                        await _loadInventoryData();
                      }
                    } : null,
                    showPurchasePrice: showPurchasePrice,
                    showProfit: showProfit,
                  );
                },
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _showProductDetails(ProductModel product) {
    final showPurchasePrice = _isAdmin || _permissions.canViewPurchasePrice;
    final showProfit = _isAdmin || _permissions.canViewProfit;

    showDialog(
      context: context,
      builder: (context) => ProductDetailsDialog(
        product: product,
        showPurchasePrice: showPurchasePrice,
        showProfit: showProfit,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final currencyFormat = NumberFormat.currency(
      symbol: '\$',
      decimalDigits: 2,
    );
    final showPurchasePrice = _isAdmin || _permissions.canViewPurchasePrice;
    final showProfit = _isAdmin || _permissions.canViewProfit;

    return RefreshIndicator(
      onRefresh: _loadInventoryData,
      child: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : SingleChildScrollView(
              physics: const AlwaysScrollableScrollPhysics(),
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // KPIs Principales
                  Row(
                    children: [
                      const Text(
                        'Métricas de Inventario',
                        style: TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.w700,
                          letterSpacing: -0.5,
                        ),
                      ),
                      const Spacer(),
                      Text(
                        'Panel de Control',
                        style: TextStyle(fontSize: 12, color: Colors.grey[600]),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  GridView.count(
                    crossAxisCount: 4,
                    shrinkWrap: true,
                    physics: const NeverScrollableScrollPhysics(),
                    crossAxisSpacing: 10,
                    mainAxisSpacing: 10,
                    childAspectRatio: 1.4,
                    children: [
                      KpiCard(
                        title: 'Inversión Total',
                        value: showPurchasePrice
                            ? currencyFormat.format(_totalInventoryValue)
                            : 'Oculto',
                        icon: Icons.account_balance_wallet,
                        color: Colors.blue,
                      ),
                      KpiCard(
                        title: 'Valor de Venta',
                        value: currencyFormat.format(_totalPotentialRevenue),
                        icon: Icons.attach_money,
                        color: Colors.green,
                      ),
                      KpiCard(
                        title: 'Ganancia Potencial',
                        value: showProfit
                            ? currencyFormat.format(_totalPotentialProfit)
                            : 'Oculto',
                        icon: Icons.trending_up,
                        color: Colors.purple,
                      ),
                      KpiCard(
                        title: 'Margen Promedio',
                        value: (showProfit && showPurchasePrice)
                            ? (_totalInventoryValue > 0
                                ? '${((_totalPotentialProfit / _totalInventoryValue) * 100).toStringAsFixed(1)}%'
                                : '0%')
                            : 'Oculto',
                        icon: Icons.percent,
                        color: Colors.teal,
                      ),
                    ],
                  ),

                  const SizedBox(height: 24),

                  // Alertas
                  Row(
                    children: [
                      const Text(
                        'Alertas de Inventario',
                        style: TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.w700,
                          letterSpacing: -0.5,
                        ),
                      ),
                      const Spacer(),
                      Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 8,
                          vertical: 3,
                        ),
                        decoration: BoxDecoration(
                          color: Colors.red[50],
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: Text(
                          '${_lowStockCount + _outOfStockCount} alertas',
                          style: TextStyle(
                            fontSize: 11,
                            fontWeight: FontWeight.w600,
                            color: Colors.red[700],
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      Expanded(
                        child: KpiCard(
                          title: 'Stock Bajo',
                          value: _lowStockCount.toString(),
                          icon: Icons.warning,
                          color: Colors.orange,
                          onTap: _lowStockCount > 0
                              ? _showLowStockDetails
                              : null,
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: KpiCard(
                          title: 'Agotados',
                          value: _outOfStockCount.toString(),
                          icon: Icons.error,
                          color: Colors.red,
                          onTap: _outOfStockCount > 0
                              ? _showOutOfStockDetails
                              : null,
                        ),
                      ),
                    ],
                  ),

                  if (_lowStockCount == 0 && _outOfStockCount == 0) ...[
                    const SizedBox(height: 32),
                    Center(
                      child: Column(
                        children: [
                          Icon(
                            Icons.check_circle,
                            size: 64,
                            color: Colors.green[400],
                          ),
                          const SizedBox(height: 16),
                          Text(
                            '¡Todo bajo control!',
                            style: TextStyle(
                              fontSize: 18,
                              fontWeight: FontWeight.bold,
                              color: Colors.green[700],
                            ),
                          ),
                          const SizedBox(height: 8),
                          Text(
                            'No hay productos con stock bajo o agotados',
                            style: TextStyle(
                              fontSize: 14,
                              color: Colors.grey[600],
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ],
              ),
            ),
    );
  }
}

import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../data/products_repository.dart';
import '../../data/stock_repository.dart';
import '../../models/product_model.dart';
import '../../models/stock_movement_model.dart';
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
  final StockRepository _stockRepo = StockRepository();

  bool _isLoading = false;
  bool _isAdmin = false;
  UserPermissions _permissions = UserPermissions.cashier();
  double _totalInventoryValue = 0;
  double _totalPotentialRevenue = 0;
  double _totalPotentialProfit = 0;
  double _totalUnits = 0;
  int _productCount = 0;
  StockSummary? _stockSummary;
  int _lowStockCount = 0;
  int _outOfStockCount = 0;
  List<ProductModel> _lowStockProducts = [];
  List<ProductModel> _outOfStockProducts = [];
  List<StockMovementDetail> _recentMovements = [];

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
        _productsRepo.calculateTotalUnits(),
        _productsRepo.countActive(),
        _stockRepo.summarize(),
        _stockRepo.getDetailedHistory(limit: 15),
      ]);

      _totalInventoryValue = results[0] as double;
      _totalPotentialRevenue = results[1] as double;
      _totalPotentialProfit = results[2] as double;
      _lowStockProducts = results[3] as List<ProductModel>;
      _outOfStockProducts = results[4] as List<ProductModel>;
      _totalUnits = results[5] as double;
      _productCount = results[6] as int;
      _stockSummary = results[7] as StockSummary;
      _recentMovements = results[8] as List<StockMovementDetail>;
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
                    onAddStockTap: canAdjustStock
                        ? () async {
                            Navigator.pop(context);
                            final result = await context.push(
                              '/products/add-stock/${product.id}',
                            );
                            // Si retorna true, recargar datos
                            if (result == true && mounted) {
                              await _loadInventoryData();
                            }
                          }
                        : null,
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
                    onAddStockTap: canAdjustStock
                        ? () async {
                            Navigator.pop(context);
                            final result = await context.push(
                              '/products/add-stock/${product.id}',
                            );
                            // Si retorna true, recargar datos
                            if (result == true && mounted) {
                              await _loadInventoryData();
                            }
                          }
                        : null,
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

  void _openHistory() {
    context.push('/products/history');
  }

  Widget _buildMovementTile(
    StockMovementDetail detail,
    NumberFormat numberFormat,
    DateFormat dateFormat,
  ) {
    final movement = detail.movement;
    final isPositive =
        movement.isInput || (movement.isAdjust && movement.quantity >= 0);
    final color = movement.isInput
        ? Colors.green
        : movement.isOutput
        ? Colors.red
        : (movement.quantity >= 0 ? Colors.orange : Colors.deepOrange);
    String qtyLabel;
    if (movement.isAdjust) {
      qtyLabel = movement.quantity > 0
          ? '+${numberFormat.format(movement.quantity)}'
          : numberFormat.format(movement.quantity);
    } else if (movement.isInput) {
      qtyLabel = '+${numberFormat.format(movement.quantity)}';
    } else {
      qtyLabel = '-${numberFormat.format(movement.quantity)}';
    }

    final dateLabel = dateFormat.format(movement.createdAt.toLocal());

    return Card(
      elevation: 0,
      margin: const EdgeInsets.symmetric(vertical: 6),
      child: ListTile(
        leading: CircleAvatar(
          backgroundColor: color.withOpacity(0.15),
          child: Icon(
            movement.isInput
                ? Icons.call_made
                : movement.isOutput
                ? Icons.call_received
                : Icons.tune,
            color: color,
          ),
        ),
        title: Row(
          children: [
            Expanded(
              child: Text(
                detail.productLabel,
                style: const TextStyle(
                  fontWeight: FontWeight.w600,
                  fontSize: 14,
                ),
              ),
            ),
            const SizedBox(width: 8),
            Text(
              qtyLabel,
              style: TextStyle(fontWeight: FontWeight.bold, color: color),
            ),
          ],
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Text(
                  movement.type.label,
                  style: TextStyle(color: color, fontWeight: FontWeight.w600),
                ),
                const SizedBox(width: 8),
                if (detail.productCode != null)
                  Text(
                    'Cód: ${detail.productCode}',
                    style: TextStyle(color: Colors.grey[700]),
                  ),
              ],
            ),
            const SizedBox(height: 4),
            Text(
              '$dateLabel • ${detail.userLabel}',
              style: TextStyle(color: Colors.grey[600], fontSize: 12),
            ),
            if (movement.note?.isNotEmpty ?? false) ...[
              const SizedBox(height: 4),
              Text(
                'Nota: ${movement.note}',
                style: TextStyle(
                  color: Colors.grey[700],
                  fontStyle: FontStyle.italic,
                  fontSize: 12,
                ),
              ),
            ],
          ],
        ),
        trailing: movement.isAdjust
            ? Icon(
                Icons.analytics,
                color: isPositive ? Colors.orange : Colors.deepOrange,
              )
            : null,
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
    final unitsFormat = NumberFormat.decimalPattern();
    final dateFormat = DateFormat('dd/MM/yyyy HH:mm');
    final showPurchasePrice = _isAdmin || _permissions.canViewPurchasePrice;
    final showProfit = _isAdmin || _permissions.canViewProfit;
    final stockSummary = _stockSummary;
    final crossAxisCount = MediaQuery.of(context).size.width >= 1100
        ? 4
        : MediaQuery.of(context).size.width >= 820
        ? 3
        : 2;

    final kpis = <Widget>[
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
      KpiCard(
        title: 'Unidades en Stock',
        value: unitsFormat.format(_totalUnits),
        icon: Icons.inventory_2_outlined,
        color: Colors.indigo,
      ),
      KpiCard(
        title: 'Productos Activos',
        value: _productCount.toString(),
        icon: Icons.checklist_rtl,
        color: Colors.cyan,
      ),
      if (stockSummary != null) ...[
        KpiCard(
          title: 'Entradas registradas',
          value: unitsFormat.format(
            stockSummary.totalInputs +
                (stockSummary.totalAdjustments > 0
                    ? stockSummary.totalAdjustments
                    : 0),
          ),
          icon: Icons.call_made,
          color: Colors.green,
        ),
        KpiCard(
          title: 'Salidas registradas',
          value: unitsFormat.format(stockSummary.totalOutputs),
          icon: Icons.call_received,
          color: Colors.red,
        ),
        KpiCard(
          title: 'Ajustes netos',
          value: stockSummary.totalAdjustments >= 0
              ? '+${unitsFormat.format(stockSummary.totalAdjustments)}'
              : unitsFormat.format(stockSummary.totalAdjustments),
          icon: Icons.tune,
          color: stockSummary.totalAdjustments >= 0
              ? Colors.orange
              : Colors.deepOrange,
        ),
      ],
    ];

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
                    crossAxisCount: crossAxisCount,
                    shrinkWrap: true,
                    physics: const NeverScrollableScrollPhysics(),
                    crossAxisSpacing: 10,
                    mainAxisSpacing: 10,
                    childAspectRatio: 1.4,
                    children: kpis,
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

                  const SizedBox(height: 28),
                  Row(
                    children: [
                      const Text(
                        'Historial Reciente',
                        style: TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.w700,
                          letterSpacing: -0.5,
                        ),
                      ),
                      const Spacer(),
                      if (stockSummary != null)
                        Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 10,
                            vertical: 4,
                          ),
                          decoration: BoxDecoration(
                            color: Colors.blueGrey[50],
                            borderRadius: BorderRadius.circular(20),
                          ),
                          child: Text(
                            '${stockSummary.movementsCount} mov.',
                            style: TextStyle(
                              fontSize: 11,
                              color: Colors.blueGrey[700],
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                      const SizedBox(width: 8),
                      TextButton.icon(
                        onPressed: _openHistory,
                        icon: const Icon(Icons.history),
                        label: const Text('Ver historial completo'),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  if (_recentMovements.isEmpty)
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(24),
                      decoration: BoxDecoration(
                        color: Colors.grey[100],
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: Colors.grey[200]!),
                      ),
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(
                            Icons.history,
                            size: 48,
                            color: Colors.grey[400],
                          ),
                          const SizedBox(height: 8),
                          const Text(
                            'Sin movimientos recientes',
                            style: TextStyle(fontWeight: FontWeight.w600),
                          ),
                          const SizedBox(height: 4),
                          const Text(
                            'Cada entrada, salida o ajuste quedará registrado aquí.',
                            textAlign: TextAlign.center,
                          ),
                        ],
                      ),
                    )
                  else
                    Column(
                      children: _recentMovements
                          .take(10)
                          .map(
                            (m) =>
                                _buildMovementTile(m, unitsFormat, dateFormat),
                          )
                          .toList(),
                    ),
                ],
              ),
            ),
    );
  }
}

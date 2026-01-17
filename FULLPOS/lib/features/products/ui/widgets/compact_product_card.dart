import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../../models/product_model.dart';
import 'product_thumbnail.dart';

/// Tarjeta compacta de producto para inventario (estilo corporativo)
class CompactProductCard extends StatelessWidget {
  final ProductModel product;
  final VoidCallback? onTap;
  final VoidCallback? onAddStockTap;
  final String? categoryName;
  final String? supplierName;
  final bool showPurchasePrice;
  final bool showProfit;

  const CompactProductCard({
    super.key,
    required this.product,
    this.onTap,
    this.onAddStockTap,
    this.categoryName,
    this.supplierName,
    this.showPurchasePrice = true,
    this.showProfit = true,
  });

  @override
  Widget build(BuildContext context) {
    final currencyFormat = NumberFormat.currency(
      symbol: '\$',
      decimalDigits: 2,
    );
    final numberFormat = NumberFormat.decimalPattern();

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 3),
      elevation: 0.5,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(6),
        side: BorderSide(color: Colors.grey[200]!, width: 1),
      ),
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(6),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
          child: Row(
            children: [
              // Indicador de estado (barra lateral)
              Container(
                width: 3,
                height: 40,
                decoration: BoxDecoration(
                  color: _getStatusColor(),
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
              const SizedBox(width: 10),

              ProductThumbnail.fromProduct(
                product,
                size: 44,
                showBorder: false,
                borderRadius: BorderRadius.circular(6),
              ),
              const SizedBox(width: 10),

              // Código del producto
              Container(
                width: 70,
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 3),
                decoration: BoxDecoration(
                  color: Colors.grey[100],
                  borderRadius: BorderRadius.circular(3),
                ),
                child: Text(
                  product.code,
                  style: const TextStyle(
                    fontWeight: FontWeight.w600,
                    fontSize: 10,
                    fontFamily: 'monospace',
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              const SizedBox(width: 10),

              // Nombre del producto
              Expanded(
                flex: 2,
                child: Text(
                  product.name,
                  style: const TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w500,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              const SizedBox(width: 8),

              // Stock
              _buildMiniInfo(
                numberFormat.format(product.stock),
                'Stock',
                _getStockColor(),
              ),
              const SizedBox(width: 8),

              // Valor Inventario (costo)
              if (showPurchasePrice) ...[
                _buildMiniInfo(
                  currencyFormat.format(product.inventoryValue),
                  'Valor',
                  Colors.purple,
                ),
                const SizedBox(width: 8),
              ],

              // Margen
              if (showProfit) ...[
                _buildMiniInfo(
                  '${product.profitPercentage.toStringAsFixed(0)}%',
                  'Margen',
                  product.profit > 0 ? Colors.green : Colors.red,
                ),
                const SizedBox(width: 4),
              ],

              // Icono de estado
              Icon(_getStatusIcon(), size: 16, color: _getStatusColor()),
              const SizedBox(width: 8),

              // Botón de Agregar Stock
              if (onAddStockTap != null)
                SizedBox(
                  width: 36,
                  height: 36,
                  child: IconButton(
                    padding: EdgeInsets.zero,
                    icon: const Icon(Icons.add_circle_outline, size: 20),
                    tooltip: 'Agregar Stock',
                    onPressed: onAddStockTap,
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildMiniInfo(String value, String label, Color color) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.end,
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(
          value,
          style: TextStyle(
            fontSize: 11,
            fontWeight: FontWeight.w700,
            color: color,
          ),
        ),
        Text(label, style: TextStyle(fontSize: 8, color: Colors.grey[600])),
      ],
    );
  }

  Color _getStatusColor() {
    if (product.isDeleted) return Colors.red;
    if (!product.isActive) return Colors.orange;
    if (product.isOutOfStock) return Colors.red;
    if (product.hasLowStock) return Colors.orange;
    return Colors.green;
  }

  Color _getStockColor() {
    if (product.isOutOfStock) return Colors.red;
    if (product.hasLowStock) return Colors.orange;
    return Colors.grey[700]!;
  }

  IconData _getStatusIcon() {
    if (product.isDeleted) return Icons.delete_forever;
    if (!product.isActive) return Icons.pause_circle;
    if (product.isOutOfStock) return Icons.error;
    if (product.hasLowStock) return Icons.warning;
    return Icons.check_circle;
  }
}

import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../../models/product_model.dart';
import 'product_thumbnail.dart';

/// Widget para mostrar una tarjeta de producto
class ProductCard extends StatelessWidget {
  final ProductModel product;
  final VoidCallback? onTap;
  final VoidCallback? onEdit;
  final VoidCallback? onDelete;
  final VoidCallback? onToggleActive;
  final VoidCallback? onAddStock;
  final String? categoryName;
  final String? supplierName;
  final bool showPurchasePrice;
  final bool showProfit;

  const ProductCard({
    super.key,
    required this.product,
    this.onTap,
    this.onEdit,
    this.onDelete,
    this.onToggleActive,
    this.onAddStock,
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
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      elevation: 1,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(8),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          child: Row(
            children: [
              // Imagen del producto (thumbnail)
              ProductThumbnail.fromProduct(
                product,
                size: 48,
                borderRadius: BorderRadius.circular(6),
              ),
              const SizedBox(width: 10),

              // Código del producto - Ancho fijo
              Container(
                width: 80,
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 4),
                decoration: BoxDecoration(
                  color: Colors.grey[200],
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Text(
                  product.code,
                  style: const TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 11,
                    fontFamily: 'monospace',
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              const SizedBox(width: 10),

              // Nombre del producto - Expandible
              Expanded(
                flex: 2,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      product.name,
                      style: const TextStyle(
                        fontSize: 13,
                        fontWeight: FontWeight.w600,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    if (categoryName != null || supplierName != null)
                      Text(
                        [
                          if (categoryName != null) categoryName!,
                          if (supplierName != null) supplierName!,
                        ].join(' • '),
                        style: TextStyle(fontSize: 10, color: Colors.grey[600]),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                  ],
                ),
              ),
              const SizedBox(width: 8),

              // Precio Compra
              if (showPurchasePrice) ...[
                _buildCompactInfo(
                  'Compra',
                  currencyFormat.format(product.purchasePrice),
                  Colors.blue,
                ),
                const SizedBox(width: 6),
              ],

              // Precio Venta
              _buildCompactInfo(
                'Venta',
                currencyFormat.format(product.salePrice),
                Colors.green,
              ),
              const SizedBox(width: 6),

              // Stock
              _buildCompactInfo(
                'Stock',
                '${numberFormat.format(product.stock)}/${numberFormat.format(product.stockMin)}',
                product.isOutOfStock
                    ? Colors.red
                    : product.hasLowStock
                    ? Colors.orange
                    : Colors.grey,
              ),
              const SizedBox(width: 6),

              if (showProfit) ...[
                // Ganancia
                _buildCompactInfo(
                  'Ganancia',
                  currencyFormat.format(product.profit),
                  product.profit > 0 ? Colors.green : Colors.red,
                ),
                const SizedBox(width: 6),

                // Margen
                _buildCompactInfo(
                  'Margen',
                  '${product.profitPercentage.toStringAsFixed(0)}%',
                  product.profit > 0 ? Colors.green : Colors.red,
                ),
                const SizedBox(width: 6),
              ],

              // Valor Inventario
              if (showPurchasePrice) ...[
                _buildCompactInfo(
                  'Val.Inv',
                  currencyFormat.format(product.inventoryValue),
                  Colors.purple,
                ),
                const SizedBox(width: 6),
              ],

              // Ganancia Potencial
              if (showProfit) ...[
                _buildCompactInfo(
                  'Gan.Pot',
                  currencyFormat.format(product.profit * product.stock),
                  Colors.teal,
                ),
                const SizedBox(width: 8),
              ] else ...[
                const SizedBox(width: 8),
              ],

              // Badges y acciones
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  // Badges de estado
                  if (product.isDeleted)
                    _buildMiniBadge('DEL', Colors.red)
                  else if (!product.isActive)
                    _buildMiniBadge('INA', Colors.orange)
                  else if (product.isOutOfStock)
                    _buildMiniBadge('AGO', Colors.red)
                  else if (product.hasLowStock)
                    _buildMiniBadge('BAJ', Colors.orange),

                  // Botones de acción compactos
                  if (onToggleActive != null)
                    IconButton(
                      icon: Icon(
                        product.isActive ? Icons.toggle_on : Icons.toggle_off,
                        size: 20,
                        color: product.isActive ? Colors.green : Colors.grey,
                      ),
                      onPressed: onToggleActive,
                      padding: EdgeInsets.zero,
                      constraints: const BoxConstraints(),
                      tooltip: product.isActive ? 'Desactivar' : 'Activar',
                    ),
                  if (onEdit != null)
                    IconButton(
                      icon: const Icon(
                        Icons.edit,
                        size: 18,
                        color: Colors.blue,
                      ),
                      onPressed: onEdit,
                      padding: const EdgeInsets.all(4),
                      constraints: const BoxConstraints(),
                      tooltip: 'Editar',
                    ),
                  if (onDelete != null)
                    IconButton(
                      icon: Icon(
                        product.isDeleted
                            ? Icons.restore_from_trash
                            : Icons.delete,
                        size: 18,
                        color: product.isDeleted ? Colors.green : Colors.red,
                      ),
                      onPressed: onDelete,
                      padding: const EdgeInsets.all(4),
                      constraints: const BoxConstraints(),
                      tooltip: product.isDeleted ? 'Restaurar' : 'Eliminar',
                    ),
                  if (onAddStock != null && !product.isDeleted)
                    IconButton(
                      icon: const Icon(
                        Icons.add_circle_outline,
                        size: 18,
                        color: Colors.green,
                      ),
                      onPressed: onAddStock,
                      padding: const EdgeInsets.all(4),
                      constraints: const BoxConstraints(),
                      tooltip: 'Agregar Stock',
                    ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildMiniBadge(String label, Color color) {
    return Container(
      margin: const EdgeInsets.only(right: 4),
      padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
      decoration: BoxDecoration(
        color: color.withOpacity(0.15),
        borderRadius: BorderRadius.circular(3),
      ),
      child: Text(
        label,
        style: TextStyle(
          fontSize: 9,
          fontWeight: FontWeight.bold,
          color: color,
        ),
      ),
    );
  }

  Widget _buildCompactInfo(String label, String value, Color color) {
    return SizedBox(
      width: 75,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(label, style: TextStyle(fontSize: 9, color: Colors.grey[600])),
          Text(
            value,
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.bold,
              color: color,
            ),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
        ],
      ),
    );
  }
}

import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../../models/product_model.dart';
import '../widgets/product_thumbnail.dart';

/// Diálogo de detalles completos del producto
class ProductDetailsDialog extends StatelessWidget {
  final ProductModel product;
  final String? categoryName;
  final String? supplierName;
  final bool showPurchasePrice;
  final bool showProfit;

  const ProductDetailsDialog({
    super.key,
    required this.product,
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
    final dateFormat = DateFormat('dd/MM/yyyy HH:mm');

    return Dialog(
      child: Container(
        width: 600,
        padding: const EdgeInsets.all(24),
        child: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              // Header
              Row(
                children: [
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 12,
                      vertical: 6,
                    ),
                    decoration: BoxDecoration(
                      color: Colors.teal[700],
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Text(
                      product.code,
                      style: const TextStyle(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                        fontSize: 16,
                        fontFamily: 'monospace',
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      product.name,
                      style: const TextStyle(
                        fontSize: 20,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                  IconButton(
                    icon: const Icon(Icons.close),
                    onPressed: () => Navigator.pop(context),
                  ),
                ],
              ),
              const SizedBox(height: 8),

              // Badges de estado
              Wrap(
                spacing: 8,
                children: [
                  if (product.isDeleted) _buildBadge('ELIMINADO', Colors.red),
                  if (!product.isActive && !product.isDeleted)
                    _buildBadge('INACTIVO', Colors.orange),
                  if (product.isOutOfStock && product.isActive)
                    _buildBadge('AGOTADO', Colors.red),
                  if (product.hasLowStock && product.isActive)
                    _buildBadge('STOCK BAJO', Colors.orange),
                ],
              ),
              const Divider(height: 32),

              // Imagen del producto
              _buildSection(
                'Imagen',
                [
                  SizedBox(
                    height: 220,
                    width: double.infinity,
                    child: ProductThumbnail.fromProduct(
                      product,
                      width: double.infinity,
                      height: 220,
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                ],
              ),

              // Información general
              _buildSection('Información General', [
                if (categoryName != null)
                  _buildInfoRow('Categoría', categoryName!, Icons.category),
                if (supplierName != null)
                  _buildInfoRow('Suplidor', supplierName!, Icons.business),
              ]),

              // Precios
              _buildSection('Precios y Finanzas', [
                if (showPurchasePrice)
                  _buildInfoRow(
                    'Precio de Compra',
                    currencyFormat.format(product.purchasePrice),
                    Icons.shopping_cart,
                    valueColor: Colors.blue,
                  ),
                _buildInfoRow(
                  'Precio de Venta',
                  currencyFormat.format(product.salePrice),
                  Icons.sell,
                  valueColor: Colors.green,
                ),
                if (showProfit)
                  _buildInfoRow(
                    'Ganancia Unitaria',
                    currencyFormat.format(product.profit),
                    Icons.attach_money,
                    valueColor: product.profit > 0 ? Colors.green : Colors.red,
                  ),
                if (showProfit)
                  _buildInfoRow(
                    'Margen de Ganancia',
                    '${product.profitPercentage.toStringAsFixed(2)}%',
                    Icons.percent,
                    valueColor: product.profit > 0 ? Colors.green : Colors.red,
                  ),
              ]),

              // Inventario
              _buildSection('Inventario', [
                _buildInfoRow(
                  'Stock Actual',
                  numberFormat.format(product.stock),
                  Icons.inventory_2,
                  valueColor: product.isOutOfStock
                      ? Colors.red
                      : product.hasLowStock
                      ? Colors.orange
                      : Colors.grey[700],
                ),
                _buildInfoRow(
                  'Stock Mínimo',
                  numberFormat.format(product.stockMin),
                  Icons.warning_amber,
                  valueColor: Colors.orange,
                ),
                if (showPurchasePrice)
                  _buildInfoRow(
                    'Valor en Inventario',
                    currencyFormat.format(product.inventoryValue),
                    Icons.account_balance_wallet,
                    valueColor: Colors.purple,
                  ),
                if (showProfit)
                  _buildInfoRow(
                    'Ganancia Potencial',
                    currencyFormat.format(product.profit * product.stock),
                    Icons.trending_up,
                    valueColor: Colors.teal,
                  ),
                _buildInfoRow(
                  'Valor de Venta Potencial',
                  currencyFormat.format(product.potentialRevenue),
                  Icons.monetization_on,
                  valueColor: Colors.green[700],
                ),
              ]),

              // Fechas
              _buildSection('Registro', [
                _buildInfoRow(
                  'Fecha de Creación',
                  dateFormat.format(product.createdAt),
                  Icons.calendar_today,
                ),
                _buildInfoRow(
                  'Última Actualización',
                  dateFormat.format(product.updatedAt),
                  Icons.update,
                ),
                if (product.isDeleted && product.deletedAt != null)
                  _buildInfoRow(
                    'Fecha de Eliminación',
                    dateFormat.format(product.deletedAt!),
                    Icons.delete_forever,
                    valueColor: Colors.red,
                  ),
              ]),

              const SizedBox(height: 16),
              // Botón cerrar
              SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  onPressed: () => Navigator.pop(context),
                  style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                  child: const Text('Cerrar'),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildSection(String title, List<Widget> children) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: TextStyle(
            fontSize: 16,
            fontWeight: FontWeight.bold,
            color: Colors.teal[700],
          ),
        ),
        const SizedBox(height: 12),
        ...children,
        const SizedBox(height: 20),
      ],
    );
  }

  Widget _buildInfoRow(
    String label,
    String value,
    IconData icon, {
    Color? valueColor,
  }) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        children: [
          Icon(icon, size: 20, color: Colors.grey[600]),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              label,
              style: TextStyle(fontSize: 14, color: Colors.grey[700]),
            ),
          ),
          Text(
            value,
            style: TextStyle(
              fontSize: 14,
              fontWeight: FontWeight.w600,
              color: valueColor ?? Colors.grey[900],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildBadge(String label, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color),
      ),
      child: Text(
        label,
        style: TextStyle(
          fontSize: 11,
          fontWeight: FontWeight.bold,
          color: color,
        ),
      ),
    );
  }
}

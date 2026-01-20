import 'dart:math' as math;
import 'package:flutter/material.dart';

class InventoryPage extends StatelessWidget {
  const InventoryPage({super.key});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final items = [
      _InventoryItem('Cafe Espresso', 'BEB-001', 120, 1.50, 2.80),
      _InventoryItem('Leche Entera', 'INS-014', 80, 0.70, 1.20),
      _InventoryItem('Azucar', 'INS-033', 60, 0.20, 0.50),
      _InventoryItem('Vasos 12oz', 'INS-078', 200, 0.10, 0.30),
    ];
    final totalUnits = items.fold<int>(0, (sum, i) => sum + i.units);
    final totalCost = items.fold<double>(
      0,
      (sum, i) => sum + (i.units * i.cost),
    );
    final potentialSales = items.fold<double>(
      0,
      (sum, i) => sum + (i.units * i.price),
    );

    return Scaffold(
      appBar: AppBar(title: const Text('Inventario')),
      body: LayoutBuilder(
        builder: (context, constraints) {
          final listHeight = math.max(240.0, constraints.maxHeight - 220);
          return SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: ConstrainedBox(
              constraints: BoxConstraints(minHeight: constraints.maxHeight),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Wrap(
                    spacing: 12,
                    runSpacing: 12,
                    children: [
                      _StatCard(
                        title: 'Inversion',
                        value: '\$${totalCost.toStringAsFixed(2)}',
                        icon: Icons.savings_outlined,
                        color: Colors.tealAccent,
                      ),
                      _StatCard(
                        title: 'Unidades',
                        value: '$totalUnits',
                        icon: Icons.format_list_numbered,
                        color: Colors.lightBlueAccent,
                      ),
                      _StatCard(
                        title: 'Potencial de venta',
                        value: '\$${potentialSales.toStringAsFixed(2)}',
                        icon: Icons.trending_up,
                        color: Colors.orangeAccent,
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  SizedBox(
                    height: listHeight,
                    child: Card(
                      child: ListView.separated(
                        itemCount: items.length,
                        separatorBuilder: (context, index) =>
                            const Divider(height: 1),
                        itemBuilder: (context, index) {
                          final item = items[index];
                          return ListTile(
                            leading: CircleAvatar(
                              backgroundColor: theme.colorScheme.primary
                                  .withAlpha((0.15 * 255).round()),
                              child: Text(item.code.substring(0, 2)),
                            ),
                            title: Text(item.name),
                            subtitle: Text(
                              'Codigo: ${item.code}\nUnidades: ${item.units}',
                            ),
                            trailing: Column(
                              mainAxisAlignment: MainAxisAlignment.center,
                              crossAxisAlignment: CrossAxisAlignment.end,
                              children: [
                                Text('Costo: \$${item.cost.toStringAsFixed(2)}'),
                                Text(
                                  'Precio: \$${item.price.toStringAsFixed(2)}',
                                  style: TextStyle(
                                    color: theme.colorScheme.primary,
                                  ),
                                ),
                              ],
                            ),
                          );
                        },
                      ),
                    ),
                  ),
                ],
              ),
            ),
          );
        },
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
  });

  final String title;
  final String value;
  final IconData icon;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: 200,
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(14),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(icon, color: color),
              const SizedBox(height: 10),
              Text(title, style: Theme.of(context).textTheme.bodyMedium),
              const SizedBox(height: 4),
              Text(
                value,
                style: Theme.of(
                  context,
                ).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.bold),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _InventoryItem {
  _InventoryItem(this.name, this.code, this.units, this.cost, this.price);
  final String name;
  final String code;
  final int units;
  final double cost;
  final double price;
}

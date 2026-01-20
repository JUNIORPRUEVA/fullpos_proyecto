import 'dart:math' as math;
import 'package:flutter/material.dart';

class QuotesPage extends StatelessWidget {
  const QuotesPage({super.key});

  @override
  Widget build(BuildContext context) {
    final quotes = [
      _Quote(
        'Q-1023',
        'Juan Perez',
        320.50,
        DateTime.now().subtract(const Duration(days: 1)),
        'Enviada',
      ),
      _Quote(
        'Q-1022',
        'Cafe Central',
        185.00,
        DateTime.now().subtract(const Duration(days: 2)),
        'Aprobada',
      ),
      _Quote(
        'Q-1021',
        'Maria Sosa',
        90.75,
        DateTime.now().subtract(const Duration(days: 3)),
        'Pendiente',
      ),
    ];

    return Scaffold(
      appBar: AppBar(title: const Text('Cotizaciones')),
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
                      _Metric(
                        title: 'Total cotizado',
                        value:
                            '\$${quotes.fold<double>(0, (s, q) => s + q.total).toStringAsFixed(2)}',
                        icon: Icons.request_page_outlined,
                        color: Colors.lightBlueAccent,
                      ),
                      _Metric(
                        title: 'Pendientes',
                        value: quotes
                            .where((q) => q.status == 'Pendiente')
                            .length
                            .toString(),
                        icon: Icons.timelapse_outlined,
                        color: Colors.orangeAccent,
                      ),
                      _Metric(
                        title: 'Aprobadas',
                        value: quotes
                            .where((q) => q.status == 'Aprobada')
                            .length
                            .toString(),
                        icon: Icons.verified_outlined,
                        color: Colors.tealAccent,
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  SizedBox(
                    height: listHeight,
                    child: Card(
                      child: ListView.separated(
                        itemCount: quotes.length,
                        separatorBuilder: (context, index) =>
                            const Divider(height: 1),
                        itemBuilder: (context, index) {
                          final q = quotes[index];
                          return ListTile(
                            leading: CircleAvatar(
                              backgroundColor: Theme.of(context)
                                  .colorScheme
                                  .primary
                                  .withAlpha((0.14 * 255).round()),
                              child: Text(q.code.replaceAll('Q-', '')),
                            ),
                            title: Text('${q.code} - ${q.client}'),
                            subtitle: Text(
                              'Fecha: ${q.date.toLocal().toIso8601String().split('T').first}\nEstado: ${q.status}',
                            ),
                            trailing: Text('\$${q.total.toStringAsFixed(2)}'),
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

class _Metric extends StatelessWidget {
  const _Metric({
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

class _Quote {
  _Quote(this.code, this.client, this.total, this.date, this.status);
  final String code;
  final String client;
  final double total;
  final DateTime date;
  final String status;
}

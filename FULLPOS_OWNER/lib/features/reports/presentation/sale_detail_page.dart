import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';

import '../data/report_models.dart';
import '../data/reports_repository.dart';
import '../data/sale_realtime_service.dart';

class SaleDetailPage extends ConsumerStatefulWidget {
  const SaleDetailPage({super.key, required this.id});

  final int id;

  @override
  ConsumerState<SaleDetailPage> createState() => _SaleDetailPageState();
}

class _SaleDetailPageState extends ConsumerState<SaleDetailPage> {
  StreamSubscription<SaleRealtimeMessage>? _saleRealtimeSubscription;
  SaleDetail? _detail;
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _saleRealtimeSubscription = ref
        .read(saleRealtimeServiceProvider)
        .stream
        .listen((message) {
          final eventSaleId = int.tryParse(message.sale['id']?.toString() ?? '');
          if (eventSaleId == widget.id) {
            _load();
          }
        });
    _load();
  }

  @override
  void dispose() {
    _saleRealtimeSubscription?.cancel();
    super.dispose();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });

    try {
      final detail = await ref.read(reportsRepositoryProvider).saleDetail(widget.id);
      if (!mounted) return;
      setState(() {
        _detail = detail;
        _loading = false;
      });
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _error = 'Error cargando factura';
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final number = NumberFormat.currency(locale: 'es_DO', symbol: '\$');
    final dateFmt = DateFormat('yyyy-MM-dd HH:mm');

    if (_loading) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    if (_error != null) {
      return Scaffold(
        appBar: AppBar(title: Text('Factura #${widget.id}')),
        body: Center(child: Text(_error!)),
      );
    }
    if (_detail == null) {
      return Scaffold(
        appBar: AppBar(title: Text('Factura #${widget.id}')),
        body: const Center(child: Text('Sin datos')),
      );
    }

    final detail = _detail!;

    return Scaffold(
      appBar: AppBar(title: Text(detail.localCode)),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Wrap(
                spacing: 12,
                runSpacing: 12,
                children: [
                  _InfoChip('Estado', detail.status),
                  _InfoChip('Tipo', detail.kind),
                  _InfoChip('Pago', detail.paymentMethod ?? 'N/D'),
                  _InfoChip('Total', number.format(detail.total)),
                  _InfoChip('Costo', number.format(detail.totalCost)),
                  _InfoChip('Ganancia', number.format(detail.profit)),
                  if (detail.createdAt != null)
                    _InfoChip('Fecha', dateFmt.format(detail.createdAt!)),
                  if ((detail.sessionStatus ?? '').isNotEmpty)
                    _InfoChip('Corte', detail.sessionStatus!),
                  if ((detail.ncfFull ?? '').isNotEmpty)
                    _InfoChip('NCF', detail.ncfFull!),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Cliente y resumen',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 10),
                  _DetailRow('Cliente', detail.customerName ?? 'Consumidor final'),
                  _DetailRow('Telefono', detail.customerPhone ?? 'N/D'),
                  _DetailRow('RNC', detail.customerRnc ?? 'N/D'),
                  _DetailRow(
                    'Vendedor',
                    detail.user?.displayName ?? detail.user?.username ?? 'N/D',
                  ),
                  _DetailRow('Subtotal', number.format(detail.subtotal ?? 0)),
                  _DetailRow('Descuento', number.format(detail.discountTotal ?? 0)),
                  _DetailRow('ITBIS', number.format(detail.itbisAmount ?? 0)),
                  _DetailRow('Pagado', number.format(detail.paidAmount ?? 0)),
                  _DetailRow('Cambio', number.format(detail.changeAmount ?? 0)),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Lineas de venta',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 12),
                  ...detail.items.map(
                    (item) => Container(
                      margin: const EdgeInsets.only(bottom: 10),
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(12),
                        color: Theme.of(context).colorScheme.surfaceContainerHighest,
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            item.productNameSnapshot,
                            style: Theme.of(context).textTheme.titleSmall,
                          ),
                          const SizedBox(height: 4),
                          if ((item.productCodeSnapshot ?? '').isNotEmpty)
                            Text('Codigo: ${item.productCodeSnapshot}'),
                          const SizedBox(height: 8),
                          Wrap(
                            spacing: 12,
                            runSpacing: 8,
                            children: [
                              _InfoChip('Cant.', item.qty.toStringAsFixed(2)),
                              _InfoChip('Precio', number.format(item.unitPrice)),
                              _InfoChip(
                                'Costo',
                                number.format(item.purchasePriceSnapshot),
                              ),
                              _InfoChip(
                                'Desc.',
                                number.format(item.discountLine),
                              ),
                              _InfoChip('Linea', number.format(item.totalLine)),
                              _InfoChip('Ganancia', number.format(item.lineProfit)),
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
      ),
    );
  }
}

class _InfoChip extends StatelessWidget {
  const _InfoChip(this.label, this.value);

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            label,
            style: Theme.of(context).textTheme.labelMedium,
          ),
          const SizedBox(height: 2),
          Text(value, style: Theme.of(context).textTheme.titleSmall),
        ],
      ),
    );
  }
}

class _DetailRow extends StatelessWidget {
  const _DetailRow(this.label, this.value);

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 110,
            child: Text(
              label,
              style: Theme.of(context).textTheme.labelLarge,
            ),
          ),
          Expanded(child: Text(value)),
        ],
      ),
    );
  }
}
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';

import '../../../core/providers/sync_request_provider.dart';
import '../../../core/utils/accounting_format.dart';
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
          final eventSaleId = int.tryParse(
            message.sale['id']?.toString() ?? '',
          );
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
      final detail = await ref
          .read(reportsRepositoryProvider)
          .saleDetail(widget.id);
      if (!mounted) return;
      setState(() {
        _detail = detail;
        _loading = false;
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _error = 'Error cargando factura';
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    ref.listen<SyncRequest>(syncRequestProvider, (previous, next) {
      if (previous?.revision == next.revision) return;
      if (!next.appliesTo('/sales/detail')) return;
      unawaited(_load());
    });

    final dateFormat = DateFormat('dd/MM/yyyy hh:mm a');

    if (_loading) {
      return const Center(child: CircularProgressIndicator());
    }

    if (_error != null) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(_error!),
            const SizedBox(height: 10),
            OutlinedButton(onPressed: _load, child: const Text('Reintentar')),
          ],
        ),
      );
    }

    final detail = _detail;
    if (detail == null) {
      return const Center(child: Text('Sin datos de la factura.'));
    }

    final cashier = _normalizeText(detail.cashierName);
    final customer = _normalizeText(detail.customerName);
    final paymentMethod = _translatePaymentMethod(detail.paymentMethod);
    final status = _translateSaleStatus(detail.status);
    final type = _translateSaleType(detail.kind);

    return Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 760),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Expanded(
              child: SingleChildScrollView(
                padding: const EdgeInsets.fromLTRB(0, 4, 0, 12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    _TicketHero(
                      localCode: detail.localCode,
                      status: status,
                      paymentMethod: paymentMethod,
                      createdAt: detail.createdAt == null
                          ? 'Fecha no disponible'
                          : dateFormat.format(detail.createdAt!),
                    ),
                    const SizedBox(height: 12),
                    _TicketSection(
                      title: 'Cliente y venta',
                      child: Column(
                        children: [
                          if (customer != null)
                            _TicketRow(label: 'Cliente', value: customer),
                          if (cashier != null)
                            _TicketRow(label: 'Cajero', value: cashier),
                          _TicketRow(label: 'Pago', value: paymentMethod),
                          _TicketRow(label: 'Tipo', value: type),
                          if ((detail.customerPhone ?? '').trim().isNotEmpty)
                            _TicketRow(
                              label: 'Telefono',
                              value: detail.customerPhone!.trim(),
                            ),
                          if ((detail.customerRnc ?? '').trim().isNotEmpty)
                            _TicketRow(
                              label: 'RNC',
                              value: detail.customerRnc!.trim(),
                            ),
                          if ((detail.ncfFull ?? '').trim().isNotEmpty)
                            _TicketRow(
                              label: 'NCF',
                              value: detail.ncfFull!.trim(),
                            ),
                          if (detail.sessionId != null)
                            _TicketRow(
                              label: 'Sesion',
                              value: detail.sessionId.toString(),
                            ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 12),
                    _TicketSection(
                      title: 'Productos',
                      child: Column(
                        children: [
                          for (final item in detail.items)
                            _TicketItemRow(item: item),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 12),
            _FixedTotalsPanel(detail: detail),
          ],
        ),
      ),
    );
  }
}

class _TicketHero extends StatelessWidget {
  const _TicketHero({
    required this.localCode,
    required this.status,
    required this.paymentMethod,
    required this.createdAt,
  });

  final String localCode;
  final String status;
  final String paymentMethod;
  final String createdAt;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(28),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Ticket de venta',
            style: theme.textTheme.labelLarge?.copyWith(
              color: theme.colorScheme.primary,
              fontWeight: FontWeight.w800,
            ),
          ),
          const SizedBox(height: 10),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              _HeroBadge(label: localCode),
              _HeroBadge(label: status),
              _HeroBadge(label: paymentMethod),
              _HeroBadge(label: createdAt),
            ],
          ),
        ],
      ),
    );
  }
}

class _FixedTotalsPanel extends StatelessWidget {
  const _FixedTotalsPanel({required this.detail});

  final SaleDetail detail;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(24)),
        border: Border.all(color: theme.colorScheme.outlineVariant),
        boxShadow: [
          BoxShadow(
            color: theme.colorScheme.shadow.withValues(alpha: 0.08),
            blurRadius: 18,
            offset: const Offset(0, -4),
          ),
        ],
      ),
      child: SafeArea(
        top: false,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Totales',
              style: theme.textTheme.titleMedium?.copyWith(
                fontWeight: FontWeight.w800,
              ),
            ),
            const SizedBox(height: 12),
            _TicketRow(
              label: 'Subtotal',
              value: formatAccountingAmount(detail.subtotal ?? 0),
            ),
            _TicketRow(
              label: 'Descuento',
              value: formatAccountingAmount(detail.discountTotal ?? 0),
            ),
            _TicketRow(
              label: 'ITBIS',
              value: formatAccountingAmount(detail.itbisAmount ?? 0),
            ),
            _TicketRow(
              label: 'Costo',
              value: formatAccountingAmount(detail.totalCost),
            ),
            _TicketRow(
              label: 'Ganancia',
              value: formatAccountingAmount(detail.profit),
            ),
            _TicketRow(
              label: 'Pagado',
              value: formatAccountingAmount(detail.paidAmount ?? 0),
              emphasized: true,
            ),
            _TicketRow(
              label: 'Cambio',
              value: formatAccountingAmount(detail.changeAmount ?? 0),
            ),
            _TicketRow(
              label: 'Total final',
              value: formatAccountingAmount(detail.total),
              emphasized: true,
            ),
          ],
        ),
      ),
    );
  }
}

class _HeroBadge extends StatelessWidget {
  const _HeroBadge({required this.label});

  final String label;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(999),
      ),
      child: Text(
        label,
        style: theme.textTheme.bodySmall?.copyWith(fontWeight: FontWeight.w700),
      ),
    );
  }
}

class _TicketSection extends StatelessWidget {
  const _TicketSection({required this.title, required this.child});

  final String title;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(24),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: theme.textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.w800,
            ),
          ),
          const SizedBox(height: 12),
          child,
        ],
      ),
    );
  }
}

class _TicketRow extends StatelessWidget {
  const _TicketRow({
    required this.label,
    required this.value,
    this.emphasized = false,
  });

  final String label;
  final String value;
  final bool emphasized;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 108,
            child: Text(
              label,
              style: theme.textTheme.labelLarge?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              textAlign: TextAlign.right,
              style: theme.textTheme.bodyLarge?.copyWith(
                fontWeight: emphasized ? FontWeight.w900 : FontWeight.w700,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _TicketItemRow extends StatelessWidget {
  const _TicketItemRow({required this.item});

  final SaleDetailItem item;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  item.productNameSnapshot,
                  style: theme.textTheme.titleSmall?.copyWith(
                    fontWeight: FontWeight.w800,
                  ),
                ),
              ),
              const SizedBox(width: 10),
              Text(
                formatAccountingAmount(item.totalLine),
                style: theme.textTheme.titleSmall?.copyWith(
                  fontWeight: FontWeight.w900,
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          Text(
            '${item.qty.toStringAsFixed(2)} x ${formatAccountingAmount(item.unitPrice)}',
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          if ((item.productCodeSnapshot ?? '').trim().isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(top: 2),
              child: Text(
                'Codigo: ${item.productCodeSnapshot!.trim()}',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ),
        ],
      ),
    );
  }
}

String? _normalizeText(String? value) {
  final normalized = value?.trim();
  if (normalized == null || normalized.isEmpty) {
    return null;
  }
  return normalized;
}

String _translatePaymentMethod(String? value) {
  switch (value?.trim().toLowerCase()) {
    case 'cash':
    case 'efectivo':
      return 'Efectivo';
    case 'card':
    case 'tarjeta':
      return 'Tarjeta';
    case 'transfer':
    case 'transferencia':
      return 'Transferencia';
    case 'mixed':
    case 'mixto':
      return 'Mixto';
    case 'credit':
    case 'credito':
      return 'Crédito';
    default:
      return _normalizeText(value) ?? 'No especificado';
  }
}

String _translateSaleStatus(String value) {
  switch (value.trim().toLowerCase()) {
    case 'completed':
    case 'complete':
      return 'Completado';
    case 'pending':
      return 'Pendiente';
    case 'cancelled':
    case 'canceled':
      return 'Cancelado';
    case 'draft':
      return 'Borrador';
    default:
      return _capitalizeWords(value);
  }
}

String _translateSaleType(String value) {
  switch (value.trim().toLowerCase()) {
    case 'invoice':
      return 'Factura';
    case 'sale':
      return 'Venta';
    case 'quote':
      return 'Cotización';
    case 'order':
      return 'Pedido';
    default:
      return _capitalizeWords(value);
  }
}

String _capitalizeWords(String value) {
  final trimmed = value.trim();
  if (trimmed.isEmpty) {
    return value;
  }

  return trimmed
      .split(RegExp(r'[_\-\s]+'))
      .where((part) => part.isNotEmpty)
      .map(
        (part) => '${part[0].toUpperCase()}${part.substring(1).toLowerCase()}',
      )
      .join(' ');
}

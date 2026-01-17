import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../../core/constants/app_colors.dart';
import '../../../core/constants/app_sizes.dart';
import '../../../core/errors/error_handler.dart';
import '../data/purchases_repository.dart';
import '../data/purchase_order_models.dart';

class PurchaseOrdersListPage extends StatefulWidget {
  const PurchaseOrdersListPage({super.key});

  @override
  State<PurchaseOrdersListPage> createState() => _PurchaseOrdersListPageState();
}

class _PurchaseOrdersListPageState extends State<PurchaseOrdersListPage> {
  final PurchasesRepository _repo = PurchasesRepository();

  bool _loading = true;
  String? _error;
  List<PurchaseOrderSummaryDto> _orders = const [];

  Future<void> _deleteOrder(int orderId) async {
    try {
      await _repo.deleteOrder(orderId);
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Orden eliminada')));
      await _load();
    } catch (e, st) {
      if (!mounted) return;
      await ErrorHandler.instance.handle(
        e,
        stackTrace: st,
        context: context,
        onRetry: () => _deleteOrder(orderId),
        module: 'purchases/delete',
      );
    }
  }

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });

    try {
      final data = await _repo.listOrders();
      if (!mounted) return;
      setState(() {
        _orders = data;
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  Future<void> _confirmAndDelete(int orderId) async {
    final shouldDelete = await showDialog<bool>(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text('Eliminar orden'),
          content: const Text(
            '¿Seguro que deseas eliminar esta orden de compra? Esta acción no se puede deshacer.',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(false),
              child: const Text('Cancelar'),
            ),
            FilledButton(
              onPressed: () => Navigator.of(context).pop(true),
              child: const Text('Eliminar'),
            ),
          ],
        );
      },
    );

    if (shouldDelete != true) return;

    await _deleteOrder(orderId);
  }

  @override
  Widget build(BuildContext context) {
    final dateFormat = DateFormat('dd/MM/yyyy HH:mm');
    final currency = NumberFormat('#,##0.00', 'en_US');

    return Scaffold(
      backgroundColor: AppColors.bgLight,
      appBar: AppBar(
        title: const Text(
          'Órdenes de Compra',
          style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600),
        ),
        toolbarHeight: 48,
        actions: [
          TextButton(
            onPressed: () => context.go('/purchases/new'),
            child: const Text('Crear manual'),
          ),
          const SizedBox(width: 8),
          TextButton(
            onPressed: () => context.go('/purchases/auto'),
            child: const Text('Stock mínimo'),
          ),
          const SizedBox(width: 8),
        ],
      ),
      body: Padding(
        padding: const EdgeInsets.all(AppSizes.paddingL),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                ElevatedButton.icon(
                  onPressed: _load,
                  icon: const Icon(Icons.refresh, size: 18),
                  label: const Text('Actualizar'),
                ),
                const SizedBox(width: 12),
                Text(
                  'Total: ${_orders.length}',
                  style: TextStyle(color: AppColors.textDarkSecondary),
                ),
              ],
            ),
            const SizedBox(height: AppSizes.paddingM),
            Expanded(
              child: _loading
                  ? const Center(child: CircularProgressIndicator())
                  : _error != null
                  ? Center(
                      child: Text(
                        'Error: $_error',
                        style: const TextStyle(color: Colors.red),
                      ),
                    )
                  : _orders.isEmpty
                  ? Center(
                      child: SingleChildScrollView(
                        child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(
                              Icons.shopping_cart_outlined,
                              size: 72,
                              color: AppColors.textDarkSecondary,
                            ),
                            const SizedBox(height: 16),
                            Text(
                              'No hay órdenes de compra',
                              style: TextStyle(
                                fontSize: 16,
                                fontWeight: FontWeight.w600,
                                color: AppColors.textDarkSecondary,
                              ),
                            ),
                            const SizedBox(height: 8),
                            Text(
                              'Crea una nueva orden para comenzar',
                              style: TextStyle(
                                fontSize: 14,
                                color: AppColors.textDarkSecondary,
                              ),
                            ),
                            const SizedBox(height: 32),
                            FilledButton.icon(
                              onPressed: () => context.go('/purchases/new'),
                              icon: const Icon(Icons.add),
                              label: const Text('Crear Orden Manual'),
                            ),
                            const SizedBox(height: 12),
                            OutlinedButton.icon(
                              onPressed: () => context.go('/purchases/auto'),
                              icon: const Icon(Icons.inventory_2),
                              label: const Text('Crear por Stock Mínimo'),
                            ),
                          ],
                        ),
                      ),
                    )
                  : ListView.separated(
                      itemCount: _orders.length,
                      separatorBuilder: (_, __) => const SizedBox(height: 8),
                      itemBuilder: (context, index) {
                        final o = _orders[index];
                        final order = o.order;
                        final created = DateTime.fromMillisecondsSinceEpoch(
                          order.createdAtMs,
                        );
                        final isReceived =
                            order.status.toUpperCase() == 'RECIBIDA';

                        final orderId = order.id;

                        final statusColor = isReceived
                            ? AppColors.success
                            : AppColors.gold;

                        return Card(
                          elevation: 0,
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(12),
                            side: BorderSide(
                              color: AppColors.surfaceLightBorder,
                            ),
                          ),
                          child: ListTile(
                            contentPadding: const EdgeInsets.symmetric(
                              horizontal: AppSizes.paddingM,
                              vertical: 6,
                            ),
                            leading: CircleAvatar(
                              backgroundColor: statusColor.withOpacity(0.12),
                              foregroundColor: statusColor,
                              child: Icon(
                                isReceived
                                    ? Icons.inventory_2_rounded
                                    : Icons.local_shipping_outlined,
                              ),
                            ),
                            title: Text(
                              'Orden #${order.id ?? '-'} • ${o.supplierName}',
                              style: const TextStyle(
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                            subtitle: Text(
                              '${dateFormat.format(created)} • ${order.status} • Total: ${currency.format(order.total)}',
                              style: TextStyle(
                                color: AppColors.textDarkSecondary,
                              ),
                            ),
                            trailing: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                PopupMenuButton<String>(
                                  tooltip: 'Acciones',
                                  onSelected: (value) async {
                                    if (orderId == null) return;
                                    switch (value) {
                                      case 'details':
                                        context.go(
                                          '/purchases/receive/$orderId',
                                        );
                                        break;
                                      case 'edit':
                                        context.go('/purchases/edit/$orderId');
                                        break;
                                      case 'delete':
                                        await _confirmAndDelete(orderId);
                                        break;
                                    }
                                  },
                                  itemBuilder: (context) {
                                    return [
                                      const PopupMenuItem<String>(
                                        value: 'details',
                                        child: Text('Ver detalle'),
                                      ),
                                      PopupMenuItem<String>(
                                        value: 'edit',
                                        enabled: !isReceived,
                                        child: const Text('Editar'),
                                      ),
                                      PopupMenuItem<String>(
                                        value: 'delete',
                                        enabled: !isReceived,
                                        child: const Text('Eliminar'),
                                      ),
                                    ];
                                  },
                                ),
                                const Icon(Icons.chevron_right),
                              ],
                            ),
                            onTap: () async {
                              context.go('/purchases/receive/${order.id}');
                            },
                          ),
                        );
                      },
                    ),
            ),
          ],
        ),
      ),
    );
  }
}

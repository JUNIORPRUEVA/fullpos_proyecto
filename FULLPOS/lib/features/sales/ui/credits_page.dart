import 'package:flutter/material.dart';
import '../data/credits_repository.dart';
import '../../../core/errors/error_handler.dart';

class CreditsPage extends StatefulWidget {
  const CreditsPage({Key? key}) : super(key: key);

  @override
  State<CreditsPage> createState() => _CreditsPageState();
}

class _CreditsPageState extends State<CreditsPage> with SingleTickerProviderStateMixin {
  late TabController _tabController;
  bool _loading = true;
  List<Map<String, dynamic>> _creditsByClient = [];
  List<Map<String, dynamic>> _creditSales = [];

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _loadCredits();
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _loadCredits() async {
    setState(() => _loading = true);
    try {
      final byClient = await CreditsRepository.getCreditSummaryByClient();
      final sales = await CreditsRepository.listCreditSales();

      setState(() {
        _creditsByClient = byClient;
        _creditSales = sales;
      });
    } catch (e, st) {
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: _loadCredits,
          module: 'sales/credits/load',
        );
      }
    } finally {
      setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Gestión de Créditos'),
        elevation: 0,
        bottom: TabBar(
          controller: _tabController,
          tabs: const [
            Tab(text: 'Por Cliente'),
            Tab(text: 'Ventas a Crédito'),
          ],
        ),
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : TabBarView(
        controller: _tabController,
        children: [
          // Tab 1: Por Cliente
          _buildByClientTab(),
          // Tab 2: Ventas a Crédito
          _buildCreditSalesTab(),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _loadCredits,
        child: const Icon(Icons.refresh),
      ),
    );
  }

  Widget _buildByClientTab() {
    if (_creditsByClient.isEmpty) {
      return const Center(child: Text('No hay créditos'));
    }

    return ListView.builder(
      padding: const EdgeInsets.all(8),
      itemCount: _creditsByClient.length,
      itemBuilder: (context, index) {
        final item = _creditsByClient[index];
        final clientName = item['nombre'] ?? 'S/N';
        final totalPending = (item['total_pending'] as num?)?.toDouble() ?? 0.0;
        final totalAmount = (item['total_amount'] as num?)?.toDouble() ?? 0.0;
        final totalCredits = item['total_credits'] as int? ?? 0;

        return Card(
          margin: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
          child: ListTile(
            leading: const Icon(Icons.person),
            title: Text(clientName, style: const TextStyle(fontWeight: FontWeight.bold)),
            subtitle: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('${totalCredits} créditos'),
                Text('Total: \$${totalAmount.toStringAsFixed(2)}'),
              ],
            ),
            trailing: Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: totalPending > 0 ? Colors.red.withOpacity(0.1) : Colors.green.withOpacity(0.1),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Text(
                '\$${totalPending.toStringAsFixed(2)}',
                style: TextStyle(
                  fontWeight: FontWeight.bold,
                  color: totalPending > 0 ? Colors.red : Colors.green,
                ),
              ),
            ),
            onTap: () {
              // Ver detalles del cliente
            },
          ),
        );
      },
    );
  }

  Widget _buildCreditSalesTab() {
    if (_creditSales.isEmpty) {
      return const Center(child: Text('No hay ventas a crédito'));
    }

    return ListView.builder(
      padding: const EdgeInsets.all(8),
      itemCount: _creditSales.length,
      itemBuilder: (context, index) {
        final sale = _creditSales[index];
        final saleId = sale['id'];
        final localCode = sale['local_code'] ?? 'N/A';
        final clientName = sale['customer_name_snapshot'] ?? 'S/C';
        final total = (sale['total'] as num?)?.toDouble() ?? 0.0;
        final status = sale['status'] ?? 'CREDIT';

        return Card(
          margin: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
          child: ListTile(
            leading: const Icon(Icons.receipt),
            title: Text(localCode, style: const TextStyle(fontWeight: FontWeight.bold)),
            subtitle: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(clientName),
                Text('Total: \$${total.toStringAsFixed(2)}'),
              ],
            ),
            trailing: Chip(
              label: Text(status),
              backgroundColor: status == 'PAID' ? Colors.green : Colors.orange,
              labelStyle: const TextStyle(color: Colors.white),
            ),
            onTap: () {
              _showPaymentDialog(saleId, localCode, clientName, total);
            },
          ),
        );
      },
    );
  }

  void _showPaymentDialog(int saleId, String saleCode, String clientName, double saleTotal) {
    final _amountController = TextEditingController();

    showDialog(
      context: context,
      builder: (context) => Dialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Registrar Abono',
                style: Theme.of(context).textTheme.headlineSmall,
              ),
              const SizedBox(height: 12),
              Text('Venta: $saleCode'),
              Text('Cliente: $clientName'),
              Text('Total: \$${saleTotal.toStringAsFixed(2)}'),
              const SizedBox(height: 20),
              TextField(
                controller: _amountController,
                decoration: InputDecoration(
                  labelText: 'Monto a Abonar',
                  border: OutlineInputBorder(borderRadius: BorderRadius.circular(8)),
                  prefixText: '\$ ',
                ),
                keyboardType: const TextInputType.numberWithOptions(decimal: true),
              ),
              const SizedBox(height: 20),
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  TextButton(
                    onPressed: () => Navigator.pop(context),
                    child: const Text('Cancelar'),
                  ),
                  const SizedBox(width: 8),
                  ElevatedButton(
                    onPressed: () async {
                      final amount = double.tryParse(_amountController.text) ?? 0.0;
                      if (amount <= 0) {
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('Monto inválido')),
                        );
                        return;
                      }

                      try {
                        // TODO: Implementar registro de pago de crédito
                        await CreditsRepository.registerCreditPayment(
                          saleId: saleId,
                          clientId: 0, // Obtener del sale
                          amount: amount,
                          method: 'cash',
                        );

                        if (mounted) {
                          Navigator.pop(context);
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(content: Text('Abono registrado')),
                          );
                          _loadCredits();
                        }
                      } catch (e, st) {
                        if (mounted) {
                          await ErrorHandler.instance.handle(
                            e,
                            stackTrace: st,
                            context: context,
                            onRetry: () => _showPaymentDialog(
                              saleId,
                              saleCode,
                              clientName,
                              saleTotal,
                            ),
                            module: 'sales/credits/payment',
                          );
                        }
                      }
                    },
                    child: const Text('Registrar'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}

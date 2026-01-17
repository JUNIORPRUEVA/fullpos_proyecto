import 'package:flutter/material.dart';
import '../data/cash_model.dart';
import '../data/cash_box_repository.dart';

/// Página principal de gestión de Caja
class CashBoxPage extends StatefulWidget {
  const CashBoxPage({super.key});

  @override
  State<CashBoxPage> createState() => _CashBoxPageState();
}

class _CashBoxPageState extends State<CashBoxPage> {
  CashBoxModel? _currentCashBox;
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadCurrentCashBox();
  }

  Future<void> _loadCurrentCashBox() async {
    final cashBox = await CashBoxRepository.getCurrentOpenCashBox();
    if (mounted) {
      setState(() {
        _currentCashBox = cashBox;
        _isLoading = false;
      });
    }
  }

  void _openCashBoxDialog() {
    final controller = TextEditingController();

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Abrir Caja'),
        content: TextField(
          controller: controller,
          keyboardType: const TextInputType.numberWithOptions(decimal: true),
          decoration: const InputDecoration(
            labelText: 'Saldo Inicial',
            hintText: '0.00',
            prefixText: '\$',
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancelar'),
          ),
          ElevatedButton(
            onPressed: () async {
              final amount = double.tryParse(controller.text) ?? 0.0;
              await CashBoxRepository.openCashBox(openingBalance: amount);
              if (mounted) {
                Navigator.pop(context);
                _loadCurrentCashBox();
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('✓ Caja abierta correctamente')),
                );
              }
            },
            child: const Text('Abrir Caja'),
          ),
        ],
      ),
    );
  }

  void _closeCashBoxDialog() {
    if (_currentCashBox == null) return;

    final amountController = TextEditingController();
    final notesController = TextEditingController();

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Cerrar Caja'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                'Saldo Inicial: \$${_currentCashBox!.openingBalance.toStringAsFixed(2)}',
                style: const TextStyle(fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: amountController,
                keyboardType: const TextInputType.numberWithOptions(decimal: true),
                decoration: const InputDecoration(
                  labelText: 'Saldo Final',
                  hintText: '0.00',
                  prefixText: '\$',
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: notesController,
                maxLines: 3,
                decoration: const InputDecoration(
                  labelText: 'Notas (opcional)',
                  hintText: 'Diferencias, observaciones...',
                  border: OutlineInputBorder(),
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancelar'),
          ),
          ElevatedButton(
            onPressed: () async {
              final closingAmount = double.tryParse(amountController.text) ?? 0.0;
              final notes = notesController.text.isEmpty ? null : notesController.text;

              // Obtener estadísticas para expectedBalance
              final salesTotal = await CashBoxRepository.getCashBoxSalesTotal(
                _currentCashBox!.id,
              );

              await CashBoxRepository.closeCashBox(
                cashBoxId: _currentCashBox!.id,
                closingBalance: closingAmount,
                expectedBalance: salesTotal,
                notes: notes,
              );

              if (mounted) {
                Navigator.pop(context);
                _loadCurrentCashBox();
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('✓ Caja cerrada correctamente')),
                );
              }
            },
            child: const Text('Cerrar Caja'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_isLoading) {
      return const Scaffold(
        body: Center(child: CircularProgressIndicator()),
      );
    }

    return Scaffold(
      appBar: AppBar(
        title: const Text('Gestión de Caja'),
        backgroundColor: const Color(0xFF009688),
      ),
      body: _currentCashBox == null
          ? Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(
                    Icons.store,
                    size: 64,
                    color: Colors.grey.shade400,
                  ),
                  const SizedBox(height: 16),
                  const Text(
                    'No hay caja abierta',
                    style: TextStyle(fontSize: 18, fontWeight: FontWeight.w500),
                  ),
                  const SizedBox(height: 24),
                  ElevatedButton.icon(
                    onPressed: _openCashBoxDialog,
                    icon: const Icon(Icons.add),
                    label: const Text('Abrir Caja'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: const Color(0xFFD4AF37),
                      foregroundColor: Colors.black,
                      padding: const EdgeInsets.symmetric(
                        horizontal: 32,
                        vertical: 12,
                      ),
                    ),
                  ),
                ],
              ),
            )
          : SingleChildScrollView(
              padding: const EdgeInsets.all(16),
              child: Column(
                children: [
                  // Card de caja abierta
                  Card(
                    elevation: 4,
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text(
                            'CAJA ABIERTA',
                            style: TextStyle(
                              fontSize: 12,
                              fontWeight: FontWeight.bold,
                              color: Colors.green,
                              letterSpacing: 1,
                            ),
                          ),
                          const SizedBox(height: 12),
                          Row(
                            mainAxisAlignment: MainAxisAlignment.spaceBetween,
                            children: [
                              Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  const Text(
                                    'Saldo Inicial',
                                    style: TextStyle(color: Colors.grey),
                                  ),
                                  Text(
                                    '\$${_currentCashBox!.openingBalance.toStringAsFixed(2)}',
                                    style: const TextStyle(
                                      fontSize: 20,
                                      fontWeight: FontWeight.bold,
                                      color: Colors.green,
                                    ),
                                  ),
                                ],
                              ),
                              Column(
                                crossAxisAlignment: CrossAxisAlignment.end,
                                children: [
                                  const Text(
                                    'Abierta hace',
                                    style: TextStyle(color: Colors.grey),
                                  ),
                                  Text(
                                    _formatTime(_currentCashBox!.openedAtMs),
                                    style: const TextStyle(
                                      fontSize: 14,
                                      fontWeight: FontWeight.w500,
                                    ),
                                  ),
                                ],
                              ),
                            ],
                          ),
                          const SizedBox(height: 20),
                          ElevatedButton.icon(
                            onPressed: _closeCashBoxDialog,
                            icon: const Icon(Icons.close),
                            label: const Text('Cerrar Caja'),
                            style: ElevatedButton.styleFrom(
                              backgroundColor: Colors.red,
                              foregroundColor: Colors.white,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 24),
                  // Historial de cajas cerradas
                  const Align(
                    alignment: Alignment.centerLeft,
                    child: Text(
                      'Historial de Cajas',
                      style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                  const SizedBox(height: 12),
                  FutureBuilder<List<CashBoxModel>>(
                    future: CashBoxRepository.getCashBoxHistory(),
                    builder: (context, snapshot) {
                      if (snapshot.connectionState == ConnectionState.waiting) {
                        return const CircularProgressIndicator();
                      }

                      if (!snapshot.hasData || snapshot.data!.isEmpty) {
                        return const Text('Sin historial de cajas');
                      }

                      return ListView.builder(
                        shrinkWrap: true,
                        physics: const NeverScrollableScrollPhysics(),
                        itemCount: snapshot.data!.length,
                        itemBuilder: (context, index) {
                          final cashBox = snapshot.data![index];
                          return Card(
                            child: ListTile(
                              leading: Icon(
                                Icons.done_all,
                                color: cashBox.difference.abs() < 0.01
                                    ? Colors.green
                                    : Colors.orange,
                              ),
                              title: Text(
                                'Caja ${index + 1}',
                              ),
                              subtitle: Text(
                                'Diferencia: \$${cashBox.difference.toStringAsFixed(2)}',
                                style: TextStyle(
                                  color: cashBox.difference.abs() < 0.01
                                      ? Colors.green
                                      : Colors.orange,
                                ),
                              ),
                              trailing: Text(
                                _formatDateTime(cashBox.closedAtMs ?? 0),
                              ),
                            ),
                          );
                        },
                      );
                    },
                  ),
                ],
              ),
            ),
    );
  }

  String _formatTime(int ms) {
    final now = DateTime.now().millisecondsSinceEpoch;
    final diff = now - ms;
    final minutes = diff ~/ 60000;
    final hours = minutes ~/ 60;

    if (hours > 0) {
      return '$hours h ${minutes % 60} min';
    }
    return '$minutes min';
  }

  String _formatDateTime(int ms) {
    if (ms == 0) return '';
    final dt = DateTime.fromMillisecondsSinceEpoch(ms);
    return '${dt.day}/${dt.month} ${dt.hour}:${dt.minute.toString().padLeft(2, '0')}';
  }
}

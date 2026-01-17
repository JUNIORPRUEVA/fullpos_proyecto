import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../../../clients/data/client_model.dart';

enum PaymentMethod { cash, card, transfer, mixed, credit }

class PrintAndConfirmPaymentIntent extends Intent {
  const PrintAndConfirmPaymentIntent();
}

/// Diálogo de pago profesional
class PaymentDialog extends StatefulWidget {
  final double total;
  final ClientModel? selectedClient;
  final VoidCallback onSelectClient;

  const PaymentDialog({
    super.key,
    required this.total,
    this.selectedClient,
    required this.onSelectClient,
  });

  @override
  State<PaymentDialog> createState() => _PaymentDialogState();
}

class _PaymentDialogState extends State<PaymentDialog> {
  PaymentMethod _selectedMethod = PaymentMethod.cash;
  final _cashController = TextEditingController();
  final _cardController = TextEditingController();
  final _transferController = TextEditingController();
  final _interestController = TextEditingController(text: '0');
  final _noteController = TextEditingController();
  final _receivedController = TextEditingController();
  DateTime? _dueDate;
  double _change = 0.0;
  bool _printTicket = true; // Por defecto imprimir

  @override
  void initState() {
    super.initState();
    _cashController.text = widget.total.toStringAsFixed(2);
    _receivedController.text = widget.total.toStringAsFixed(2);
    _cashController.addListener(_calculateChange);
    _cardController.addListener(_calculateChange);
    _transferController.addListener(_calculateChange);
    _receivedController.addListener(_calculateReceivedChange);
    _calculateReceivedChange();
  }

  @override
  void dispose() {
    _cashController.dispose();
    _cardController.dispose();
    _transferController.dispose();
    _interestController.dispose();
    _noteController.dispose();
    _receivedController.dispose();
    super.dispose();
  }

  void _calculateReceivedChange() {
    final received = double.tryParse(_receivedController.text) ?? widget.total;
    setState(() {
      _change = received - widget.total;
    });
  }

  void _calculateChange() {
    if (_selectedMethod == PaymentMethod.cash) {
      final cash = double.tryParse(_cashController.text) ?? 0;
      setState(() {
        _change = cash - widget.total;
      });
    } else if (_selectedMethod == PaymentMethod.mixed) {
      final cash = double.tryParse(_cashController.text) ?? 0;
      final card = double.tryParse(_cardController.text) ?? 0;
      final transfer = double.tryParse(_transferController.text) ?? 0;
      final total = cash + card + transfer;
      setState(() {
        _change = total - widget.total;
      });
    } else {
      setState(() {
        _change = 0;
      });
    }
  }

  Future<void> _selectDueDate() async {
    final date = await showDatePicker(
      context: context,
      initialDate: DateTime.now().add(const Duration(days: 30)),
      firstDate: DateTime.now(),
      lastDate: DateTime.now().add(const Duration(days: 365)),
    );
    if (date != null) {
      setState(() {
        _dueDate = date;
      });
    }
  }

  void _processPayment() {
    // Validar según método
    if (_selectedMethod == PaymentMethod.credit) {
      if (widget.selectedClient == null) {
        _showError('Debe seleccionar un cliente para vender a crédito');
        widget.onSelectClient();
        return;
      }
      if (_dueDate == null) {
        _showError('Debe seleccionar una fecha de pago');
        return;
      }
    }

    // Retornar resultado
    Navigator.pop(context, {
      'method': _selectedMethod,
      'cash': double.tryParse(_cashController.text) ?? 0,
      'card': double.tryParse(_cardController.text) ?? 0,
      'transfer': double.tryParse(_transferController.text) ?? 0,
      'received': double.tryParse(_receivedController.text) ?? widget.total,
      'change': _change > 0 ? _change : 0,
      'dueDate': _dueDate,
      'interest': double.tryParse(_interestController.text) ?? 0,
      'note': _noteController.text.trim(),
      'printTicket': _printTicket,
    });
  }

  void _showError(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), backgroundColor: Colors.red),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Shortcuts(
      shortcuts: const {
        SingleActivator(LogicalKeyboardKey.f9):
            PrintAndConfirmPaymentIntent(),
      },
      child: Actions(
        actions: {
          PrintAndConfirmPaymentIntent: CallbackAction<PrintAndConfirmPaymentIntent>(
            onInvoke: (_) {
              if (!_printTicket) {
                setState(() => _printTicket = true);
              }
              _processPayment();
              return null;
            },
          ),
        },
        child: Focus(
          autofocus: true,
          child: Dialog(
      child: Container(
        width: 500,
        constraints: const BoxConstraints(maxHeight: 700),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Header
            Container(
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: Colors.teal,
                borderRadius: const BorderRadius.vertical(
                  top: Radius.circular(4),
                ),
              ),
              child: Row(
                children: [
                  const Icon(Icons.payment, color: Colors.white, size: 28),
                  const SizedBox(width: 12),
                  const Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'PROCESAR PAGO',
                          style: TextStyle(
                            fontSize: 20,
                            fontWeight: FontWeight.bold,
                            color: Colors.white,
                          ),
                        ),
                        Text(
                          'SELECCIONE EL MÉTODO DE PAGO',
                          style: TextStyle(color: Colors.white70, fontSize: 13),
                        ),
                      ],
                    ),
                  ),
                  IconButton(
                    onPressed: () => Navigator.pop(context),
                    icon: const Icon(Icons.close, color: Colors.white),
                  ),
                ],
              ),
            ),

            // Body
            Flexible(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(20),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // Total a pagar
                    Container(
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: Colors.teal.shade50,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(
                          color: Colors.teal.shade200,
                          width: 2,
                        ),
                      ),
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          const Row(
                            children: [
                              Icon(
                                Icons.attach_money,
                                color: Colors.teal,
                                size: 24,
                              ),
                              SizedBox(width: 8),
                              Text(
                                'TOTAL A PAGAR:',
                                style: TextStyle(
                                  fontSize: 18,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ],
                          ),
                          Text(
                            '\$${widget.total.toStringAsFixed(2)}',
                            style: TextStyle(
                              fontSize: 24,
                              fontWeight: FontWeight.bold,
                              color: Colors.teal.shade800,
                            ),
                          ),
                        ],
                      ),
                    ),

                    const SizedBox(height: 16),

                    // Sección de Recibido y Devuelta
                    Container(
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: Colors.grey.shade50,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: Colors.grey.shade300),
                      ),
                      child: Column(
                        children: [
                          // Campo de monto recibido
                          Row(
                            children: [
                              const Icon(Icons.payments, color: Colors.blue, size: 22),
                              const SizedBox(width: 12),
                              const Expanded(
                                flex: 2,
                                child: Text(
                                  'CLIENTE PAGA CON:',
                                  style: TextStyle(
                                    fontSize: 15,
                                    fontWeight: FontWeight.w600,
                                  ),
                                ),
                              ),
                              Expanded(
                                flex: 2,
                                child: TextField(
                                  controller: _receivedController,
                                  keyboardType: TextInputType.number,
                                  textAlign: TextAlign.right,
                                  style: const TextStyle(
                                    fontSize: 20,
                                    fontWeight: FontWeight.bold,
                                    color: Colors.blue,
                                  ),
                                  decoration: InputDecoration(
                                    hintText: widget.total.toStringAsFixed(2),
                                    hintStyle: TextStyle(color: Colors.grey.shade400),
                                    prefixText: '\$ ',
                                    prefixStyle: const TextStyle(
                                      fontSize: 20,
                                      fontWeight: FontWeight.bold,
                                      color: Colors.blue,
                                    ),
                                    contentPadding: const EdgeInsets.symmetric(
                                      horizontal: 12,
                                      vertical: 8,
                                    ),
                                    border: OutlineInputBorder(
                                      borderRadius: BorderRadius.circular(8),
                                    ),
                                    focusedBorder: OutlineInputBorder(
                                      borderRadius: BorderRadius.circular(8),
                                      borderSide: const BorderSide(color: Colors.blue, width: 2),
                                    ),
                                  ),
                                  inputFormatters: [
                                    FilteringTextInputFormatter.allow(RegExp(r'^\d+\.?\d{0,2}')),
                                  ],
                                ),
                              ),
                            ],
                          ),
                          
                          const SizedBox(height: 12),
                          
                          // Devuelta
                          Container(
                            padding: const EdgeInsets.all(12),
                            decoration: BoxDecoration(
                              color: _change > 0 
                                  ? Colors.green.shade100 
                                  : (_change < 0 ? Colors.red.shade100 : Colors.grey.shade100),
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Row(
                              mainAxisAlignment: MainAxisAlignment.spaceBetween,
                              children: [
                                Row(
                                  children: [
                                    Icon(
                                      _change >= 0 ? Icons.arrow_back : Icons.warning,
                                      color: _change > 0 
                                          ? Colors.green.shade700 
                                          : (_change < 0 ? Colors.red.shade700 : Colors.grey),
                                      size: 22,
                                    ),
                                    const SizedBox(width: 8),
                                    Text(
                                      _change >= 0 ? 'DEVUELTA:' : 'FALTA:',
                                      style: TextStyle(
                                        fontSize: 16,
                                        fontWeight: FontWeight.bold,
                                        color: _change > 0 
                                            ? Colors.green.shade700 
                                            : (_change < 0 ? Colors.red.shade700 : Colors.grey.shade600),
                                      ),
                                    ),
                                  ],
                                ),
                                Text(
                                  '\$${_change.abs().toStringAsFixed(2)}',
                                  style: TextStyle(
                                    fontSize: 24,
                                    fontWeight: FontWeight.bold,
                                    color: _change > 0 
                                        ? Colors.green.shade700 
                                        : (_change < 0 ? Colors.red.shade700 : Colors.grey.shade600),
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),

                    const SizedBox(height: 24),

                    // Método de pago
                    const Text(
                      'MÉTODO DE PAGO',
                      style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(height: 12),

                    Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      children: [
                        _buildMethodChip(
                          PaymentMethod.cash,
                          'EFECTIVO',
                          Icons.money,
                        ),
                        _buildMethodChip(
                          PaymentMethod.card,
                          'TARJETA',
                          Icons.credit_card,
                        ),
                        _buildMethodChip(
                          PaymentMethod.transfer,
                          'TRANSFERENCIA',
                          Icons.account_balance,
                        ),
                        _buildMethodChip(
                          PaymentMethod.mixed,
                          'MIXTO',
                          Icons.payments,
                        ),
                        _buildMethodChip(
                          PaymentMethod.credit,
                          'CRÉDITO',
                          Icons.request_quote,
                        ),
                      ],
                    ),

                    const SizedBox(height: 24),

                    // Campos según método
                    if (_selectedMethod == PaymentMethod.cash) ...[
                      // Solo el efectivo, la devuelta ya se muestra arriba
                      const SizedBox.shrink(),
                    ] else if (_selectedMethod == PaymentMethod.card) ...[
                      _buildAmountField(
                        'MONTO CON TARJETA',
                        _cardController,
                        Icons.credit_card,
                      ),
                    ] else if (_selectedMethod == PaymentMethod.transfer) ...[
                      _buildAmountField(
                        'MONTO TRANSFERIDO',
                        _transferController,
                        Icons.account_balance,
                      ),
                    ] else if (_selectedMethod == PaymentMethod.mixed) ...[
                      _buildAmountField(
                        'EFECTIVO',
                        _cashController,
                        Icons.money,
                      ),
                      const SizedBox(height: 12),
                      _buildAmountField(
                        'TARJETA',
                        _cardController,
                        Icons.credit_card,
                      ),
                      const SizedBox(height: 12),
                      _buildAmountField(
                        'TRANSFERENCIA',
                        _transferController,
                        Icons.account_balance,
                      ),
                      const SizedBox(height: 16),
                      Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: _change.abs() < 0.01
                              ? Colors.green.shade50
                              : Colors.orange.shade50,
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(
                            color: _change.abs() < 0.01
                                ? Colors.green
                                : Colors.orange,
                          ),
                        ),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            const Text(
                              'DIFERENCIA:',
                              style: TextStyle(fontWeight: FontWeight.w600),
                            ),
                            Text(
                              '\$${_change.toStringAsFixed(2)}',
                              style: TextStyle(
                                fontSize: 16,
                                fontWeight: FontWeight.bold,
                                color: _change.abs() < 0.01
                                    ? Colors.green.shade800
                                    : Colors.orange.shade800,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ] else if (_selectedMethod == PaymentMethod.credit) ...[
                      // Cliente
                      Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          border: Border.all(color: Colors.grey.shade300),
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: Row(
                          children: [
                            Icon(Icons.person, color: Colors.teal),
                            const SizedBox(width: 12),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  const Text(
                                    'CLIENTE',
                                    style: TextStyle(
                                      fontSize: 12,
                                      color: Colors.grey,
                                    ),
                                  ),
                                  Text(
                                    (widget.selectedClient?.nombre ?? 'NINGUNO').toUpperCase(),
                                    style: const TextStyle(
                                      fontSize: 16,
                                      fontWeight: FontWeight.w600,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                            if (widget.selectedClient == null)
                              ElevatedButton(
                                onPressed: widget.onSelectClient,
                                style: ElevatedButton.styleFrom(
                                  backgroundColor: Colors.teal,
                                ),
                                child: const Text('SELECCIONAR'),
                              ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 16),

                      // Fecha de pago
                      InkWell(
                        onTap: _selectDueDate,
                        child: Container(
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            border: Border.all(color: Colors.grey.shade300),
                            borderRadius: BorderRadius.circular(8),
                          ),
                          child: Row(
                            children: [
                              Icon(Icons.calendar_today, color: Colors.teal),
                              const SizedBox(width: 12),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    const Text(
                                      'FECHA DE PAGO',
                                      style: TextStyle(
                                        fontSize: 12,
                                        color: Colors.grey,
                                      ),
                                    ),
                                    Text(
                                      _dueDate != null
                                          ? '${_dueDate!.day}/${_dueDate!.month}/${_dueDate!.year}'
                                          : 'SELECCIONAR FECHA',
                                      style: const TextStyle(
                                        fontSize: 16,
                                        fontWeight: FontWeight.w600,
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                              const Icon(Icons.arrow_forward_ios, size: 16),
                            ],
                          ),
                        ),
                      ),
                      const SizedBox(height: 16),

                      // Interés
                      TextFormField(
                        controller: _interestController,
                        decoration: const InputDecoration(
                          labelText: 'INTERÉS (%)',
                          border: OutlineInputBorder(),
                          prefixIcon: Icon(Icons.percent),
                        ),
                        keyboardType: TextInputType.number,
                        inputFormatters: [
                          FilteringTextInputFormatter.allow(
                            RegExp(r'^\d+\.?\d{0,2}'),
                          ),
                        ],
                      ),
                      const SizedBox(height: 16),

                      // Nota
                      TextFormField(
                        controller: _noteController,
                        decoration: const InputDecoration(
                          labelText: 'NOTA / CONDICIONES',
                          border: OutlineInputBorder(),
                          prefixIcon: Icon(Icons.note),
                        ),
                        maxLines: 2,
                      ),
                    ],
                  ],
                ),
              ),
            ),

            // Footer
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.grey.shade100,
                borderRadius: const BorderRadius.vertical(
                  bottom: Radius.circular(4),
                ),
              ),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  // Opción de imprimir ticket
                  Container(
                    margin: const EdgeInsets.only(bottom: 12),
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
                    decoration: BoxDecoration(
                      color: Colors.white,
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: Colors.grey.shade300),
                    ),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(
                          _printTicket ? Icons.print : Icons.print_disabled,
                          color: _printTicket ? Colors.teal : Colors.grey,
                          size: 20,
                        ),
                        const SizedBox(width: 8),
                        const Text(
                          'IMPRIMIR TICKET',
                          style: TextStyle(
                            fontSize: 14,
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Switch(
                          value: _printTicket,
                          onChanged: (value) {
                            setState(() {
                              _printTicket = value;
                            });
                          },
                          activeColor: Colors.teal,
                        ),
                      ],
                    ),
                  ),
                  
                  // Botones
                  Row(
                    mainAxisAlignment: MainAxisAlignment.end,
                    children: [
                      TextButton(
                        onPressed: () => Navigator.pop(context),
                        child: const Text('CANCELAR'),
                      ),
                      const SizedBox(width: 12),
                      ElevatedButton.icon(
                        onPressed: _processPayment,
                        icon: Icon(_printTicket ? Icons.print : Icons.check_circle),
                        label: Text(_printTicket ? 'CONFIRMAR E IMPRIMIR' : 'CONFIRMAR SIN IMPRIMIR'),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.teal,
                          padding: const EdgeInsets.symmetric(
                            horizontal: 24,
                            vertical: 14,
                          ),
                          textStyle: const TextStyle(
                            fontSize: 15,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
          ),
        ),
      ),
    );
  }

  Widget _buildMethodChip(PaymentMethod method, String label, IconData icon) {
    final isSelected = _selectedMethod == method;
    return ChoiceChip(
      selected: isSelected,
      label: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 18, color: isSelected ? Colors.white : Colors.teal),
          const SizedBox(width: 6),
          Text(label),
        ],
      ),
      onSelected: (selected) {
        if (selected) {
          setState(() {
            _selectedMethod = method;
            _change = 0;
            // Resetear campos
            if (method != PaymentMethod.cash && method != PaymentMethod.mixed) {
              _cashController.clear();
            }
            if (method != PaymentMethod.card && method != PaymentMethod.mixed) {
              _cardController.clear();
            }
            if (method != PaymentMethod.transfer &&
                method != PaymentMethod.mixed) {
              _transferController.clear();
            }
            // Pre-llenar según método
            if (method == PaymentMethod.card) {
              _cardController.text = widget.total.toStringAsFixed(2);
            } else if (method == PaymentMethod.transfer) {
              _transferController.text = widget.total.toStringAsFixed(2);
            } else if (method == PaymentMethod.cash) {
              _cashController.text = widget.total.toStringAsFixed(2);
            }
          });
        }
      },
      selectedColor: Colors.teal,
      labelStyle: TextStyle(
        color: isSelected ? Colors.white : Colors.black87,
        fontWeight: FontWeight.w600,
      ),
    );
  }

  Widget _buildAmountField(
    String label,
    TextEditingController controller,
    IconData icon,
  ) {
    return TextFormField(
      controller: controller,
      decoration: InputDecoration(
        labelText: label,
        border: const OutlineInputBorder(),
        prefixIcon: Icon(icon),
      ),
      keyboardType: TextInputType.number,
      inputFormatters: [
        FilteringTextInputFormatter.allow(RegExp(r'^\d+\.?\d{0,2}')),
      ],
    );
  }
}

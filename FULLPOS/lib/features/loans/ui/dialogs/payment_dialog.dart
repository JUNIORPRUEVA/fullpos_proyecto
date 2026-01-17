import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:intl/intl.dart';
import '../../../../core/constants/app_colors.dart';
import '../../../../core/errors/error_handler.dart';
import '../../data/loan_models.dart';
import '../../data/loans_repository.dart';

/// Diálogo para registrar un pago de préstamo
class PaymentDialog extends StatefulWidget {
  final int loanId;
  final double balance;
  final LoanInstallmentModel? nextInstallment;

  const PaymentDialog({
    super.key,
    required this.loanId,
    required this.balance,
    this.nextInstallment,
  });

  @override
  State<PaymentDialog> createState() => _PaymentDialogState();
}

class _PaymentDialogState extends State<PaymentDialog> {
  final _amountController = TextEditingController();
  final _noteController = TextEditingController();
  String _method = PaymentMethod.cash;
  bool _isProcessing = false;

  @override
  void initState() {
    super.initState();
    // Pre-llenar con el monto de la próxima cuota si existe
    if (widget.nextInstallment != null) {
      _amountController.text = widget.nextInstallment!.remainingAmount.toStringAsFixed(2);
    }
  }

  @override
  void dispose() {
    _amountController.dispose();
    _noteController.dispose();
    super.dispose();
  }

  Future<void> _processPayment() async {
    final amount = double.tryParse(_amountController.text);
    if (amount == null || amount <= 0) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Ingrese un monto válido'), backgroundColor: AppColors.error),
      );
      return;
    }

    if (amount > widget.balance) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('El monto excede el saldo pendiente'), backgroundColor: AppColors.error),
      );
      return;
    }

    setState(() => _isProcessing = true);

    try {
      await LoansRepository.registerPayment(
        loanId: widget.loanId,
        amount: amount,
        method: _method,
        note: _noteController.text.isEmpty ? null : _noteController.text,
      );

      if (mounted) {
        Navigator.pop(context, {
          'success': true,
          'amount': amount,
          'method': _method,
        });
      }
    } catch (e, st) {
      setState(() => _isProcessing = false);
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: _processPayment,
          module: 'loans/payment',
        );
      }
    }
  }

  void _setQuickAmount(double amount) {
    _amountController.text = amount.toStringAsFixed(2);
  }

  @override
  Widget build(BuildContext context) {
    final currencyFormat = NumberFormat.currency(locale: 'es_DO', symbol: 'RD\$');

    return Dialog(
      child: Container(
        constraints: const BoxConstraints(maxWidth: 450),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Header
            Container(
              padding: const EdgeInsets.all(16),
              decoration: const BoxDecoration(
                color: AppColors.success,
                borderRadius: BorderRadius.only(
                  topLeft: Radius.circular(12),
                  topRight: Radius.circular(12),
                ),
              ),
              child: Row(
                children: [
                  const Icon(Icons.payment, color: Colors.white, size: 24),
                  const SizedBox(width: 12),
                  const Expanded(
                    child: Text(
                      'Registrar Pago',
                      style: TextStyle(
                        color: Colors.white,
                        fontSize: 18,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                  IconButton(
                    onPressed: () => Navigator.pop(context),
                    icon: const Icon(Icons.close, color: Colors.white),
                  ),
                ],
              ),
            ),

            // Content
            Padding(
              padding: const EdgeInsets.all(20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Saldo pendiente
                  Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: Colors.grey.shade50,
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        const Text('Saldo Pendiente:', style: TextStyle(fontSize: 14)),
                        Text(
                          currencyFormat.format(widget.balance),
                          style: const TextStyle(
                            fontSize: 20,
                            fontWeight: FontWeight.bold,
                            color: AppColors.teal700,
                          ),
                        ),
                      ],
                    ),
                  ),

                  const SizedBox(height: 20),

                  // Monto
                  const Text('Monto a Pagar', style: TextStyle(fontWeight: FontWeight.w600)),
                  const SizedBox(height: 8),
                  TextFormField(
                    controller: _amountController,
                    keyboardType: const TextInputType.numberWithOptions(decimal: true),
                    inputFormatters: [FilteringTextInputFormatter.allow(RegExp(r'[\d.]'))],
                    style: const TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
                    textAlign: TextAlign.center,
                    decoration: InputDecoration(
                      prefixText: 'RD\$ ',
                      hintText: '0.00',
                      filled: true,
                      fillColor: Colors.grey.shade100,
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(10),
                        borderSide: BorderSide.none,
                      ),
                    ),
                  ),

                  const SizedBox(height: 12),

                  // Quick amounts
                  Wrap(
                    spacing: 8,
                    children: [
                      if (widget.nextInstallment != null)
                        _QuickAmountChip(
                          label: 'Cuota',
                          amount: widget.nextInstallment!.remainingAmount,
                          onTap: () => _setQuickAmount(widget.nextInstallment!.remainingAmount),
                        ),
                      _QuickAmountChip(
                        label: 'Total',
                        amount: widget.balance,
                        onTap: () => _setQuickAmount(widget.balance),
                      ),
                      if (widget.balance >= 500)
                        _QuickAmountChip(
                          label: '',
                          amount: 500,
                          onTap: () => _setQuickAmount(500),
                        ),
                      if (widget.balance >= 1000)
                        _QuickAmountChip(
                          label: '',
                          amount: 1000,
                          onTap: () => _setQuickAmount(1000),
                        ),
                    ],
                  ),

                  const SizedBox(height: 20),

                  // Método de pago
                  const Text('Método de Pago', style: TextStyle(fontWeight: FontWeight.w600)),
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      Expanded(
                        child: _PaymentMethodCard(
                          icon: Icons.payments,
                          label: 'Efectivo',
                          isSelected: _method == PaymentMethod.cash,
                          onTap: () => setState(() => _method = PaymentMethod.cash),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: _PaymentMethodCard(
                          icon: Icons.swap_horiz,
                          label: 'Transferencia',
                          isSelected: _method == PaymentMethod.transfer,
                          onTap: () => setState(() => _method = PaymentMethod.transfer),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: _PaymentMethodCard(
                          icon: Icons.credit_card,
                          label: 'Tarjeta',
                          isSelected: _method == PaymentMethod.card,
                          onTap: () => setState(() => _method = PaymentMethod.card),
                        ),
                      ),
                    ],
                  ),

                  const SizedBox(height: 16),

                  // Nota
                  TextFormField(
                    controller: _noteController,
                    decoration: InputDecoration(
                      labelText: 'Nota (opcional)',
                      hintText: 'Agregar comentario...',
                      prefixIcon: const Icon(Icons.note, size: 20),
                      filled: true,
                      fillColor: Colors.grey.shade50,
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8),
                        borderSide: BorderSide.none,
                      ),
                    ),
                  ),
                ],
              ),
            ),

            // Actions
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.grey.shade50,
                border: Border(top: BorderSide(color: Colors.grey.shade200)),
              ),
              child: Row(
                children: [
                  Expanded(
                    child: OutlinedButton(
                      onPressed: () => Navigator.pop(context),
                      child: const Text('Cancelar'),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    flex: 2,
                    child: ElevatedButton.icon(
                      onPressed: _isProcessing ? null : _processPayment,
                      icon: _isProcessing
                          ? const SizedBox(
                              width: 18,
                              height: 18,
                              child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                            )
                          : const Icon(Icons.check),
                      label: Text(_isProcessing ? 'Procesando...' : 'Confirmar Pago'),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: AppColors.success,
                        foregroundColor: Colors.white,
                        padding: const EdgeInsets.symmetric(vertical: 14),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _QuickAmountChip extends StatelessWidget {
  final String label;
  final double amount;
  final VoidCallback onTap;

  const _QuickAmountChip({
    required this.label,
    required this.amount,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final currencyFormat = NumberFormat.currency(locale: 'es_DO', symbol: 'RD\$', decimalDigits: 0);
    
    return ActionChip(
      label: Text(
        label.isNotEmpty ? '$label: ${currencyFormat.format(amount)}' : currencyFormat.format(amount),
        style: const TextStyle(fontSize: 12),
      ),
      onPressed: onTap,
      backgroundColor: AppColors.teal.withOpacity(0.1),
    );
  }
}

class _PaymentMethodCard extends StatelessWidget {
  final IconData icon;
  final String label;
  final bool isSelected;
  final VoidCallback onTap;

  const _PaymentMethodCard({
    required this.icon,
    required this.label,
    required this.isSelected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(8),
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 8),
        decoration: BoxDecoration(
          color: isSelected ? AppColors.success.withOpacity(0.1) : Colors.grey.shade50,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(
            color: isSelected ? AppColors.success : Colors.grey.shade300,
            width: isSelected ? 2 : 1,
          ),
        ),
        child: Column(
          children: [
            Icon(icon, size: 24, color: isSelected ? AppColors.success : Colors.grey),
            const SizedBox(height: 4),
            Text(
              label,
              style: TextStyle(
                fontSize: 11,
                fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
                color: isSelected ? AppColors.success : Colors.grey.shade700,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

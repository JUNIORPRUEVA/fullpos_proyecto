import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../../../../core/services/app_configuration_service.dart';
import '../../../../core/constants/app_colors.dart';
import '../../../../core/errors/error_handler.dart';
import '../../../../core/printing/loan_printer.dart';
import '../../../../core/session/session_manager.dart';

/// Diálogo para mostrar y/o imprimir recibo de pago
class PaymentReceiptDialog extends StatefulWidget {
  final int loanId;
  final String clientName;
  final double amount;
  final String method;
  final double newBalance;
  final DateTime date;

  const PaymentReceiptDialog({
    super.key,
    required this.loanId,
    required this.clientName,
    required this.amount,
    required this.method,
    required this.newBalance,
    required this.date,
  });

  @override
  State<PaymentReceiptDialog> createState() => _PaymentReceiptDialogState();
}

class _PaymentReceiptDialogState extends State<PaymentReceiptDialog> {
  bool _isPrinting = false;

  String _getMethodLabel() {
    switch (widget.method) {
      case 'cash':
        return 'Efectivo';
      case 'transfer':
        return 'Transferencia';
      case 'card':
        return 'Tarjeta';
      default:
        return widget.method;
    }
  }

  Future<void> _printReceipt() async {
    setState(() => _isPrinting = true);

    try {
      final cashierName = await SessionManager.displayName() ?? 'Sistema';

      final success = await LoanPrinter.printPaymentReceipt(
        loanId: widget.loanId,
        clientName: widget.clientName,
        amount: widget.amount,
        method: widget.method,
        newBalance: widget.newBalance,
        date: widget.date,
        cashierName: cashierName,
      );

      if (mounted) {
        if (success) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Recibo impreso correctamente'),
              backgroundColor: AppColors.success,
            ),
          );
        } else {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('No se pudo imprimir. Verifique la impresora.'),
              backgroundColor: AppColors.warning,
            ),
          );
        }
      }
    } catch (e, st) {
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: _printReceipt,
          module: 'loans/print_receipt',
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isPrinting = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final currencyFormat = NumberFormat.currency(
      locale: 'es_DO',
      symbol: 'RD\$',
    );
    final dateFormat = DateFormat('dd/MM/yyyy HH:mm');

    return Dialog(
      child: Container(
        constraints: const BoxConstraints(maxWidth: 350),
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
                  const Icon(Icons.receipt_long, color: Colors.white, size: 24),
                  const SizedBox(width: 12),
                  const Expanded(
                    child: Text(
                      'Recibo de Pago',
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

            // Receipt preview
            Container(
              margin: const EdgeInsets.all(16),
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: Colors.grey.shade300),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withOpacity(0.05),
                    blurRadius: 10,
                  ),
                ],
              ),
              child: Column(
                children: [
                  // Logo/título
                  Text(
                    appConfigService.getBusinessName().trim().isNotEmpty
                        ? appConfigService.getBusinessName().trim()
                        : 'MI NEGOCIO',
                    style: const TextStyle(
                      fontSize: 20,
                      fontWeight: FontWeight.bold,
                      letterSpacing: 2,
                    ),
                  ),
                  const Text(
                    'RECIBO DE PAGO',
                    style: TextStyle(fontSize: 12, color: Colors.grey),
                  ),
                  const Divider(height: 24),

                  // Info
                  _ReceiptRow(
                    label: 'Fecha',
                    value: dateFormat.format(widget.date),
                  ),
                  _ReceiptRow(label: 'Préstamo', value: '#${widget.loanId}'),
                  _ReceiptRow(label: 'Cliente', value: widget.clientName),
                  const Divider(height: 16),

                  _ReceiptRow(label: 'Método', value: _getMethodLabel()),
                  const SizedBox(height: 8),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      const Text(
                        'MONTO PAGADO',
                        style: TextStyle(fontWeight: FontWeight.bold),
                      ),
                      Text(
                        currencyFormat.format(widget.amount),
                        style: const TextStyle(
                          fontSize: 22,
                          fontWeight: FontWeight.bold,
                          color: AppColors.success,
                        ),
                      ),
                    ],
                  ),
                  const Divider(height: 16),

                  _ReceiptRow(
                    label: 'Nuevo Saldo',
                    value: currencyFormat.format(widget.newBalance),
                    valueStyle: TextStyle(
                      fontWeight: FontWeight.w600,
                      color: widget.newBalance > 0
                          ? Colors.orange
                          : Colors.green,
                    ),
                  ),

                  const SizedBox(height: 16),
                  Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: Colors.green.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: const Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(Icons.check_circle, color: Colors.green, size: 18),
                        SizedBox(width: 8),
                        Text(
                          '¡Pago registrado exitosamente!',
                          style: TextStyle(color: Colors.green, fontSize: 13),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),

            // Actions
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
              child: Row(
                children: [
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: () => Navigator.pop(context),
                      icon: const Icon(Icons.close, size: 18),
                      label: const Text('Cerrar'),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: ElevatedButton.icon(
                      onPressed: _isPrinting ? null : _printReceipt,
                      icon: _isPrinting
                          ? const SizedBox(
                              width: 18,
                              height: 18,
                              child: CircularProgressIndicator(
                                strokeWidth: 2,
                                color: Colors.white,
                              ),
                            )
                          : const Icon(Icons.print, size: 18),
                      label: Text(_isPrinting ? 'Imprimiendo...' : 'Imprimir'),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: AppColors.teal,
                        foregroundColor: Colors.white,
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

class _ReceiptRow extends StatelessWidget {
  final String label;
  final String value;
  final TextStyle? valueStyle;

  const _ReceiptRow({
    required this.label,
    required this.value,
    this.valueStyle,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: TextStyle(color: Colors.grey.shade600, fontSize: 13),
          ),
          Text(value, style: valueStyle ?? const TextStyle(fontSize: 13)),
        ],
      ),
    );
  }
}

import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../../../../core/constants/app_colors.dart';
import '../../../../core/errors/error_handler.dart';
import '../../../../core/printing/loan_printer.dart';
import '../../../../core/session/session_manager.dart';
import '../../utils/loan_contract_pdf_launcher.dart';
import '../../data/loan_models.dart';
import '../../data/loans_repository.dart';
import 'payment_dialog.dart';
import 'payment_receipt_dialog.dart';

/// Diálogo para ver los detalles completos de un préstamo
class LoanDetailDialog extends StatefulWidget {
  final int loanId;

  const LoanDetailDialog({super.key, required this.loanId});

  @override
  State<LoanDetailDialog> createState() => _LoanDetailDialogState();
}

class _LoanDetailDialogState extends State<LoanDetailDialog> {
  LoanDetailDto? _detail;
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadDetail();
  }

  Future<void> _loadDetail() async {
    setState(() => _isLoading = true);
    try {
      final detail = await LoansRepository.getLoanDetail(widget.loanId);
      setState(() {
        _detail = detail;
        _isLoading = false;
      });
    } catch (e, st) {
      setState(() => _isLoading = false);
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: _loadDetail,
          module: 'loans/detail',
        );
      }
    }
  }

  /// Abre el contrato en PDF (vista previa + descargar/imprimir/compartir)
  Future<void> _openContractPdf() async {
    if (_detail == null) return;
    await LoanContractPdfLauncher.openPreviewDialog(
      context: context,
      loanDetail: _detail!,
    );
  }

  Future<void> _printStatement() async {
    if (_detail == null) return;

    final cashierName = await SessionManager.displayName() ?? 'Usuario';
    final success = await LoanPrinter.printLoanStatement(
      loanDetail: _detail!,
      cashierName: cashierName,
    );

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            success ? '✅ Estado de cuenta impreso' : '❌ Error al imprimir',
          ),
          backgroundColor: success ? Colors.green : Colors.red,
        ),
      );
    }
  }

  Future<void> _showPaymentDialog() async {
    if (_detail == null) return;

    final result = await showDialog<Map<String, dynamic>>(
      context: context,
      builder: (context) => PaymentDialog(
        loanId: widget.loanId,
        balance: _detail!.loan.balance,
        nextInstallment: _detail!.nextPendingInstallment,
      ),
    );

    if (result != null && result['success'] == true) {
      await _loadDetail();

      // Mostrar recibo
      if (mounted) {
        showDialog(
          context: context,
          builder: (context) => PaymentReceiptDialog(
            loanId: widget.loanId,
            clientName: _detail!.clientName,
            amount: result['amount'] as double,
            method: result['method'] as String,
            newBalance: _detail!.loan.balance,
            date: DateTime.now(),
          ),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final currencyFormat = NumberFormat.currency(
      locale: 'es_DO',
      symbol: 'RD\$',
    );
    final dateFormat = DateFormat('dd/MM/yyyy');

    if (_isLoading) {
      return const Dialog(
        child: SizedBox(
          width: 400,
          height: 300,
          child: Center(child: CircularProgressIndicator()),
        ),
      );
    }

    if (_detail == null) {
      return Dialog(
        child: SizedBox(
          width: 400,
          height: 200,
          child: Center(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Icon(
                  Icons.error_outline,
                  size: 48,
                  color: AppColors.error,
                ),
                const SizedBox(height: 16),
                const Text('No se pudo cargar el préstamo'),
                const SizedBox(height: 16),
                ElevatedButton(
                  onPressed: () => Navigator.pop(context),
                  child: const Text('Cerrar'),
                ),
              ],
            ),
          ),
        ),
      );
    }

    final loan = _detail!.loan;
    final installments = _detail!.installments;
    final payments = _detail!.payments;

    Color statusColor;
    String statusLabel;
    switch (loan.status) {
      case LoanStatus.open:
        statusColor = Colors.green;
        statusLabel = 'ACTIVO';
        break;
      case LoanStatus.overdue:
        statusColor = Colors.red;
        statusLabel = 'VENCIDO';
        break;
      case LoanStatus.paid:
        statusColor = Colors.blue;
        statusLabel = 'PAGADO';
        break;
      default:
        statusColor = Colors.grey;
        statusLabel = loan.status;
    }

    return Dialog(
      child: Container(
        constraints: const BoxConstraints(maxWidth: 700, maxHeight: 650),
        child: Column(
          children: [
            // Header
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: [AppColors.teal800, AppColors.teal700],
                ),
                borderRadius: const BorderRadius.only(
                  topLeft: Radius.circular(12),
                  topRight: Radius.circular(12),
                ),
              ),
              child: Row(
                children: [
                  const Icon(Icons.handshake, color: Colors.white, size: 28),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Préstamo #${loan.id}',
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 20,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        Text(
                          _detail!.clientName,
                          style: TextStyle(
                            color: Colors.white.withOpacity(0.9),
                            fontSize: 14,
                          ),
                        ),
                      ],
                    ),
                  ),
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 12,
                      vertical: 6,
                    ),
                    decoration: BoxDecoration(
                      color: statusColor,
                      borderRadius: BorderRadius.circular(16),
                    ),
                    child: Text(
                      statusLabel,
                      style: const TextStyle(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                        fontSize: 12,
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  IconButton(
                    onPressed: () => Navigator.pop(context),
                    icon: const Icon(Icons.close, color: Colors.white),
                  ),
                ],
              ),
            ),

            // Content
            Expanded(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // Resumen financiero
                    Container(
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: Colors.grey.shade50,
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Row(
                        children: [
                          Expanded(
                            child: _SummaryItem(
                              label: 'Principal',
                              value: currencyFormat.format(loan.principal),
                              icon: Icons.attach_money,
                            ),
                          ),
                          Container(
                            width: 1,
                            height: 50,
                            color: Colors.grey.shade300,
                          ),
                          Expanded(
                            child: _SummaryItem(
                              label: 'Total',
                              value: currencyFormat.format(loan.totalDue),
                              icon: Icons.account_balance,
                            ),
                          ),
                          Container(
                            width: 1,
                            height: 50,
                            color: Colors.grey.shade300,
                          ),
                          Expanded(
                            child: _SummaryItem(
                              label: 'Pagado',
                              value: currencyFormat.format(loan.paidAmount),
                              icon: Icons.check_circle,
                              color: Colors.green,
                            ),
                          ),
                          Container(
                            width: 1,
                            height: 50,
                            color: Colors.grey.shade300,
                          ),
                          Expanded(
                            child: _SummaryItem(
                              label: 'Saldo',
                              value: currencyFormat.format(loan.balance),
                              icon: Icons.pending,
                              color: loan.balance > 0
                                  ? AppColors.error
                                  : Colors.green,
                            ),
                          ),
                        ],
                      ),
                    ),

                    const SizedBox(height: 16),

                    // Barra de progreso
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            const Text(
                              'Progreso de Pago',
                              style: TextStyle(fontWeight: FontWeight.w600),
                            ),
                            Text('${loan.progressPercent.toStringAsFixed(1)}%'),
                          ],
                        ),
                        const SizedBox(height: 8),
                        ClipRRect(
                          borderRadius: BorderRadius.circular(4),
                          child: LinearProgressIndicator(
                            value: loan.progressPercent / 100,
                            minHeight: 10,
                            backgroundColor: Colors.grey.shade200,
                            valueColor: AlwaysStoppedAnimation<Color>(
                              loan.progressPercent >= 100
                                  ? Colors.green
                                  : AppColors.teal,
                            ),
                          ),
                        ),
                      ],
                    ),

                    const SizedBox(height: 20),

                    // Info del préstamo
                    Row(
                      children: [
                        Expanded(
                          child: _InfoCard(
                            icon: Icons.percent,
                            label: 'Tasa',
                            value:
                                '${loan.interestRate}% ${loan.interestMode == InterestMode.monthlyFlat ? 'mensual' : 'flat'}',
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: _InfoCard(
                            icon: Icons.calendar_today,
                            label: 'Frecuencia',
                            value: _getFrequencyLabel(loan.frequency),
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: _InfoCard(
                            icon: Icons.format_list_numbered,
                            label: 'Cuotas',
                            value:
                                '${installments.where((i) => i.isPaid).length}/${loan.installmentsCount}',
                          ),
                        ),
                      ],
                    ),

                    // Garantía si tiene
                    if (_detail!.collateral != null) ...[
                      const SizedBox(height: 16),
                      Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: AppColors.gold.withOpacity(0.1),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(
                            color: AppColors.gold.withOpacity(0.3),
                          ),
                        ),
                        child: Row(
                          children: [
                            Icon(Icons.inventory_2, color: AppColors.gold),
                            const SizedBox(width: 12),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  const Text(
                                    'Garantía',
                                    style: TextStyle(
                                      fontWeight: FontWeight.w600,
                                      fontSize: 12,
                                    ),
                                  ),
                                  Text(_detail!.collateral!.description),
                                  if (_detail!.collateral!.estimatedValue !=
                                      null)
                                    Text(
                                      'Valor: ${currencyFormat.format(_detail!.collateral!.estimatedValue)}',
                                      style: TextStyle(
                                        fontSize: 12,
                                        color: Colors.grey.shade600,
                                      ),
                                    ),
                                ],
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],

                    const SizedBox(height: 20),

                    // Cuotas
                    const Text(
                      'Cuotas',
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
                        fontSize: 16,
                      ),
                    ),
                    const SizedBox(height: 8),
                    Container(
                      decoration: BoxDecoration(
                        border: Border.all(color: Colors.grey.shade200),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Column(
                        children: [
                          // Header
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 12,
                              vertical: 8,
                            ),
                            decoration: BoxDecoration(
                              color: Colors.grey.shade100,
                              borderRadius: const BorderRadius.only(
                                topLeft: Radius.circular(7),
                                topRight: Radius.circular(7),
                              ),
                            ),
                            child: const Row(
                              children: [
                                SizedBox(
                                  width: 40,
                                  child: Text(
                                    '#',
                                    style: TextStyle(
                                      fontWeight: FontWeight.w600,
                                      fontSize: 12,
                                    ),
                                  ),
                                ),
                                Expanded(
                                  child: Text(
                                    'Vencimiento',
                                    style: TextStyle(
                                      fontWeight: FontWeight.w600,
                                      fontSize: 12,
                                    ),
                                  ),
                                ),
                                SizedBox(
                                  width: 100,
                                  child: Text(
                                    'Monto',
                                    textAlign: TextAlign.right,
                                    style: TextStyle(
                                      fontWeight: FontWeight.w600,
                                      fontSize: 12,
                                    ),
                                  ),
                                ),
                                SizedBox(
                                  width: 100,
                                  child: Text(
                                    'Pagado',
                                    textAlign: TextAlign.right,
                                    style: TextStyle(
                                      fontWeight: FontWeight.w600,
                                      fontSize: 12,
                                    ),
                                  ),
                                ),
                                SizedBox(
                                  width: 80,
                                  child: Text(
                                    'Estado',
                                    textAlign: TextAlign.center,
                                    style: TextStyle(
                                      fontWeight: FontWeight.w600,
                                      fontSize: 12,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ),
                          // Items
                          ...installments.map((inst) {
                            Color instStatusColor;
                            String instStatusLabel;
                            switch (inst.status) {
                              case InstallmentStatus.paid:
                                instStatusColor = Colors.green;
                                instStatusLabel = 'Pagada';
                                break;
                              case InstallmentStatus.partial:
                                instStatusColor = Colors.orange;
                                instStatusLabel = 'Parcial';
                                break;
                              case InstallmentStatus.overdue:
                                instStatusColor = Colors.red;
                                instStatusLabel = 'Vencida';
                                break;
                              default:
                                instStatusColor = Colors.grey;
                                instStatusLabel = 'Pendiente';
                            }

                            return Container(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 12,
                                vertical: 10,
                              ),
                              decoration: BoxDecoration(
                                border: Border(
                                  top: BorderSide(color: Colors.grey.shade200),
                                ),
                              ),
                              child: Row(
                                children: [
                                  SizedBox(
                                    width: 40,
                                    child: Text(
                                      '${inst.number}',
                                      style: const TextStyle(fontSize: 13),
                                    ),
                                  ),
                                  Expanded(
                                    child: Text(
                                      dateFormat.format(inst.dueDate),
                                      style: const TextStyle(fontSize: 13),
                                    ),
                                  ),
                                  SizedBox(
                                    width: 100,
                                    child: Text(
                                      currencyFormat.format(inst.amountDue),
                                      textAlign: TextAlign.right,
                                      style: const TextStyle(fontSize: 13),
                                    ),
                                  ),
                                  SizedBox(
                                    width: 100,
                                    child: Text(
                                      currencyFormat.format(inst.amountPaid),
                                      textAlign: TextAlign.right,
                                      style: const TextStyle(fontSize: 13),
                                    ),
                                  ),
                                  SizedBox(
                                    width: 80,
                                    child: Container(
                                      padding: const EdgeInsets.symmetric(
                                        horizontal: 6,
                                        vertical: 2,
                                      ),
                                      decoration: BoxDecoration(
                                        color: instStatusColor.withOpacity(0.1),
                                        borderRadius: BorderRadius.circular(4),
                                      ),
                                      child: Text(
                                        instStatusLabel,
                                        textAlign: TextAlign.center,
                                        style: TextStyle(
                                          fontSize: 11,
                                          color: instStatusColor,
                                          fontWeight: FontWeight.w600,
                                        ),
                                      ),
                                    ),
                                  ),
                                ],
                              ),
                            );
                          }),
                        ],
                      ),
                    ),

                    // Historial de pagos
                    if (payments.isNotEmpty) ...[
                      const SizedBox(height: 20),
                      const Text(
                        'Historial de Pagos',
                        style: TextStyle(
                          fontWeight: FontWeight.bold,
                          fontSize: 16,
                        ),
                      ),
                      const SizedBox(height: 8),
                      ...payments.map(
                        (payment) => Container(
                          margin: const EdgeInsets.only(bottom: 8),
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: Colors.green.withOpacity(0.05),
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(
                              color: Colors.green.withOpacity(0.2),
                            ),
                          ),
                          child: Row(
                            children: [
                              Container(
                                padding: const EdgeInsets.all(8),
                                decoration: BoxDecoration(
                                  color: Colors.green.withOpacity(0.1),
                                  shape: BoxShape.circle,
                                ),
                                child: const Icon(
                                  Icons.payment,
                                  size: 20,
                                  color: Colors.green,
                                ),
                              ),
                              const SizedBox(width: 12),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      currencyFormat.format(payment.amount),
                                      style: const TextStyle(
                                        fontWeight: FontWeight.bold,
                                      ),
                                    ),
                                    Text(
                                      '${dateFormat.format(payment.paidDate)} - ${_getPaymentMethodLabel(payment.method)}',
                                      style: TextStyle(
                                        fontSize: 12,
                                        color: Colors.grey.shade600,
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                              IconButton(
                                icon: const Icon(Icons.receipt_long, size: 20),
                                onPressed: () {
                                  showDialog(
                                    context: context,
                                    builder: (context) => PaymentReceiptDialog(
                                      loanId: widget.loanId,
                                      clientName: _detail!.clientName,
                                      amount: payment.amount,
                                      method: payment.method,
                                      newBalance: loan.balance,
                                      date: payment.paidDate,
                                    ),
                                  );
                                },
                                tooltip: 'Ver recibo',
                              ),
                            ],
                          ),
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),

            // Actions
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.grey.shade50,
                border: Border(top: BorderSide(color: Colors.grey.shade200)),
              ),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  // Botones de impresión
                  Row(
                    children: [
                      Expanded(
                        child: OutlinedButton.icon(
                          onPressed: _openContractPdf,
                          icon: const Icon(Icons.picture_as_pdf, size: 18),
                          label: const Text('Contrato (PDF)'),
                          style: OutlinedButton.styleFrom(
                            foregroundColor: Colors.teal,
                            side: const BorderSide(color: Colors.teal),
                          ),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: OutlinedButton.icon(
                          onPressed: _printStatement,
                          icon: const Icon(Icons.receipt_long, size: 18),
                          label: const Text('Estado Cuenta'),
                          style: OutlinedButton.styleFrom(
                            foregroundColor: Colors.orange,
                            side: const BorderSide(color: Colors.orange),
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  // Botones principales
                  Row(
                    children: [
                      Expanded(
                        child: OutlinedButton.icon(
                          onPressed: () => Navigator.pop(context),
                          icon: const Icon(Icons.close, size: 18),
                          label: const Text('Cerrar'),
                        ),
                      ),
                      const SizedBox(width: 12),
                      if (loan.balance > 0)
                        Expanded(
                          flex: 2,
                          child: ElevatedButton.icon(
                            onPressed: _showPaymentDialog,
                            icon: const Icon(Icons.payment, size: 18),
                            label: const Text('Registrar Pago'),
                            style: ElevatedButton.styleFrom(
                              backgroundColor: AppColors.success,
                              foregroundColor: Colors.white,
                              padding: const EdgeInsets.symmetric(vertical: 14),
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
    );
  }

  String _getFrequencyLabel(String frequency) {
    switch (frequency) {
      case LoanFrequency.weekly:
        return 'Semanal';
      case LoanFrequency.biweekly:
        return 'Quincenal';
      case LoanFrequency.monthly:
        return 'Mensual';
      case LoanFrequency.single:
        return 'Pago Único';
      default:
        return frequency;
    }
  }

  String _getPaymentMethodLabel(String method) {
    switch (method) {
      case PaymentMethod.cash:
        return 'Efectivo';
      case PaymentMethod.transfer:
        return 'Transferencia';
      case PaymentMethod.card:
        return 'Tarjeta';
      default:
        return method;
    }
  }
}

class _SummaryItem extends StatelessWidget {
  final String label;
  final String value;
  final IconData icon;
  final Color? color;

  const _SummaryItem({
    required this.label,
    required this.value,
    required this.icon,
    this.color,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Icon(icon, size: 20, color: color ?? Colors.grey),
        const SizedBox(height: 4),
        Text(
          label,
          style: TextStyle(fontSize: 11, color: Colors.grey.shade600),
        ),
        const SizedBox(height: 2),
        Text(
          value,
          style: TextStyle(
            fontSize: 13,
            fontWeight: FontWeight.bold,
            color: color ?? AppColors.textDark,
          ),
        ),
      ],
    );
  }
}

class _InfoCard extends StatelessWidget {
  final IconData icon;
  final String label;
  final String value;

  const _InfoCard({
    required this.icon,
    required this.label,
    required this.value,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        border: Border.all(color: Colors.grey.shade200),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          Icon(icon, size: 18, color: AppColors.teal),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  label,
                  style: TextStyle(fontSize: 11, color: Colors.grey.shade600),
                ),
                Text(
                  value,
                  style: const TextStyle(
                    fontWeight: FontWeight.w600,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

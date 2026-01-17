import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../core/errors/error_handler.dart';
import '../../../core/security/app_actions.dart';
import '../../../core/security/authorization_guard.dart';
import '../data/cash_summary_model.dart';
import '../data/cash_repository.dart';
import '../providers/cash_providers.dart';

/// Diálogo para cerrar caja
class CashCloseDialog extends ConsumerStatefulWidget {
  final int sessionId;

  const CashCloseDialog({
    super.key,
    required this.sessionId,
  });

  static Future<bool?> show(BuildContext context, {required int sessionId}) {
    return showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (context) => CashCloseDialog(sessionId: sessionId),
    );
  }

  @override
  ConsumerState<CashCloseDialog> createState() => _CashCloseDialogState();
}

class _CashCloseDialogState extends ConsumerState<CashCloseDialog> {
  final _formKey = GlobalKey<FormState>();
  final _closingAmountController = TextEditingController();
  final _noteController = TextEditingController();
  bool _isLoading = false;
  CashSummaryModel? _summary;
  bool _loadingSummary = true;

  @override
  void initState() {
    super.initState();
    _loadSummary();
  }

  Future<void> _loadSummary() async {
    try {
      final summary = await CashRepository.buildSummary(
        sessionId: widget.sessionId,
      );
      setState(() {
        _summary = summary;
        _loadingSummary = false;
        // Pre-llenar con el esperado
        _closingAmountController.text = summary.expectedCash.toStringAsFixed(2);
      });
    } catch (e, st) {
      setState(() => _loadingSummary = false);
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: _loadSummary,
          module: 'cash/summary',
        );
      }
    }
  }

  @override
  void dispose() {
    _closingAmountController.dispose();
    _noteController.dispose();
    super.dispose();
  }

  double get _closingAmount =>
      double.tryParse(_closingAmountController.text) ?? 0.0;

  double get _difference {
    if (_summary == null) return 0.0;
    return _closingAmount - _summary!.expectedCash;
  }

  Future<void> _closeCash() async {
    if (!_formKey.currentState!.validate()) return;

    final authorized = await requireAuthorizationIfNeeded(
      context: context,
      action: AppActions.closeCash,
      resourceType: 'cash_session',
      resourceId: widget.sessionId.toString(),
      reason: 'Cerrar caja',
    );
    if (!authorized) return;

    setState(() => _isLoading = true);

    try {
      await ref.read(cashSessionControllerProvider.notifier).closeSession(
        sessionId: widget.sessionId,
        closingAmount: _closingAmount,
        note: _noteController.text.trim(),
      );

      if (mounted) {
        Navigator.of(context).pop(true);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: const Text('Corte de caja realizado correctamente'),
            backgroundColor: Colors.green.shade700,
          ),
        );
      }
    } catch (e, st) {
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: _closeCash,
          module: 'cash/close',
        );
      }
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final screenSize = MediaQuery.of(context).size;
    final dialogWidth = screenSize.width * 0.32;
    final dialogHeight = screenSize.height * 0.72;

    return Dialog(
      backgroundColor: const Color(0xFF1E1E1E),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      child: Container(
        width: dialogWidth.clamp(380.0, 520.0),
        height: dialogHeight.clamp(480.0, 650.0),
        padding: const EdgeInsets.all(24),
        child: _loadingSummary
            ? const Center(
                child: CircularProgressIndicator(
                  color: Color(0xFFD4AF37),
                ),
              )
            : Form(
                key: _formKey,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // Header
                    Row(
                      children: [
                        Container(
                          padding: const EdgeInsets.all(10),
                          decoration: BoxDecoration(
                            color: Colors.red.withOpacity(0.2),
                            borderRadius: BorderRadius.circular(10),
                          ),
                          child: const Icon(
                            Icons.lock_outline,
                            color: Colors.red,
                            size: 24,
                          ),
                        ),
                        const SizedBox(width: 12),
                        const Text(
                          'CORTE DE CAJA',
                          style: TextStyle(
                            fontSize: 18,
                            fontWeight: FontWeight.bold,
                            color: Colors.white,
                          ),
                        ),
                        const Spacer(),
                        IconButton(
                          onPressed:
                              _isLoading ? null : () => Navigator.pop(context),
                          icon: const Icon(Icons.close, color: Colors.grey),
                          splashRadius: 20,
                        ),
                      ],
                    ),
                    const SizedBox(height: 20),

                    // Resumen
                    Expanded(
                      child: SingleChildScrollView(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            _buildSummarySection(),
                            const SizedBox(height: 20),
                            _buildClosingSection(),
                          ],
                        ),
                      ),
                    ),
                    const SizedBox(height: 16),

                    // Botones
                    Row(
                      mainAxisAlignment: MainAxisAlignment.end,
                      children: [
                        TextButton(
                          onPressed:
                              _isLoading ? null : () => Navigator.pop(context),
                          child: const Text(
                            'Cancelar',
                            style: TextStyle(color: Colors.grey),
                          ),
                        ),
                        const SizedBox(width: 12),
                        ElevatedButton.icon(
                          onPressed: _isLoading ? null : _closeCash,
                          style: ElevatedButton.styleFrom(
                            backgroundColor: Colors.red.shade700,
                            foregroundColor: Colors.white,
                            padding: const EdgeInsets.symmetric(
                              horizontal: 24,
                              vertical: 12,
                            ),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(8),
                            ),
                          ),
                          icon: _isLoading
                              ? const SizedBox(
                                  width: 16,
                                  height: 16,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                    valueColor: AlwaysStoppedAnimation<Color>(
                                        Colors.white),
                                  ),
                                )
                              : const Icon(Icons.lock, size: 18),
                          label: const Text(
                            'HACER CORTE',
                            style: TextStyle(fontWeight: FontWeight.bold),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
      ),
    );
  }

  Widget _buildSummarySection() {
    if (_summary == null) return const SizedBox.shrink();

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF2A2A2A),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'RESUMEN DE LA JORNADA',
            style: TextStyle(
              color: Color(0xFFD4AF37),
              fontSize: 12,
              fontWeight: FontWeight.bold,
              letterSpacing: 1,
            ),
          ),
          const SizedBox(height: 12),
          _buildSummaryRow('Apertura', _summary!.openingAmount, isHeader: true),
          const Divider(color: Colors.grey, height: 20),
          _buildSummaryRow('Ventas Efectivo', _summary!.salesCashTotal,
              color: Colors.green),
          _buildSummaryRow('Ventas Tarjeta', _summary!.salesCardTotal,
              color: Colors.blue),
          _buildSummaryRow('Ventas Transferencia', _summary!.salesTransferTotal,
              color: Colors.cyan),
          _buildSummaryRow('Ventas Crédito', _summary!.salesCreditTotal,
              color: Colors.orange),
          const Divider(color: Colors.grey, height: 20),
          _buildSummaryRow('+ Entradas manuales', _summary!.cashInManual,
              color: Colors.green),
          _buildSummaryRow('- Retiros manuales', _summary!.cashOutManual,
              color: Colors.red, isNegative: true),
          if (_summary!.refundsCash > 0)
            _buildSummaryRow('- Devoluciones', _summary!.refundsCash,
                color: Colors.red, isNegative: true),
          const Divider(color: Colors.grey, height: 20),
          _buildSummaryRow(
            'EFECTIVO ESPERADO',
            _summary!.expectedCash,
            isHeader: true,
            color: const Color(0xFFD4AF37),
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              _buildStatChip('${_summary!.totalTickets}', 'Tickets', Colors.blue),
              const SizedBox(width: 8),
              _buildStatChip(
                '\$${_summary!.totalSales.toStringAsFixed(2)}',
                'Total Ventas',
                Colors.green,
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildSummaryRow(
    String label,
    double amount, {
    bool isHeader = false,
    Color? color,
    bool isNegative = false,
  }) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: TextStyle(
              color: isHeader ? Colors.white : Colors.grey.shade400,
              fontSize: isHeader ? 14 : 13,
              fontWeight: isHeader ? FontWeight.bold : FontWeight.normal,
            ),
          ),
          Text(
            '${isNegative ? "-" : ""}\$${amount.toStringAsFixed(2)}',
            style: TextStyle(
              color: color ?? Colors.white,
              fontSize: isHeader ? 14 : 13,
              fontWeight: isHeader ? FontWeight.bold : FontWeight.w500,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildStatChip(String value, String label, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: color.withOpacity(0.15),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            value,
            style: TextStyle(
              color: color,
              fontSize: 12,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(width: 4),
          Text(
            label,
            style: TextStyle(
              color: color.withOpacity(0.8),
              fontSize: 10,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildClosingSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'CIERRE',
          style: TextStyle(
            color: Color(0xFFD4AF37),
            fontSize: 12,
            fontWeight: FontWeight.bold,
            letterSpacing: 1,
          ),
        ),
        const SizedBox(height: 12),

        // Efectivo contado
        const Text(
          'Efectivo contado',
          style: TextStyle(
            color: Colors.grey,
            fontSize: 13,
          ),
        ),
        const SizedBox(height: 8),
        TextFormField(
          controller: _closingAmountController,
          keyboardType: const TextInputType.numberWithOptions(decimal: true),
          inputFormatters: [
            FilteringTextInputFormatter.allow(RegExp(r'^\d*\.?\d{0,2}')),
          ],
          style: const TextStyle(
            color: Colors.white,
            fontSize: 22,
            fontWeight: FontWeight.bold,
          ),
          onChanged: (_) => setState(() {}),
          decoration: InputDecoration(
            prefixText: '\$ ',
            prefixStyle: const TextStyle(
              color: Color(0xFFD4AF37),
              fontSize: 22,
              fontWeight: FontWeight.bold,
            ),
            filled: true,
            fillColor: const Color(0xFF2A2A2A),
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(10),
              borderSide: BorderSide.none,
            ),
            focusedBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(10),
              borderSide: const BorderSide(color: Color(0xFFD4AF37), width: 1),
            ),
          ),
          validator: (value) {
            if (value == null || value.isEmpty) {
              return 'Ingrese el efectivo contado';
            }
            final amount = double.tryParse(value);
            if (amount == null || amount < 0) {
              return 'Monto inválido';
            }
            return null;
          },
        ),
        const SizedBox(height: 12),

        // Diferencia
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: _difference == 0
                ? Colors.green.withOpacity(0.1)
                : (_difference > 0
                    ? Colors.blue.withOpacity(0.1)
                    : Colors.red.withOpacity(0.1)),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(
              color: _difference == 0
                  ? Colors.green.withOpacity(0.3)
                  : (_difference > 0
                      ? Colors.blue.withOpacity(0.3)
                      : Colors.red.withOpacity(0.3)),
            ),
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                'Diferencia:',
                style: TextStyle(
                  color: Colors.grey.shade400,
                  fontSize: 14,
                ),
              ),
              Text(
                '${_difference >= 0 ? '+' : ''}\$${_difference.toStringAsFixed(2)}',
                style: TextStyle(
                  color: _difference == 0
                      ? Colors.green
                      : (_difference > 0 ? Colors.blue : Colors.red),
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),

        // Nota
        const Text(
          'Nota del cierre',
          style: TextStyle(
            color: Colors.grey,
            fontSize: 13,
          ),
        ),
        const SizedBox(height: 8),
        TextFormField(
          controller: _noteController,
          maxLines: 2,
          style: const TextStyle(color: Colors.white),
          decoration: InputDecoration(
            hintText: 'Observaciones del cierre...',
            hintStyle: TextStyle(color: Colors.grey.shade600),
            filled: true,
            fillColor: const Color(0xFF2A2A2A),
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(10),
              borderSide: BorderSide.none,
            ),
          ),
        ),
      ],
    );
  }
}

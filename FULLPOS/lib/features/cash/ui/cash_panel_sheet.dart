import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';
import '../data/cash_movement_model.dart';
import '../data/cash_summary_model.dart';
import '../data/cash_repository.dart';
import 'cash_movement_dialog.dart';
import 'cash_close_dialog.dart';

/// Panel lateral de caja con resumen y opciones
class CashPanelSheet extends ConsumerStatefulWidget {
  final int sessionId;

  const CashPanelSheet({super.key, required this.sessionId});

  static Future<void> show(BuildContext context, {required int sessionId}) {
    return showDialog(
      context: context,
      builder: (context) => CashPanelSheet(sessionId: sessionId),
    );
  }

  @override
  ConsumerState<CashPanelSheet> createState() => _CashPanelSheetState();
}

class _CashPanelSheetState extends ConsumerState<CashPanelSheet> {
  bool _loadingSummary = true;
  bool _loadingMovements = true;
  CashSummaryModel? _summary;
  List<CashMovementModel> _movements = [];

  @override
  void initState() {
    super.initState();
    _loadData();
  }

  Future<void> _loadData() async {
    await Future.wait([_loadSummary(), _loadMovements()]);
  }

  Future<void> _loadSummary() async {
    try {
      final summary = await CashRepository.buildSummary(
        sessionId: widget.sessionId,
      );
      if (mounted) {
        setState(() {
          _summary = summary;
          _loadingSummary = false;
        });
      }
    } catch (e) {
      if (mounted) setState(() => _loadingSummary = false);
    }
  }

  Future<void> _loadMovements() async {
    try {
      final movements = await CashRepository.listMovements(
        sessionId: widget.sessionId,
      );
      if (mounted) {
        setState(() {
          _movements = movements;
          _loadingMovements = false;
        });
      }
    } catch (e) {
      if (mounted) setState(() => _loadingMovements = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: const Color(0xFF1E1E1E),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
      child: Container(
        constraints: const BoxConstraints(maxWidth: 520, maxHeight: 680),
        child: Column(
          children: [
            // Header
            Padding(
              padding: const EdgeInsets.fromLTRB(24, 20, 20, 16),
              child: Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: const Color(0xFFD4AF37).withOpacity(0.2),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: const Icon(
                      Icons.point_of_sale,
                      color: Color(0xFFD4AF37),
                      size: 24,
                    ),
                  ),
                  const SizedBox(width: 12),
                  const Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'PANEL DE CAJA',
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                          color: Colors.white,
                        ),
                      ),
                      Text(
                        'Caja abierta',
                        style: TextStyle(fontSize: 12, color: Colors.green),
                      ),
                    ],
                  ),
                  const Spacer(),
                  IconButton(
                    onPressed: () => Navigator.pop(context),
                    icon: const Icon(Icons.close, color: Colors.grey),
                  ),
                ],
              ),
            ),

            // Acciones rápidas
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24),
              child: Row(
                children: [
                  Expanded(
                    child: _buildActionButton(
                      icon: Icons.add_circle_outline,
                      label: 'Entrada',
                      color: Colors.green,
                      onTap: () => _showMovementDialog(CashMovementType.income),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: _buildActionButton(
                      icon: Icons.remove_circle_outline,
                      label: 'Retiro',
                      color: Colors.orange,
                      onTap: () =>
                          _showMovementDialog(CashMovementType.outcome),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: _buildActionButton(
                      icon: Icons.lock_outline,
                      label: 'Corte',
                      color: Colors.red,
                      onTap: _showCloseDialog,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 20),

            // Contenido con tabs
            Expanded(
              child: DefaultTabController(
                length: 2,
                child: Column(
                  children: [
                    TabBar(
                      indicatorColor: const Color(0xFFD4AF37),
                      labelColor: const Color(0xFFD4AF37),
                      unselectedLabelColor: Colors.grey,
                      tabs: const [
                        Tab(text: 'RESUMEN'),
                        Tab(text: 'MOVIMIENTOS'),
                      ],
                    ),
                    Expanded(
                      child: TabBarView(
                        children: [_buildSummaryTab(), _buildMovementsTab()],
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildActionButton({
    required IconData icon,
    required String label,
    required Color color,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(10),
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 12),
        decoration: BoxDecoration(
          color: color.withOpacity(0.15),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: color.withOpacity(0.3)),
        ),
        child: Column(
          children: [
            Icon(icon, color: color, size: 24),
            const SizedBox(height: 4),
            Text(
              label,
              style: TextStyle(
                color: color,
                fontSize: 11,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSummaryTab() {
    if (_loadingSummary) {
      return const Center(
        child: CircularProgressIndicator(color: Color(0xFFD4AF37)),
      );
    }

    if (_summary == null) {
      return const Center(
        child: Text(
          'No se pudo cargar el resumen',
          style: TextStyle(color: Colors.grey),
        ),
      );
    }

    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Column(
        children: [
          _buildSummaryCard(),
          const SizedBox(height: 16),
          _buildSalesBreakdown(),
        ],
      ),
    );
  }

  Widget _buildSummaryCard() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            const Color(0xFFD4AF37).withOpacity(0.2),
            const Color(0xFF2A2A2A),
          ],
        ),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFFD4AF37).withOpacity(0.3)),
      ),
      child: Column(
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Text(
                'EFECTIVO ESPERADO',
                style: TextStyle(
                  color: Colors.grey,
                  fontSize: 12,
                  letterSpacing: 1,
                ),
              ),
              IconButton(
                onPressed: _loadData,
                icon: const Icon(Icons.refresh, color: Colors.grey, size: 20),
                splashRadius: 18,
              ),
            ],
          ),
          Text(
            '\$${_summary!.expectedCash.toStringAsFixed(2)}',
            style: const TextStyle(
              color: Color(0xFFD4AF37),
              fontSize: 36,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 16),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceEvenly,
            children: [
              _buildMiniStat(
                'Apertura',
                '\$${_summary!.openingAmount.toStringAsFixed(2)}',
                Colors.white,
              ),
              _buildMiniStat(
                'Tickets',
                '${_summary!.totalTickets}',
                Colors.blue,
              ),
              _buildMiniStat(
                'Ventas',
                '\$${_summary!.totalSales.toStringAsFixed(2)}',
                Colors.green,
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildMiniStat(String label, String value, Color color) {
    return Column(
      children: [
        Text(
          value,
          style: TextStyle(
            color: color,
            fontSize: 16,
            fontWeight: FontWeight.bold,
          ),
        ),
        Text(
          label,
          style: TextStyle(color: Colors.grey.shade500, fontSize: 11),
        ),
      ],
    );
  }

  Widget _buildSalesBreakdown() {
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
            'DESGLOSE',
            style: TextStyle(
              color: Colors.grey,
              fontSize: 12,
              letterSpacing: 1,
            ),
          ),
          const SizedBox(height: 12),
          _buildBreakdownRow(
            Icons.payments,
            'Ventas Efectivo',
            _summary!.salesCashTotal,
            Colors.green,
          ),
          _buildBreakdownRow(
            Icons.credit_card,
            'Ventas Tarjeta',
            _summary!.salesCardTotal,
            Colors.blue,
          ),
          _buildBreakdownRow(
            Icons.swap_horiz,
            'Transferencias',
            _summary!.salesTransferTotal,
            Colors.cyan,
          ),
          _buildBreakdownRow(
            Icons.schedule,
            'Créditos',
            _summary!.salesCreditTotal,
            Colors.orange,
          ),
          const Divider(color: Colors.grey, height: 20),
          _buildBreakdownRow(
            Icons.add_circle,
            'Entradas manuales',
            _summary!.cashInManual,
            Colors.green,
          ),
          _buildBreakdownRow(
            Icons.remove_circle,
            'Retiros manuales',
            _summary!.cashOutManual,
            Colors.red,
          ),
          if (_summary!.refundsCash > 0)
            _buildBreakdownRow(
              Icons.undo,
              'Devoluciones',
              _summary!.refundsCash,
              Colors.red,
            ),
        ],
      ),
    );
  }

  Widget _buildBreakdownRow(
    IconData icon,
    String label,
    double amount,
    Color color,
  ) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        children: [
          Icon(icon, color: color, size: 18),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              label,
              style: const TextStyle(color: Colors.white, fontSize: 13),
            ),
          ),
          Text(
            '\$${amount.toStringAsFixed(2)}',
            style: TextStyle(
              color: color,
              fontSize: 13,
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildMovementsTab() {
    if (_loadingMovements) {
      return const Center(
        child: CircularProgressIndicator(color: Color(0xFFD4AF37)),
      );
    }

    if (_movements.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.inbox_outlined, color: Colors.grey.shade600, size: 48),
            const SizedBox(height: 12),
            const Text(
              'No hay movimientos registrados',
              style: TextStyle(color: Colors.grey),
            ),
          ],
        ),
      );
    }

    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: _movements.length,
      itemBuilder: (context, index) {
        final movement = _movements[index];
        final isIncome = movement.isIn;
        final dateFormat = DateFormat('HH:mm');

        return Container(
          margin: const EdgeInsets.only(bottom: 8),
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: const Color(0xFF2A2A2A),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Row(
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: (isIncome ? Colors.green : Colors.red).withOpacity(
                    0.2,
                  ),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Icon(
                  isIncome ? Icons.add : Icons.remove,
                  color: isIncome ? Colors.green : Colors.red,
                  size: 18,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      movement.reason,
                      style: const TextStyle(color: Colors.white, fontSize: 13),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    Text(
                      dateFormat.format(movement.createdAt),
                      style: TextStyle(
                        color: Colors.grey.shade600,
                        fontSize: 11,
                      ),
                    ),
                  ],
                ),
              ),
              Text(
                '${isIncome ? '+' : '-'}\$${movement.amount.toStringAsFixed(2)}',
                style: TextStyle(
                  color: isIncome ? Colors.green : Colors.red,
                  fontSize: 14,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  Future<void> _showMovementDialog(String type) async {
    final result = await CashMovementDialog.show(
      context,
      type: type,
      sessionId: widget.sessionId,
    );

    if (result == true) {
      _loadData();
    }
  }

  Future<void> _showCloseDialog() async {
    final result = await CashCloseDialog.show(
      context,
      sessionId: widget.sessionId,
    );

    if (result == true && mounted) {
      Navigator.pop(context); // Cerrar el panel también
    }
  }
}

import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../../../core/constants/app_colors.dart';
import '../../../core/constants/app_sizes.dart';
import '../../../core/errors/error_handler.dart';
import '../../clients/data/clients_repository.dart';
import '../data/loans_repository.dart';
import '../data/loan_models.dart';
import 'dialogs/loan_form_dialog.dart';
import 'dialogs/loan_detail_dialog.dart';

/// Página de Préstamos (Full)
class LoansPage extends StatefulWidget {
  const LoansPage({super.key});

  @override
  State<LoansPage> createState() => _LoansPageState();
}

class _LoansPageState extends State<LoansPage> {
  bool _isLoading = true;
  List<LoanModel> _loans = [];
  Map<int, String> _clientNames = {};
  String? _statusFilter;
  LoansKpis? _kpis;

  @override
  void initState() {
    super.initState();
    _loadData();
  }

  Future<void> _loadData() async {
    setState(() => _isLoading = true);

    try {
      await LoansRepository.recalculateOverdueStatuses();
      
      final loans = await LoansRepository.listLoans(statusFilter: _statusFilter);
      
      // Cargar nombres de clientes
      final clientNames = <int, String>{};
      final clients = await ClientsRepository.list();
      for (final c in clients) {
        if (c.id != null) clientNames[c.id!] = c.nombre;
      }

      // Cargar KPIs
      final now = DateTime.now();
      final startOfMonth = DateTime(now.year, now.month, 1);
      final kpis = await LoansRepository.getLoansKpis(
        startMs: startOfMonth.millisecondsSinceEpoch,
        endMs: now.millisecondsSinceEpoch,
      );

      setState(() {
        _loans = loans;
        _clientNames = clientNames;
        _kpis = kpis;
        _isLoading = false;
      });
    } catch (e, st) {
      setState(() => _isLoading = false);
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: _loadData,
          module: 'loans/load',
        );
      }
    }
  }

  void _onFilterChanged(String? filter) {
    setState(() => _statusFilter = filter);
    _loadData();
  }

  Future<void> _showCreateLoanDialog() async {
    final result = await showDialog<bool>(
      context: context,
      builder: (context) => const LoanFormDialog(),
    );

    if (result == true) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Préstamo creado exitosamente'), backgroundColor: AppColors.success),
      );
      _loadData();
    }
  }

  void _showLoanDetail(LoanModel loan) {
    showDialog(
      context: context,
      builder: (context) => LoanDetailDialog(loanId: loan.id!),
    ).then((_) => _loadData());
  }

  @override
  Widget build(BuildContext context) {
    final currencyFormat = NumberFormat.currency(locale: 'es_DO', symbol: 'RD\$');

    return Scaffold(
      backgroundColor: AppColors.bgLight,
      body: Column(
        children: [
          // Encabezado compacto
          Container(
            padding: const EdgeInsets.all(AppSizes.paddingM),
            decoration: BoxDecoration(
              color: Colors.white,
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.05),
                  blurRadius: 4,
                  offset: const Offset(0, 2),
                ),
              ],
            ),
            child: Column(
              children: [
                Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: AppColors.teal.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: const Icon(Icons.handshake, size: 24, color: AppColors.teal),
                    ),
                    const SizedBox(width: AppSizes.paddingM),
                    const Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'Préstamos',
                            style: TextStyle(
                              fontSize: 20,
                              fontWeight: FontWeight.bold,
                              color: AppColors.textDark,
                            ),
                          ),
                          Text(
                            'Gestión completa de préstamos',
                            style: TextStyle(fontSize: 12, color: Colors.black54),
                          ),
                        ],
                      ),
                    ),
                    ElevatedButton.icon(
                      onPressed: _showCreateLoanDialog,
                      icon: const Icon(Icons.add, size: 18),
                      label: const Text('Nuevo'),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: AppColors.gold,
                        foregroundColor: Colors.white,
                        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                      ),
                    ),
                  ],
                ),

                // KPIs
                if (_kpis != null) ...[
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      Expanded(child: _KpiCard(
                        label: 'Cartera Activa',
                        value: currencyFormat.format(_kpis!.activeBalance),
                        icon: Icons.account_balance_wallet,
                        color: AppColors.teal,
                      )),
                      const SizedBox(width: 8),
                      Expanded(child: _KpiCard(
                        label: 'Cobrado (mes)',
                        value: currencyFormat.format(_kpis!.totalCollected),
                        icon: Icons.trending_up,
                        color: Colors.green,
                      )),
                      const SizedBox(width: 8),
                      Expanded(child: _KpiCard(
                        label: 'Vencidos',
                        value: '${_kpis!.overdueCount}',
                        icon: Icons.warning_amber,
                        color: _kpis!.overdueCount > 0 ? Colors.red : Colors.grey,
                      )),
                    ],
                  ),
                ],

                const SizedBox(height: 12),
                
                // Filtros
                SingleChildScrollView(
                  scrollDirection: Axis.horizontal,
                  child: Row(
                    children: [
                      _FilterChip(label: 'Todos', value: null, selected: _statusFilter, onSelected: _onFilterChanged),
                      const SizedBox(width: 8),
                      _FilterChip(label: 'Activos', value: LoanStatus.open, selected: _statusFilter, onSelected: _onFilterChanged),
                      const SizedBox(width: 8),
                      _FilterChip(label: 'Vencidos', value: LoanStatus.overdue, selected: _statusFilter, onSelected: _onFilterChanged),
                      const SizedBox(width: 8),
                      _FilterChip(label: 'Pagados', value: LoanStatus.paid, selected: _statusFilter, onSelected: _onFilterChanged),
                    ],
                  ),
                ),
              ],
            ),
          ),

          // Lista de préstamos
          Expanded(
            child: _isLoading
                ? const Center(child: CircularProgressIndicator())
                : _loans.isEmpty
                    ? Center(
                        child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(Icons.handshake_outlined, size: 64, color: Colors.grey.shade400),
                            const SizedBox(height: 16),
                            Text(
                              _statusFilter == null ? 'No hay préstamos' : 'Sin resultados',
                              style: TextStyle(fontSize: 16, color: Colors.grey.shade600),
                            ),
                            const SizedBox(height: 8),
                            if (_statusFilter == null)
                              ElevatedButton.icon(
                                onPressed: _showCreateLoanDialog,
                                icon: const Icon(Icons.add),
                                label: const Text('Crear Primer Préstamo'),
                              ),
                          ],
                        ),
                      )
                    : ListView.builder(
                        padding: const EdgeInsets.all(12),
                        itemCount: _loans.length,
                        itemBuilder: (context, index) {
                          final loan = _loans[index];
                          return _LoanCard(
                            loan: loan,
                            clientName: _clientNames[loan.clientId] ?? 'Cliente #${loan.clientId}',
                            onTap: () => _showLoanDetail(loan),
                          );
                        },
                      ),
          ),
        ],
      ),
    );
  }
}

class _KpiCard extends StatelessWidget {
  final String label;
  final String value;
  final IconData icon;
  final Color color;

  const _KpiCard({
    required this.label,
    required this.value,
    required this.icon,
    required this.color,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: color.withOpacity(0.05),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color.withOpacity(0.2)),
      ),
      child: Row(
        children: [
          Icon(icon, size: 18, color: color),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(label, style: TextStyle(fontSize: 10, color: Colors.grey.shade600)),
                Text(
                  value,
                  style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: color),
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _FilterChip extends StatelessWidget {
  final String label;
  final String? value;
  final String? selected;
  final Function(String?) onSelected;

  const _FilterChip({
    required this.label,
    required this.value,
    required this.selected,
    required this.onSelected,
  });

  @override
  Widget build(BuildContext context) {
    final isSelected = selected == value;
    return ChoiceChip(
      label: Text(label, style: TextStyle(fontSize: 12)),
      selected: isSelected,
      onSelected: (s) => s ? onSelected(value) : null,
      selectedColor: AppColors.teal,
      labelStyle: TextStyle(
        color: isSelected ? Colors.white : Colors.black87,
        fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
      ),
      padding: const EdgeInsets.symmetric(horizontal: 4),
      visualDensity: VisualDensity.compact,
    );
  }
}

class _LoanCard extends StatelessWidget {
  final LoanModel loan;
  final String clientName;
  final VoidCallback onTap;

  const _LoanCard({
    required this.loan,
    required this.clientName,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final currencyFormat = NumberFormat.currency(locale: 'es_DO', symbol: 'RD\$');
    final dateFormat = DateFormat('dd/MM/yyyy');
    final startDate = DateTime.fromMillisecondsSinceEpoch(loan.startDateMs);

    Color statusColor;
    String statusLabel;
    IconData statusIcon;

    switch (loan.status) {
      case LoanStatus.open:
        statusColor = Colors.green;
        statusLabel = 'Activo';
        statusIcon = Icons.check_circle;
        break;
      case LoanStatus.overdue:
        statusColor = Colors.red;
        statusLabel = 'Vencido';
        statusIcon = Icons.warning;
        break;
      case LoanStatus.paid:
        statusColor = Colors.blue;
        statusLabel = 'Pagado';
        statusIcon = Icons.verified;
        break;
      default:
        statusColor = Colors.grey;
        statusLabel = loan.status;
        statusIcon = Icons.info;
    }

    return Card(
      margin: const EdgeInsets.only(bottom: 10),
      elevation: 1,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(8),
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            children: [
              Row(
                children: [
                  // Avatar/icono
                  Container(
                    width: 44,
                    height: 44,
                    decoration: BoxDecoration(
                      color: statusColor.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: Icon(statusIcon, color: statusColor, size: 22),
                  ),
                  const SizedBox(width: 12),
                  // Info principal
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Expanded(
                              child: Text(
                                clientName,
                                style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 14),
                                overflow: TextOverflow.ellipsis,
                              ),
                            ),
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                              decoration: BoxDecoration(
                                color: statusColor.withOpacity(0.1),
                                borderRadius: BorderRadius.circular(10),
                              ),
                              child: Text(
                                statusLabel,
                                style: TextStyle(color: statusColor, fontSize: 11, fontWeight: FontWeight.w600),
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 4),
                        Row(
                          children: [
                            Text(
                              '#${loan.id}',
                              style: TextStyle(fontSize: 11, color: Colors.grey.shade600),
                            ),
                            Text(' • ', style: TextStyle(color: Colors.grey.shade400)),
                            Text(
                              loan.type == LoanType.secured ? 'Con garantía' : 'Sin garantía',
                              style: TextStyle(fontSize: 11, color: Colors.grey.shade600),
                            ),
                            Text(' • ', style: TextStyle(color: Colors.grey.shade400)),
                            Text(
                              dateFormat.format(startDate),
                              style: TextStyle(fontSize: 11, color: Colors.grey.shade600),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 10),
              // Barra de progreso
              ClipRRect(
                borderRadius: BorderRadius.circular(3),
                child: LinearProgressIndicator(
                  value: loan.progressPercent / 100,
                  minHeight: 6,
                  backgroundColor: Colors.grey.shade200,
                  valueColor: AlwaysStoppedAnimation<Color>(statusColor),
                ),
              ),
              const SizedBox(height: 8),
              // Montos
              Row(
                children: [
                  _AmountItem(label: 'Principal', value: currencyFormat.format(loan.principal)),
                  _AmountItem(label: 'Total', value: currencyFormat.format(loan.totalDue)),
                  _AmountItem(
                    label: 'Saldo',
                    value: currencyFormat.format(loan.balance),
                    color: loan.balance > 0 ? statusColor : Colors.green,
                    isBold: true,
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

class _AmountItem extends StatelessWidget {
  final String label;
  final String value;
  final Color? color;
  final bool isBold;

  const _AmountItem({
    required this.label,
    required this.value,
    this.color,
    this.isBold = false,
  });

  @override
  Widget build(BuildContext context) {
    return Expanded(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: TextStyle(fontSize: 10, color: Colors.grey.shade600)),
          const SizedBox(height: 2),
          Text(
            value,
            style: TextStyle(
              fontSize: 12,
              fontWeight: isBold ? FontWeight.bold : FontWeight.w500,
              color: color ?? AppColors.textDark,
            ),
          ),
        ],
      ),
    );
  }
}

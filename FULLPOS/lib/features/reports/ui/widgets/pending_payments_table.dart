import 'package:flutter/material.dart';
import '../../data/reports_repository.dart';
import '../../../../core/constants/app_colors.dart';

class PendingPaymentsTable extends StatelessWidget {
  final List<PendingPayment> payments;
  final VoidCallback? onViewAll;

  const PendingPaymentsTable({
    super.key,
    required this.payments,
    this.onViewAll,
  });

  @override
  Widget build(BuildContext context) {
    if (payments.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: AppColors.successLight,
                shape: BoxShape.circle,
              ),
              child: const Icon(
                Icons.check_circle_outline,
                size: 48,
                color: AppColors.success,
              ),
            ),
            const SizedBox(height: 16),
            const Text(
              '¡Todo al día!',
              style: TextStyle(
                color: AppColors.success,
                fontSize: 15,
                fontWeight: FontWeight.w600,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              'No hay pagos pendientes',
              style: TextStyle(color: Colors.grey.shade600, fontSize: 13),
            ),
          ],
        ),
      );
    }

    // Separar en vencidos y próximos
    final overduePayments = payments.where((p) => p.isOverdue).toList();
    final upcomingPayments = payments.where((p) => !p.isOverdue).toList();

    return Column(
      children: [
        // Summary header
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            gradient: LinearGradient(
              colors: [
                overduePayments.isNotEmpty
                    ? AppColors.error.withOpacity(0.1)
                    : AppColors.teal.withOpacity(0.1),
                Colors.white,
              ],
            ),
          ),
          child: Row(
            children: [
              if (overduePayments.isNotEmpty) ...[
                _buildSummaryChip(
                  '${overduePayments.length} Vencidos',
                  AppColors.error,
                  Icons.warning_rounded,
                ),
                const SizedBox(width: 12),
              ],
              _buildSummaryChip(
                '${upcomingPayments.length} Próximos',
                AppColors.teal,
                Icons.schedule,
              ),
              const Spacer(),
              Text(
                'Total: RD\$ ${_formatMoney(_calculateTotal(payments))}',
                style: const TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.bold,
                  color: Colors.black87,
                ),
              ),
            ],
          ),
        ),
        // Table header
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
          decoration: BoxDecoration(
            color: Colors.grey.shade50,
            border: Border(bottom: BorderSide(color: Colors.grey.shade300)),
          ),
          child: const Row(
            children: [
              Expanded(
                flex: 3,
                child: Text(
                  'Cliente',
                  style: TextStyle(fontWeight: FontWeight.w600, fontSize: 11),
                ),
              ),
              Expanded(
                flex: 1,
                child: Text(
                  'Cuota',
                  style: TextStyle(fontWeight: FontWeight.w600, fontSize: 11),
                  textAlign: TextAlign.center,
                ),
              ),
              Expanded(
                flex: 2,
                child: Text(
                  'Vencimiento',
                  style: TextStyle(fontWeight: FontWeight.w600, fontSize: 11),
                  textAlign: TextAlign.center,
                ),
              ),
              Expanded(
                flex: 2,
                child: Text(
                  'Pendiente',
                  style: TextStyle(fontWeight: FontWeight.w600, fontSize: 11),
                  textAlign: TextAlign.right,
                ),
              ),
            ],
          ),
        ),
        // Rows
        Expanded(
          child: ListView.builder(
            itemCount: payments.length,
            itemBuilder: (context, index) {
              final payment = payments[index];
              final isOverdue = payment.isOverdue;
              final dueDate = DateTime.fromMillisecondsSinceEpoch(
                payment.dueDateMs,
              );
              final daysOverdue = isOverdue
                  ? DateTime.now().difference(dueDate).inDays
                  : dueDate.difference(DateTime.now()).inDays;

              return Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 16,
                  vertical: 10,
                ),
                decoration: BoxDecoration(
                  color: isOverdue
                      ? AppColors.errorLight.withOpacity(0.3)
                      : null,
                  border: Border(
                    bottom: BorderSide(color: Colors.grey.shade200),
                    left: BorderSide(
                      color: isOverdue ? AppColors.error : Colors.transparent,
                      width: 3,
                    ),
                  ),
                ),
                child: Row(
                  children: [
                    Expanded(
                      flex: 3,
                      child: Row(
                        children: [
                          Container(
                            padding: const EdgeInsets.all(6),
                            decoration: BoxDecoration(
                              color: isOverdue
                                  ? AppColors.error.withOpacity(0.1)
                                  : AppColors.teal.withOpacity(0.1),
                              borderRadius: BorderRadius.circular(6),
                            ),
                            child: Icon(
                              isOverdue ? Icons.person_off : Icons.person,
                              size: 16,
                              color: isOverdue
                                  ? AppColors.error
                                  : AppColors.teal,
                            ),
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  payment.clientName,
                                  style: const TextStyle(
                                    fontSize: 12,
                                    fontWeight: FontWeight.w500,
                                  ),
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                ),
                                Text(
                                  'Préstamo #${payment.loanId}',
                                  style: TextStyle(
                                    fontSize: 10,
                                    color: Colors.grey.shade600,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),
                    Expanded(
                      flex: 1,
                      child: Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 8,
                          vertical: 4,
                        ),
                        decoration: BoxDecoration(
                          color: Colors.grey.shade100,
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: Text(
                          '#${payment.installmentNumber}',
                          style: const TextStyle(
                            fontSize: 11,
                            fontWeight: FontWeight.w600,
                          ),
                          textAlign: TextAlign.center,
                        ),
                      ),
                    ),
                    Expanded(
                      flex: 2,
                      child: Column(
                        children: [
                          Text(
                            _formatDate(dueDate),
                            style: TextStyle(
                              fontSize: 11,
                              color: isOverdue
                                  ? AppColors.error
                                  : Colors.black87,
                              fontWeight: isOverdue
                                  ? FontWeight.w600
                                  : FontWeight.normal,
                            ),
                            textAlign: TextAlign.center,
                          ),
                          Text(
                            isOverdue
                                ? 'Hace $daysOverdue días'
                                : (daysOverdue == 0
                                      ? 'Hoy'
                                      : 'En $daysOverdue días'),
                            style: TextStyle(
                              fontSize: 10,
                              color: isOverdue
                                  ? AppColors.error
                                  : AppColors.teal,
                              fontWeight: FontWeight.w500,
                            ),
                            textAlign: TextAlign.center,
                          ),
                        ],
                      ),
                    ),
                    Expanded(
                      flex: 2,
                      child: Text(
                        'RD\$ ${_formatMoney(payment.remaining)}',
                        style: TextStyle(
                          fontSize: 12,
                          fontWeight: FontWeight.bold,
                          color: isOverdue ? AppColors.error : AppColors.teal,
                        ),
                        textAlign: TextAlign.right,
                      ),
                    ),
                  ],
                ),
              );
            },
          ),
        ),
        if (onViewAll != null)
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              border: Border(top: BorderSide(color: Colors.grey.shade300)),
            ),
            child: TextButton.icon(
              onPressed: onViewAll,
              icon: const Icon(Icons.open_in_new, size: 16),
              label: const Text('Ver todos los pagos'),
              style: TextButton.styleFrom(foregroundColor: AppColors.teal),
            ),
          ),
      ],
    );
  }

  Widget _buildSummaryChip(String label, Color color, IconData icon) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: color.withOpacity(0.3)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 14, color: color),
          const SizedBox(width: 4),
          Text(
            label,
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.w600,
              color: color,
            ),
          ),
        ],
      ),
    );
  }

  double _calculateTotal(List<PendingPayment> payments) {
    return payments.fold<double>(0, (sum, p) => sum + p.remaining);
  }

  String _formatMoney(double value) {
    if (value >= 1000000) {
      return '${(value / 1000000).toStringAsFixed(2)}M';
    } else if (value >= 1000) {
      return '${(value / 1000).toStringAsFixed(1)}K';
    }
    return value.toStringAsFixed(2);
  }

  String _formatDate(DateTime date) {
    return '${date.day.toString().padLeft(2, '0')}/${date.month.toString().padLeft(2, '0')}/${date.year}';
  }
}

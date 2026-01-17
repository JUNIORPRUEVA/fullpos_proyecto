import 'package:flutter/material.dart';
import '../../data/reports_repository.dart';
import '../../../../core/constants/app_colors.dart';

class AdvancedKpiCards extends StatelessWidget {
  final KpisData kpis;

  const AdvancedKpiCards({super.key, required this.kpis});

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        // Primera fila - KPIs principales de ventas
        Row(
          children: [
            Expanded(
              child: _buildMainKpiCard(
                title: 'Total Ventas',
                value: kpis.totalSales,
                icon: Icons.point_of_sale,
                color: AppColors.teal,
                subtitle: '${kpis.salesCount} transacciones',
              ),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: _buildMainKpiCard(
                title: 'Ganancia Neta',
                value: kpis.totalProfit,
                icon: Icons.trending_up,
                color: AppColors.success,
                subtitle:
                    '${_calculateMargin(kpis.totalProfit, kpis.totalSales).toStringAsFixed(1)}% margen',
              ),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: _buildMainKpiCard(
                title: 'Cartera Préstamos',
                value: kpis.loansBalance,
                icon: Icons.account_balance_wallet,
                color: AppColors.gold,
                subtitle: '${kpis.loansActive} préstamos activos',
                isAlert: kpis.loansOverdue > 0,
                alertText: '${kpis.loansOverdue} vencidos',
              ),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: _buildMainKpiCard(
                title: 'Cobros Préstamos',
                value: kpis.loansCollected,
                icon: Icons.payments,
                color: Colors.blue.shade700,
                subtitle: 'RD\$ ${_formatMoney(kpis.loansLent)} prestados',
              ),
            ),
          ],
        ),
        const SizedBox(height: 16),
        // Segunda fila - KPIs secundarios
        Row(
          children: [
            Expanded(
              child: _buildSecondaryKpiCard(
                title: 'Ticket Promedio',
                value: 'RD\$ ${_formatMoney(kpis.avgTicket)}',
                icon: Icons.receipt_long,
                color: Colors.purple.shade600,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _buildSecondaryKpiCard(
                title: 'Cotizaciones',
                value: '${kpis.quotesCount}',
                icon: Icons.description_outlined,
                color: Colors.orange.shade600,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _buildSecondaryKpiCard(
                title: 'Conversión',
                value: kpis.quotesCount > 0
                    ? '${((kpis.quotesConverted / kpis.quotesCount) * 100).toStringAsFixed(0)}%'
                    : '0%',
                icon: Icons.swap_horiz,
                color: Colors.cyan.shade700,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _buildSecondaryKpiCard(
                title: 'Ingresos Caja',
                value: 'RD\$ ${_formatMoney(kpis.cashIncome)}',
                icon: Icons.arrow_downward,
                color: AppColors.success,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _buildSecondaryKpiCard(
                title: 'Egresos Caja',
                value: 'RD\$ ${_formatMoney(kpis.cashExpense)}',
                icon: Icons.arrow_upward,
                color: AppColors.error,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _buildSecondaryKpiCard(
                title: 'Balance Caja',
                value:
                    'RD\$ ${_formatMoney(kpis.cashIncome - kpis.cashExpense)}',
                icon: Icons.account_balance,
                color: (kpis.cashIncome - kpis.cashExpense) >= 0
                    ? AppColors.success
                    : AppColors.error,
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildMainKpiCard({
    required String title,
    required double value,
    required IconData icon,
    required Color color,
    required String subtitle,
    bool isAlert = false,
    String? alertText,
  }) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [Colors.white, color.withOpacity(0.05)],
        ),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: color.withOpacity(0.2)),
        boxShadow: [
          BoxShadow(
            color: color.withOpacity(0.1),
            blurRadius: 10,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: color.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Icon(icon, color: color, size: 24),
              ),
              const Spacer(),
              if (isAlert && alertText != null)
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 8,
                    vertical: 4,
                  ),
                  decoration: BoxDecoration(
                    color: AppColors.error.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(
                        Icons.warning,
                        size: 12,
                        color: AppColors.error,
                      ),
                      const SizedBox(width: 4),
                      Text(
                        alertText,
                        style: const TextStyle(
                          fontSize: 10,
                          fontWeight: FontWeight.bold,
                          color: AppColors.error,
                        ),
                      ),
                    ],
                  ),
                ),
            ],
          ),
          const SizedBox(height: 16),
          Text(
            title,
            style: TextStyle(
              fontSize: 13,
              color: Colors.grey.shade600,
              fontWeight: FontWeight.w500,
            ),
          ),
          const SizedBox(height: 6),
          Text(
            'RD\$ ${_formatMoney(value)}',
            style: TextStyle(
              fontSize: 26,
              fontWeight: FontWeight.bold,
              color: color,
            ),
          ),
          const SizedBox(height: 6),
          Text(
            subtitle,
            style: TextStyle(fontSize: 12, color: Colors.grey.shade500),
          ),
        ],
      ),
    );
  }

  Widget _buildSecondaryKpiCard({
    required String title,
    required String value,
    required IconData icon,
    required Color color,
  }) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.grey.shade200),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.03),
            blurRadius: 8,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: color.withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(icon, color: color, size: 18),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: TextStyle(fontSize: 11, color: Colors.grey.shade600),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
                const SizedBox(height: 2),
                Text(
                  value,
                  style: TextStyle(
                    fontSize: 15,
                    fontWeight: FontWeight.bold,
                    color: color,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  double _calculateMargin(double profit, double sales) {
    if (sales <= 0) return 0;
    return (profit / sales) * 100;
  }

  String _formatMoney(double value) {
    if (value >= 1000000) {
      return '${(value / 1000000).toStringAsFixed(2)}M';
    } else if (value >= 1000) {
      return '${(value / 1000).toStringAsFixed(1)}K';
    }
    return value.toStringAsFixed(2);
  }
}

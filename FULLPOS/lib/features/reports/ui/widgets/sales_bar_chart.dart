import 'package:flutter/material.dart';
import 'package:fl_chart/fl_chart.dart';
import '../../data/reports_repository.dart';
import '../../../../core/constants/app_colors.dart';

class SalesBarChart extends StatefulWidget {
  final List<SeriesDataPoint> data;
  final Color barColor;
  final String title;

  const SalesBarChart({
    super.key,
    required this.data,
    this.barColor = AppColors.teal,
    this.title = 'Ventas',
  });

  @override
  State<SalesBarChart> createState() => _SalesBarChartState();
}

class _SalesBarChartState extends State<SalesBarChart> {
  int touchedIndex = -1;

  @override
  Widget build(BuildContext context) {
    if (widget.data.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.bar_chart, size: 48, color: Colors.black26),
            const SizedBox(height: 8),
            const Text(
              'No hay datos para mostrar',
              style: TextStyle(color: Colors.black54),
            ),
          ],
        ),
      );
    }

    final maxY = widget.data
        .map((e) => e.value)
        .reduce((a, b) => a > b ? a : b);

    return Padding(
      padding: const EdgeInsets.only(top: 16, right: 16, bottom: 8),
      child: BarChart(
        BarChartData(
          maxY: maxY * 1.15,
          barTouchData: BarTouchData(
            touchTooltipData: BarTouchTooltipData(
              getTooltipColor: (group) => Colors.grey.shade800,
              tooltipPadding: const EdgeInsets.symmetric(
                horizontal: 12,
                vertical: 8,
              ),
              tooltipMargin: 8,
              getTooltipItem: (group, groupIndex, rod, rodIndex) {
                final item = widget.data[group.x.toInt()];
                return BarTooltipItem(
                  '${_formatDate(item.label)}\n',
                  const TextStyle(
                    color: Colors.white,
                    fontWeight: FontWeight.w500,
                    fontSize: 12,
                  ),
                  children: [
                    TextSpan(
                      text: 'RD\$ ${_formatMoney(item.value)}',
                      style: TextStyle(
                        color: AppColors.gold,
                        fontWeight: FontWeight.bold,
                        fontSize: 14,
                      ),
                    ),
                  ],
                );
              },
            ),
            touchCallback: (FlTouchEvent event, barTouchResponse) {
              setState(() {
                if (!event.isInterestedForInteractions ||
                    barTouchResponse == null ||
                    barTouchResponse.spot == null) {
                  touchedIndex = -1;
                  return;
                }
                touchedIndex = barTouchResponse.spot!.touchedBarGroupIndex;
              });
            },
          ),
          titlesData: FlTitlesData(
            show: true,
            rightTitles: const AxisTitles(
              sideTitles: SideTitles(showTitles: false),
            ),
            topTitles: const AxisTitles(
              sideTitles: SideTitles(showTitles: false),
            ),
            bottomTitles: AxisTitles(
              sideTitles: SideTitles(
                showTitles: true,
                reservedSize: 32,
                getTitlesWidget: (value, meta) {
                  final index = value.toInt();
                  if (index < 0 || index >= widget.data.length) {
                    return const SizedBox.shrink();
                  }

                  // Mostrar cada N etiquetas para evitar superposición
                  final showEvery = widget.data.length > 14
                      ? 3
                      : (widget.data.length > 7 ? 2 : 1);
                  if (index % showEvery != 0 &&
                      index != widget.data.length - 1) {
                    return const SizedBox.shrink();
                  }

                  final label = widget.data[index].label;
                  final parts = label.split('-');
                  final day = parts.length >= 3
                      ? '${parts[2]}/${parts[1]}'
                      : label;

                  return Padding(
                    padding: const EdgeInsets.only(top: 8),
                    child: Text(
                      day,
                      style: const TextStyle(
                        color: Colors.black54,
                        fontSize: 10,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                  );
                },
              ),
            ),
            leftTitles: AxisTitles(
              sideTitles: SideTitles(
                showTitles: true,
                reservedSize: 50,
                interval: maxY > 0 ? maxY / 4 : 1,
                getTitlesWidget: (value, meta) {
                  return Text(
                    _formatMoney(value),
                    style: const TextStyle(color: Colors.black54, fontSize: 10),
                  );
                },
              ),
            ),
          ),
          borderData: FlBorderData(
            show: true,
            border: Border(
              left: BorderSide(color: Colors.grey.shade300),
              bottom: BorderSide(color: Colors.grey.shade300),
            ),
          ),
          gridData: FlGridData(
            show: true,
            drawVerticalLine: false,
            horizontalInterval: maxY > 0 ? maxY / 4 : 1,
            getDrawingHorizontalLine: (value) {
              return FlLine(color: Colors.grey.shade200, strokeWidth: 1);
            },
          ),
          barGroups: _buildBarGroups(maxY),
        ),
      ),
    );
  }

  List<BarChartGroupData> _buildBarGroups(double maxY) {
    return widget.data.asMap().entries.map((entry) {
      final index = entry.key;
      final item = entry.value;
      final isTouched = index == touchedIndex;

      return BarChartGroupData(
        x: index,
        barRods: [
          BarChartRodData(
            toY: item.value,
            color: isTouched
                ? widget.barColor.withOpacity(0.8)
                : widget.barColor,
            width: _calculateBarWidth(),
            borderRadius: const BorderRadius.vertical(top: Radius.circular(4)),
            backDrawRodData: BackgroundBarChartRodData(
              show: true,
              toY: maxY * 1.15,
              color: Colors.grey.shade100,
            ),
          ),
        ],
      );
    }).toList();
  }

  double _calculateBarWidth() {
    final count = widget.data.length;
    if (count <= 7) return 28;
    if (count <= 14) return 18;
    if (count <= 21) return 12;
    return 8;
  }

  String _formatMoney(double value) {
    if (value >= 1000000) {
      return '${(value / 1000000).toStringAsFixed(1)}M';
    } else if (value >= 1000) {
      return '${(value / 1000).toStringAsFixed(0)}K';
    }
    return value.toStringAsFixed(0);
  }

  String _formatDate(String dateStr) {
    final parts = dateStr.split('-');
    if (parts.length >= 3) {
      return '${parts[2]}/${parts[1]}/${parts[0]}';
    }
    return dateStr;
  }
}

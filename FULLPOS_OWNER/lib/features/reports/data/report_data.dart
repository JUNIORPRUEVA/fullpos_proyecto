import 'package:intl/intl.dart';

import 'report_models.dart';

class DateFilter {
  DateFilter({required DateTime start, required DateTime end})
    : start = DateTime(start.year, start.month, start.day),
      end = DateTime(end.year, end.month, end.day, 23, 59, 59, 999);

  final DateTime start;
  final DateTime end;

  String get fromQuery => DateFormat('yyyy-MM-dd').format(start);
  String get toQuery => DateFormat('yyyy-MM-dd').format(end);
}

class ReportExpenseRow {
  ReportExpenseRow({
    required this.id,
    required this.amount,
    required this.createdAt,
    this.note,
  });

  final int id;
  final double amount;
  final DateTime createdAt;
  final String? note;

  factory ReportExpenseRow.fromJson(Map<String, dynamic> json) {
    return ReportExpenseRow(
      id: json['id'] as int,
      amount: (json['amount'] as num?)?.toDouble() ?? 0,
      createdAt: DateTime.parse(json['createdAt'] as String),
      note: json['note'] as String?,
    );
  }
}

class ReportData {
  ReportData({
    required this.sales,
    required this.expenses,
    required this.salesByDay,
    required this.totalSales,
    required this.totalCost,
    required this.grossProfit,
    required this.totalExpenses,
    required this.profit,
    required this.salesCount,
    required this.averageTicket,
  });

  final List<SaleRow> sales;
  final List<ReportExpenseRow> expenses;
  final List<SalesByDay> salesByDay;
  final double totalSales;
  final double totalCost;
  final double grossProfit;
  final double totalExpenses;
  final double profit;
  final int salesCount;
  final double averageTicket;

  factory ReportData.fromJson(Map<String, dynamic> json) {
    final salesJson = (json['sales'] as List<dynamic>? ?? const <dynamic>[])
        .cast<Map<String, dynamic>>();
    final expensesJson =
        (json['expenses'] as List<dynamic>? ?? const <dynamic>[])
            .cast<Map<String, dynamic>>();
    final salesByDayJson =
        (json['salesByDay'] as List<dynamic>? ?? const <dynamic>[])
            .cast<Map<String, dynamic>>();

    return ReportData(
      sales: salesJson.map(SaleRow.fromJson).toList(),
      expenses: expensesJson.map(ReportExpenseRow.fromJson).toList(),
      salesByDay: salesByDayJson.map(SalesByDay.fromJson).toList(),
      totalSales: (json['totalSales'] as num?)?.toDouble() ?? 0,
      totalCost: (json['totalCost'] as num?)?.toDouble() ?? 0,
      grossProfit:
          (json['grossProfit'] as num?)?.toDouble() ??
          (json['profit'] as num?)?.toDouble() ??
          0,
      totalExpenses: (json['totalExpenses'] as num?)?.toDouble() ?? 0,
      profit: (json['profit'] as num?)?.toDouble() ?? 0,
      salesCount: (json['salesCount'] as num?)?.toInt() ?? 0,
      averageTicket: (json['averageTicket'] as num?)?.toDouble() ?? 0,
    );
  }
}

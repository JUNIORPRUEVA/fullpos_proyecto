/// Modelo de Resumen de Caja
class CashSummaryModel {
  final double openingAmount;
  final double cashInManual;
  final double cashOutManual;
  final double salesCashTotal;
  final double salesCardTotal;
  final double salesTransferTotal;
  final double salesCreditTotal;
  final double refundsCash;
  final double expectedCash;
  final int totalTickets;
  final int totalRefunds;

  CashSummaryModel({
    required this.openingAmount,
    required this.cashInManual,
    required this.cashOutManual,
    required this.salesCashTotal,
    required this.salesCardTotal,
    required this.salesTransferTotal,
    required this.salesCreditTotal,
    required this.refundsCash,
    required this.expectedCash,
    required this.totalTickets,
    required this.totalRefunds,
  });

  /// Total de ventas (todos los métodos)
  double get totalSales =>
      salesCashTotal + salesCardTotal + salesTransferTotal + salesCreditTotal;

  /// Calcular diferencia con el conteo real
  double calculateDifference(double closingAmount) {
    return closingAmount - expectedCash;
  }

  /// Factory para crear resumen vacío
  factory CashSummaryModel.empty({double openingAmount = 0.0}) {
    return CashSummaryModel(
      openingAmount: openingAmount,
      cashInManual: 0.0,
      cashOutManual: 0.0,
      salesCashTotal: 0.0,
      salesCardTotal: 0.0,
      salesTransferTotal: 0.0,
      salesCreditTotal: 0.0,
      refundsCash: 0.0,
      expectedCash: openingAmount,
      totalTickets: 0,
      totalRefunds: 0,
    );
  }

  CashSummaryModel copyWith({
    double? openingAmount,
    double? cashInManual,
    double? cashOutManual,
    double? salesCashTotal,
    double? salesCardTotal,
    double? salesTransferTotal,
    double? salesCreditTotal,
    double? refundsCash,
    double? expectedCash,
    int? totalTickets,
    int? totalRefunds,
  }) {
    return CashSummaryModel(
      openingAmount: openingAmount ?? this.openingAmount,
      cashInManual: cashInManual ?? this.cashInManual,
      cashOutManual: cashOutManual ?? this.cashOutManual,
      salesCashTotal: salesCashTotal ?? this.salesCashTotal,
      salesCardTotal: salesCardTotal ?? this.salesCardTotal,
      salesTransferTotal: salesTransferTotal ?? this.salesTransferTotal,
      salesCreditTotal: salesCreditTotal ?? this.salesCreditTotal,
      refundsCash: refundsCash ?? this.refundsCash,
      expectedCash: expectedCash ?? this.expectedCash,
      totalTickets: totalTickets ?? this.totalTickets,
      totalRefunds: totalRefunds ?? this.totalRefunds,
    );
  }
}

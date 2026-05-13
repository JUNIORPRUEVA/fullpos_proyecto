import 'package:flutter_test/flutter_test.dart';
import 'package:fullpos_owner/features/reports/application/sales_financial_summary.dart';
import 'package:fullpos_owner/features/reports/data/report_models.dart';

void main() {
  test('clasifica pagos y calcula totales del rango filtrado', () {
    final summary = SalesFinancialSummary.fromSales([
      _sale(1, 100, 'cash'),
      _sale(2, 150, 'Efectivo'),
      _sale(3, 200, 'tarjeta de crédito'),
      _sale(4, 300, 'bank_transfer'),
      _sale(5, 400, 'Crédito'),
      _sale(6, 500, 'apartado'),
      _sale(7, 600, 'voucher'),
      _sale(8, 700, null),
    ], totalProfit: 1234);

    expect(summary.totalSold, 2950);
    expect(summary.totalCash, 250);
    expect(summary.totalCard, 200);
    expect(summary.totalTransfer, 300);
    expect(summary.totalCredit, 400);
    expect(summary.totalLayaway, 500);
    expect(summary.totalOther, 1300);
    expect(summary.totalProfit, 1234);
    expect(summary.salesCount, 8);
    expect(summary.averageSale, 368.75);
  });

  test('normaliza aliases comunes de métodos de pago', () {
    expect(paymentCategoryFor('debit_card'), SalesPaymentCategory.card);
    expect(paymentCategoryFor('Transferencia'), SalesPaymentCategory.transfer);
    expect(paymentCategoryFor('depósito'), SalesPaymentCategory.transfer);
    expect(paymentCategoryFor('LAYAWAY'), SalesPaymentCategory.layaway);
    expect(paymentCategoryFor('fiado'), SalesPaymentCategory.credit);
    expect(paymentCategoryFor(''), SalesPaymentCategory.other);
  });
}

SaleRow _sale(int id, double total, String? paymentMethod) {
  return SaleRow(
    id: id,
    localCode: 'V-$id',
    total: total,
    paymentMethod: paymentMethod,
  );
}

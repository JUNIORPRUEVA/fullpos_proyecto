import '../data/report_models.dart';

// Owner SaleRow only exposes a primary paymentMethod and total; split payments
// and detailed credit/layaway balances are grouped only when the method says so.
class SalesFinancialSummary {
  const SalesFinancialSummary({
    required this.totalSold,
    required this.totalCash,
    required this.totalCard,
    required this.totalTransfer,
    required this.totalCredit,
    required this.totalLayaway,
    required this.totalOther,
    required this.totalProfit,
    required this.salesCount,
  });

  final double totalSold;
  final double totalCash;
  final double totalCard;
  final double totalTransfer;
  final double totalCredit;
  final double totalLayaway;
  final double totalOther;
  final double totalProfit;
  final int salesCount;

  double get averageSale => salesCount == 0 ? 0 : totalSold / salesCount;

  factory SalesFinancialSummary.fromSales(
    List<SaleRow> sales, {
    double totalProfit = 0,
  }) {
    var totalSold = 0.0;
    var totalCash = 0.0;
    var totalCard = 0.0;
    var totalTransfer = 0.0;
    var totalCredit = 0.0;
    var totalLayaway = 0.0;
    var totalOther = 0.0;

    for (final sale in sales) {
      final total = sale.total;
      totalSold += total;

      final breakdown = _explicitPaymentBreakdownFor(sale);
      if (breakdown != null) {
        totalCash += breakdown.cash;
        totalCard += breakdown.card;
        totalTransfer += breakdown.transfer;
        final allocated = breakdown.cash + breakdown.card + breakdown.transfer;
        final remainder = total - allocated;
        if (remainder.abs() > 0.009) {
          totalOther += remainder;
        }
        continue;
      }

      switch (paymentCategoryFor(sale.paymentMethod)) {
        case SalesPaymentCategory.cash:
          totalCash += total;
          break;
        case SalesPaymentCategory.card:
          totalCard += total;
          break;
        case SalesPaymentCategory.transfer:
          totalTransfer += total;
          break;
        case SalesPaymentCategory.credit:
          totalCredit += total;
          break;
        case SalesPaymentCategory.layaway:
          totalLayaway += total;
          break;
        case SalesPaymentCategory.other:
          totalOther += total;
          break;
      }
    }

    return SalesFinancialSummary(
      totalSold: totalSold,
      totalCash: totalCash,
      totalCard: totalCard,
      totalTransfer: totalTransfer,
      totalCredit: totalCredit,
      totalLayaway: totalLayaway,
      totalOther: totalOther,
      totalProfit: totalProfit,
      salesCount: sales.length,
    );
  }
}

enum SalesPaymentCategory { cash, card, transfer, credit, layaway, other }

_PaymentBreakdown? _explicitPaymentBreakdownFor(SaleRow sale) {
  final cash = sale.paymentCashAmount;
  final card = sale.paymentCardAmount;
  final transfer = sale.paymentTransferAmount;
  if (cash.abs() <= 0.009 && card.abs() <= 0.009 && transfer.abs() <= 0.009) {
    return null;
  }
  return _PaymentBreakdown(cash: cash, card: card, transfer: transfer);
}

SalesPaymentCategory paymentCategoryFor(String? rawMethod) {
  final method = _normalizePaymentMethod(rawMethod);
  if (method.isEmpty) return SalesPaymentCategory.other;

  if (method.contains('tarjeta') ||
      method.contains('card') ||
      method.contains('debit')) {
    return SalesPaymentCategory.card;
  }
  if (method.contains('efectivo') || method.contains('cash')) {
    return SalesPaymentCategory.cash;
  }
  if (method.contains('transfer') ||
      method.contains('banco') ||
      method.contains('deposito')) {
    return SalesPaymentCategory.transfer;
  }
  if (method.contains('apartado') ||
      method.contains('layaway') ||
      method.contains('separado')) {
    return SalesPaymentCategory.layaway;
  }
  if (method.contains('credito') ||
      method.contains('credit') ||
      method.contains('fiado')) {
    return SalesPaymentCategory.credit;
  }
  return SalesPaymentCategory.other;
}

String _normalizePaymentMethod(String? rawMethod) {
  final value = rawMethod?.trim().toLowerCase() ?? '';
  return value
      .replaceAll('á', 'a')
      .replaceAll('é', 'e')
      .replaceAll('í', 'i')
      .replaceAll('ó', 'o')
      .replaceAll('ú', 'u')
      .replaceAll('ü', 'u')
      .replaceAll('_', ' ')
      .replaceAll('-', ' ')
      .replaceAll(RegExp(r'\s+'), ' ');
}

class _PaymentBreakdown {
  const _PaymentBreakdown({
    required this.cash,
    required this.card,
    required this.transfer,
  });

  final double cash;
  final double card;
  final double transfer;
}

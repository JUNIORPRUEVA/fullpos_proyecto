import 'package:flutter_test/flutter_test.dart';
import 'package:fullpos_owner/features/reports/data/report_data.dart';

void main() {
  test('ReportData mantiene ventas y totales del payload unificado', () {
    final report = ReportData.fromJson({
      'sales': [
        {
          'id': 1,
          'localCode': 'V-001',
          'total': 125.50,
          'paymentMethod': 'cash',
          'customerName': 'Cliente 1',
          'createdAt': '2026-04-14T10:00:00.000Z',
          'items': [
            {
              'id': 100,
              'productId': 10,
              'productNameSnapshot': 'Combo ejecutivo',
              'productCodeSnapshot': 'COM-001',
              'qty': 1,
            },
          ],
        },
        {
          'id': 2,
          'localCode': 'V-002',
          'total': 74.50,
          'paymentMethod': 'card',
          'customerName': 'Cliente 2',
          'createdAt': '2026-04-14T11:00:00.000Z',
        },
      ],
      'expenses': [
        {
          'id': 10,
          'amount': 50.00,
          'note': 'Caja chica',
          'createdAt': '2026-04-14T12:00:00.000Z',
        },
      ],
      'salesByDay': [
        {'date': '2026-04-14', 'total': 200.00, 'count': 2},
      ],
      'totalSales': 200.00,
      'totalExpenses': 50.00,
      'profit': 150.00,
      'salesCount': 2,
      'averageTicket': 100.00,
    });

    expect(report.sales.length, 2);
    expect(
      report.sales.first.items.single.productNameSnapshot,
      'Combo ejecutivo',
    );
    expect(report.totalSales, 200.00);
    expect(report.totalExpenses, 50.00);
    expect(report.profit, 150.00);
    expect(report.salesCount, 2);
    expect(report.averageTicket, 100.00);
    expect(report.salesByDay.single.total, 200.00);
  });

  test('ReportData normaliza productos de ventas con aliases del reporte', () {
    final report = ReportData.fromJson({
      'sales': [
        {
          'id': 1,
          'localCode': 'V-001',
          'total': 1250,
          'items': [
            {
              'product': {'id': 10, 'name': 'Capsulas', 'code': '1000'},
              'quantity': '5.00',
              'price': 250,
            },
          ],
        },
        {
          'id': 2,
          'localCode': 'V-002',
          'total': 500,
          'saleDetails': [
            {'name': 'Agua', 'qty': 1},
            {'productName': 'Refresco', 'quantity': 2},
          ],
        },
      ],
      'expenses': [],
      'salesByDay': [],
    });

    final firstItem = report.sales.first.items.single;
    expect(firstItem.productNameSnapshot, 'Capsulas');
    expect(firstItem.productName, 'Capsulas');
    expect(firstItem.productCodeSnapshot, '1000');
    expect(firstItem.productCode, '1000');
    expect(firstItem.qty, 5);
    expect(firstItem.quantity, 5);
    expect(firstItem.unitPrice, 250);

    expect(report.sales.last.items.length, 2);
    expect(report.sales.last.items.first.productNameSnapshot, 'Agua');
    expect(report.sales.last.items.last.productNameSnapshot, 'Refresco');
  });

  test('DateFilter usa rango inclusivo de día completo', () {
    final filter = DateFilter(
      start: DateTime(2026, 4, 14, 8, 30),
      end: DateTime(2026, 4, 14, 9, 45),
    );

    expect(filter.fromQuery, '2026-04-14');
    expect(filter.toQuery, '2026-04-14');
    expect(filter.start.hour, 0);
    expect(filter.end.hour, 23);
    expect(filter.end.minute, 59);
  });
}

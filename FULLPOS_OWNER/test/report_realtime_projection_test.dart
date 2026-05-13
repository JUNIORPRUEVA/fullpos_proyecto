import 'package:flutter_test/flutter_test.dart';
import 'package:fullpos_owner/features/reports/data/report_data.dart';
import 'package:fullpos_owner/features/reports/data/report_realtime_projection.dart';
import 'package:fullpos_owner/features/reports/data/sale_realtime_service.dart';

void main() {
  test('proyecta items de productos desde eventos realtime de ventas', () {
    final current = ReportData.fromJson({
      'sales': [],
      'expenses': [],
      'salesByDay': [],
    });

    final projected = applySaleRealtimeProjection(
      current: current,
      from: DateTime(2026, 5, 12),
      to: DateTime(2026, 5, 12),
      message: const SaleRealtimeMessage(
        eventId: 'sale-1',
        type: 'sale.created',
        sale: {
          'id': 1,
          'localCode': 'V-001',
          'kind': 'sale',
          'status': 'completed',
          'total': 1250,
          'createdAt': '2026-05-12T19:02:00.000Z',
          'items': [
            {
              'product': {'id': 10, 'name': 'Capsulas', 'code': '1000'},
              'quantity': 5,
              'unitPrice': 250,
            },
          ],
        },
      ),
    );

    expect(projected.sales, hasLength(1));
    final item = projected.sales.single.items.single;
    expect(item.productNameSnapshot, 'Capsulas');
    expect(item.productCodeSnapshot, '1000');
    expect(item.qty, 5);
    expect(item.unitPrice, 250);
  });
}

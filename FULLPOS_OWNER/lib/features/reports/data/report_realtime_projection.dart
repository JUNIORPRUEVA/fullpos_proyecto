import 'package:intl/intl.dart';

import 'report_data.dart';
import 'report_models.dart';
import 'sale_realtime_service.dart';

const _reportSaleKinds = {'invoice', 'sale'};
const _reportSaleStatuses = {'completed', 'PAID', 'PARTIAL_REFUND'};

final DateFormat _reportDayFormat = DateFormat('yyyy-MM-dd');

ReportData applySaleRealtimeProjection({
  required ReportData current,
  required SaleRealtimeMessage message,
  required DateTime from,
  required DateTime to,
}) {
  final normalizedFrom = DateTime(from.year, from.month, from.day);
  final normalizedTo = DateTime(
    to.year,
    to.month,
    to.day,
    23,
    59,
    59,
    999,
  );

  final sales = List<SaleRow>.from(current.sales);
  final payload = message.sale;
  final payloadId = _readInt(payload['id']);
  final payloadLocalCode = _readString(payload['localCode']);

  final existingIndex = sales.indexWhere(
    (sale) =>
        (payloadId != null && sale.id == payloadId) ||
        (payloadLocalCode.isNotEmpty && sale.localCode == payloadLocalCode),
  );
  final existing = existingIndex >= 0 ? sales[existingIndex] : null;
  final projected = _buildSaleRow(payload, previous: existing);
  final shouldInclude =
      projected != null &&
      _isVisibleInReport(projected, payload, from: normalizedFrom, to: normalizedTo);

  if (existingIndex >= 0) {
    if (shouldInclude) {
      sales[existingIndex] = projected;
    } else {
      sales.removeAt(existingIndex);
    }
  } else if (shouldInclude) {
    sales.add(projected);
  }

  sales.sort((left, right) {
    final leftDate = left.createdAt ?? DateTime.fromMillisecondsSinceEpoch(0);
    final rightDate = right.createdAt ?? DateTime.fromMillisecondsSinceEpoch(0);
    final byDate = rightDate.compareTo(leftDate);
    if (byDate != 0) return byDate;
    return right.id.compareTo(left.id);
  });

  return _rebuildReportData(current, sales);
}

SaleRow? _buildSaleRow(Map<String, dynamic> payload, {SaleRow? previous}) {
  final id = _readInt(payload['id']) ?? previous?.id;
  final localCode = _readString(payload['localCode'], fallback: previous?.localCode ?? '');
  final createdAt = _readDateTime(payload['createdAt']) ?? previous?.createdAt;
  if (id == null || localCode.isEmpty || createdAt == null) {
    return previous;
  }

  return SaleRow(
    id: id,
    localCode: localCode,
    total: _readDouble(payload['total']) ?? previous?.total ?? 0,
    paymentMethod: _readNullableString(
      payload['paymentMethod'],
      fallback: previous?.paymentMethod,
    ),
    customerName: _readNullableString(
      payload['customerName'],
      fallback: previous?.customerName,
    ),
    sessionId: previous?.sessionId,
    sessionStatus: previous?.sessionStatus,
    sessionOpenedAt: previous?.sessionOpenedAt,
    createdAt: createdAt,
    user: previous?.user,
  );
}

bool _isVisibleInReport(
  SaleRow sale,
  Map<String, dynamic> payload, {
  required DateTime from,
  required DateTime to,
}) {
  final kind = _readString(payload['kind']).toLowerCase();
  final status = _readString(payload['status']);
  final deletedAt = _readDateTime(payload['deletedAt']);
  final createdAt = sale.createdAt;
  if (!_reportSaleKinds.contains(kind)) return false;
  if (!_reportSaleStatuses.contains(status)) return false;
  if (deletedAt != null) return false;
  if (createdAt == null) return false;
  if (createdAt.isBefore(from)) return false;
  if (createdAt.isAfter(to)) return false;
  return true;
}

ReportData _rebuildReportData(ReportData current, List<SaleRow> sales) {
  final totalSales = sales.fold<double>(0, (sum, sale) => sum + sale.total);
  final salesCount = sales.length;
  final averageTicket = salesCount == 0 ? 0.0 : totalSales / salesCount;
  final salesByDayMap = <String, ({double total, int count})>{};

  for (final sale in sales) {
    final createdAt = sale.createdAt;
    if (createdAt == null) continue;
    final key = _reportDayFormat.format(createdAt);
    final currentDay = salesByDayMap[key];
    salesByDayMap[key] = (
      total: (currentDay?.total ?? 0) + sale.total,
      count: (currentDay?.count ?? 0) + 1,
    );
  }

  final salesByDay = salesByDayMap.entries.toList()
    ..sort((left, right) => left.key.compareTo(right.key));

  return ReportData(
    sales: sales,
    expenses: current.expenses,
    salesByDay: salesByDay
        .map(
          (entry) => SalesByDay(
            date: entry.key,
            total: entry.value.total,
            count: entry.value.count,
          ),
        )
        .toList(growable: false),
    totalSales: totalSales,
    totalExpenses: current.totalExpenses,
    profit: totalSales - current.totalExpenses,
    salesCount: salesCount,
    averageTicket: averageTicket,
  );
}

String _readString(Object? value, {String fallback = ''}) {
  final normalized = _readNullableString(value, fallback: fallback);
  return normalized ?? fallback;
}

String? _readNullableString(Object? value, {String? fallback}) {
  final text = value?.toString().trim();
  if (text == null || text.isEmpty) return fallback;
  return text;
}

int? _readInt(Object? value) {
  if (value is int) return value;
  if (value is num) return value.toInt();
  if (value is String) return int.tryParse(value.trim());
  return null;
}

double? _readDouble(Object? value) {
  if (value is double) return value;
  if (value is num) return value.toDouble();
  if (value is String) return double.tryParse(value.trim());
  return null;
}

DateTime? _readDateTime(Object? value) {
  if (value is DateTime) return value;
  if (value is String) return DateTime.tryParse(value);
  return null;
}
import 'package:freezed_annotation/freezed_annotation.dart';

part 'report_models.freezed.dart';
part 'report_models.g.dart';

@freezed
class SalesSummary with _$SalesSummary {
  const factory SalesSummary({
    required double total,
    required int count,
    required double average,
    @Default(0) double totalCost,
    @Default(0) double profit,
  }) = _SalesSummary;

  factory SalesSummary.fromJson(Map<String, dynamic> json) =>
      _$SalesSummaryFromJson(_normalizeSalesSummaryJson(json));
}

Map<String, dynamic> _normalizeSalesSummaryJson(Map<String, dynamic> json) {
  final normalized = Map<String, dynamic>.from(json);

  Object? pick(List<String> keys) {
    for (final key in keys) {
      if (normalized.containsKey(key) && normalized[key] != null) {
        return normalized[key];
      }
    }
    return null;
  }

  num? asNum(Object? value) {
    if (value == null) return null;
    if (value is num) return value;
    if (value is String) {
      final cleaned = value.replaceAll(',', '');
      return num.tryParse(cleaned);
    }
    return null;
  }

  normalized['total'] =
      asNum(normalized['total']) ??
      asNum(
        pick(['total', 'totalVendido', 'ventasTotal', 'ventas', 'montoTotal']),
      ) ??
      0;
  normalized['count'] =
      asNum(normalized['count']) ??
      asNum(pick(['count', 'cantidad', 'ventasCount', 'cantidadVentas'])) ??
      0;
  normalized['average'] =
      asNum(normalized['average']) ??
      asNum(pick(['average', 'promedio', 'avg', 'promedioVenta'])) ??
      0;
  normalized['totalCost'] =
      asNum(normalized['totalCost']) ??
      asNum(
        pick(['totalCost', 'total_cost', 'costo', 'costoTotal', 'totalCosto']),
      ) ??
      0;
  normalized['profit'] =
      asNum(normalized['profit']) ??
      asNum(pick(['profit', 'ganancia', 'utilidad', 'margen', 'margin'])) ??
      0;

  return normalized;
}

@freezed
class SalesByDay with _$SalesByDay {
  const factory SalesByDay({
    required String date,
    required double total,
    required int count,
  }) = _SalesByDay;

  factory SalesByDay.fromJson(Map<String, dynamic> json) =>
      _$SalesByDayFromJson(json);
}

@freezed
class SaleRow with _$SaleRow {
  const factory SaleRow({
    required int id,
    required String localCode,
    required double total,
    String? paymentMethod,
    String? customerName,
    int? sessionId,
    String? sessionStatus,
    DateTime? sessionOpenedAt,
    DateTime? createdAt,
    UserInfo? user,
  }) = _SaleRow;

  factory SaleRow.fromJson(Map<String, dynamic> json) =>
      _$SaleRowFromJson(json);
}

@freezed
class UserInfo with _$UserInfo {
  const factory UserInfo({
    required int id,
    required String username,
    String? displayName,
  }) = _UserInfo;

  factory UserInfo.fromJson(Map<String, dynamic> json) =>
      _$UserInfoFromJson(json);
}

@freezed
class PaginatedSales with _$PaginatedSales {
  const factory PaginatedSales({
    required List<SaleRow> data,
    required int page,
    required int pageSize,
    required int total,
  }) = _PaginatedSales;

  factory PaginatedSales.fromJson(Map<String, dynamic> json) =>
      _$PaginatedSalesFromJson(json);
}

@freezed
class CashClosing with _$CashClosing {
  const factory CashClosing({
    required int id,
    DateTime? openedAt,
    DateTime? closedAt,
    required String userName,
    UserInfo? openedBy,
    UserInfo? closedBy,
    required double totalSales,
    @Default(0) double cashSalesTotal,
    required int salesCount,
    @Default(0) double movementsInTotal,
    @Default(0) double movementsOutTotal,
    double? closingAmount,
    double? expectedCash,
    double? difference,
  }) = _CashClosing;

  factory CashClosing.fromJson(Map<String, dynamic> json) =>
      _$CashClosingFromJson(json);
}

@freezed
class CashClosingDetail with _$CashClosingDetail {
  const factory CashClosingDetail({
    required CashClosingSession session,
    required CashClosingTotals totals,
    required List<SaleMinimal> sales,
    required List<CashMovementRow> movements,
  }) = _CashClosingDetail;

  factory CashClosingDetail.fromJson(Map<String, dynamic> json) =>
      _$CashClosingDetailFromJson(json);
}

@freezed
class CashClosingSession with _$CashClosingSession {
  const factory CashClosingSession({
    required int id,
    DateTime? openedAt,
    DateTime? closedAt,
    double? initialAmount,
    double? closingAmount,
    double? expectedCash,
    double? difference,
    String? status,
    String? note,
    UserInfo? openedBy,
    UserInfo? closedBy,
    Map<String, dynamic>? paymentSummary,
  }) = _CashClosingSession;

  factory CashClosingSession.fromJson(Map<String, dynamic> json) =>
      _$CashClosingSessionFromJson(json);
}

@freezed
class CashClosingTotals with _$CashClosingTotals {
  const factory CashClosingTotals({
    required double totalSales,
    required Map<String, dynamic> paymentBreakdown,
  }) = _CashClosingTotals;

  factory CashClosingTotals.fromJson(Map<String, dynamic> json) =>
      _$CashClosingTotalsFromJson(json);
}

@freezed
class SaleMinimal with _$SaleMinimal {
  const factory SaleMinimal({
    required int id,
    required double total,
    String? paymentMethod,
    DateTime? createdAt,
  }) = _SaleMinimal;

  factory SaleMinimal.fromJson(Map<String, dynamic> json) =>
      _$SaleMinimalFromJson(json);
}

@freezed
class CashMovementRow with _$CashMovementRow {
  const factory CashMovementRow({
    required int id,
    required String type,
    required double amount,
    String? note,
    DateTime? createdAt,
  }) = _CashMovementRow;

  factory CashMovementRow.fromJson(Map<String, dynamic> json) =>
      _$CashMovementRowFromJson(json);
}

class ExpenseRow {
  ExpenseRow({
    required this.id,
    required this.amount,
    required this.category,
    required this.incurredAt,
    this.note,
    this.createdBy,
  });

  final int id;
  final double amount;
  final String category;
  final DateTime incurredAt;
  final String? note;
  final UserInfo? createdBy;

  factory ExpenseRow.fromJson(Map<String, dynamic> json) {
    return ExpenseRow(
      id: json['id'] as int,
      amount: (json['amount'] as num).toDouble(),
      category: json['category'] as String,
      incurredAt: DateTime.parse(json['incurredAt'] as String),
      note: json['note'] as String?,
      createdBy: json['createdBy'] != null
          ? UserInfo.fromJson(json['createdBy'] as Map<String, dynamic>)
          : null,
    );
  }
}

class ExpensesSummary {
  ExpensesSummary({required this.total, required this.count});
  final double total;
  final int count;

  factory ExpensesSummary.fromJson(Map<String, dynamic> json) {
    return ExpensesSummary(
      total: (json['total'] as num).toDouble(),
      count: json['count'] as int,
    );
  }
}

class SalesByPaymentMethodRow {
  SalesByPaymentMethodRow({
    required this.paymentMethod,
    required this.total,
    required this.count,
  });

  final String paymentMethod;
  final double total;
  final int count;

  factory SalesByPaymentMethodRow.fromJson(Map<String, dynamic> json) {
    return SalesByPaymentMethodRow(
      paymentMethod: (json['paymentMethod'] as String?) ?? 'N/D',
      total: (json['total'] as num).toDouble(),
      count: (json['count'] as num).toInt(),
    );
  }
}

class ExpensesByCategoryRow {
  ExpensesByCategoryRow({
    required this.category,
    required this.total,
    required this.count,
  });

  final String category;
  final double total;
  final int count;

  factory ExpensesByCategoryRow.fromJson(Map<String, dynamic> json) {
    return ExpensesByCategoryRow(
      category: (json['category'] as String?) ?? 'Sin categoría',
      total: (json['total'] as num).toDouble(),
      count: (json['count'] as num).toInt(),
    );
  }
}

class PaginatedExpenses {
  PaginatedExpenses({
    required this.data,
    required this.page,
    required this.pageSize,
    required this.total,
  });

  final List<ExpenseRow> data;
  final int page;
  final int pageSize;
  final int total;

  factory PaginatedExpenses.fromJson(Map<String, dynamic> json) {
    final list = (json['data'] as List).cast<Map<String, dynamic>>();
    return PaginatedExpenses(
      data: list.map(ExpenseRow.fromJson).toList(),
      page: json['page'] as int,
      pageSize: json['pageSize'] as int,
      total: json['total'] as int,
    );
  }
}

class SaleDetail {
  SaleDetail({
    required this.id,
    required this.localCode,
    required this.kind,
    required this.status,
    required this.total,
    required this.totalCost,
    required this.profit,
    required this.items,
    this.customerName,
    this.customerPhone,
    this.customerRnc,
    this.paymentMethod,
    this.sessionId,
    this.sessionStatus,
    this.subtotal,
    this.discountTotal,
    this.itbisAmount,
    this.itbisRate,
    this.paidAmount,
    this.changeAmount,
    this.fiscalEnabled,
    this.ncfFull,
    this.ncfType,
    this.createdAt,
    this.updatedAt,
    this.deletedAt,
    this.user,
    this.cashierName,
  });

  final int id;
  final String localCode;
  final String kind;
  final String status;
  final String? customerName;
  final String? customerPhone;
  final String? customerRnc;
  final double total;
  final double totalCost;
  final double profit;
  final String? paymentMethod;
  final int? sessionId;
  final String? sessionStatus;
  final double? subtotal;
  final double? discountTotal;
  final double? itbisAmount;
  final double? itbisRate;
  final double? paidAmount;
  final double? changeAmount;
  final bool? fiscalEnabled;
  final String? ncfFull;
  final String? ncfType;
  final DateTime? createdAt;
  final DateTime? updatedAt;
  final DateTime? deletedAt;
  final UserInfo? user;
  final String? cashierName;
  final List<SaleDetailItem> items;

  factory SaleDetail.fromJson(Map<String, dynamic> json) {
    final rawItems = (json['items'] as List?) ?? const [];
    final resolvedUser = _readSaleUser(json);
    return SaleDetail(
      id: (json['id'] as num).toInt(),
      localCode: json['localCode']?.toString() ?? '',
      kind: json['kind']?.toString() ?? 'sale',
      status: json['status']?.toString() ?? 'completed',
      customerName: json['customerName']?.toString(),
      customerPhone: json['customerPhone']?.toString(),
      customerRnc: json['customerRnc']?.toString(),
      total: (json['total'] as num?)?.toDouble() ?? 0,
      totalCost: (json['totalCost'] as num?)?.toDouble() ?? 0,
      profit: (json['profit'] as num?)?.toDouble() ?? 0,
      paymentMethod: json['paymentMethod']?.toString(),
      sessionId: (json['sessionId'] as num?)?.toInt(),
      sessionStatus: json['sessionStatus']?.toString(),
      subtotal: (json['subtotal'] as num?)?.toDouble(),
      discountTotal: (json['discountTotal'] as num?)?.toDouble(),
      itbisAmount: (json['itbisAmount'] as num?)?.toDouble(),
      itbisRate: (json['itbisRate'] as num?)?.toDouble(),
      paidAmount: (json['paidAmount'] as num?)?.toDouble(),
      changeAmount: (json['changeAmount'] as num?)?.toDouble(),
      fiscalEnabled: json['fiscalEnabled'] as bool?,
      ncfFull: json['ncfFull']?.toString(),
      ncfType: json['ncfType']?.toString(),
      createdAt: json['createdAt'] != null
          ? DateTime.tryParse(json['createdAt'].toString())
          : null,
      updatedAt: json['updatedAt'] != null
          ? DateTime.tryParse(json['updatedAt'].toString())
          : null,
      deletedAt: json['deletedAt'] != null
          ? DateTime.tryParse(json['deletedAt'].toString())
          : null,
      user: resolvedUser,
      cashierName: _readCashierName(json, resolvedUser),
      items: rawItems
          .whereType<Map<String, dynamic>>()
          .map(SaleDetailItem.fromJson)
          .toList(),
    );
  }
}

UserInfo? _readSaleUser(Map<String, dynamic> json) {
  final candidates = [
    json['user'],
    json['cashier'],
    json['seller'],
    json['createdBy'],
    json['employee'],
  ];

  for (final candidate in candidates) {
    if (candidate is! Map) continue;
    final map = Map<String, dynamic>.from(candidate);
    final username = map['username']?.toString().trim();
    final displayName =
        map['displayName']?.toString().trim() ??
        map['name']?.toString().trim() ??
        map['fullName']?.toString().trim();
    final hasUsername = username != null && username.isNotEmpty;
    final hasDisplayName = displayName != null && displayName.isNotEmpty;

    if (!hasUsername && !hasDisplayName) continue;

    return UserInfo(
      id: (map['id'] as num?)?.toInt() ?? 0,
      username: hasUsername ? username! : displayName!,
      displayName: hasDisplayName ? displayName : null,
    );
  }

  return null;
}

String? _readCashierName(Map<String, dynamic> json, UserInfo? user) {
  final candidates = [
    json['cashierName'],
    json['sellerName'],
    json['createdByName'],
    json['employeeName'],
    json['userName'],
    json['user_name'],
    user?.displayName,
    user?.username,
  ];

  for (final candidate in candidates) {
    final value = candidate?.toString().trim();
    if (value != null && value.isNotEmpty) {
      return value;
    }
  }

  return null;
}

class SaleDetailItem {
  SaleDetailItem({
    required this.id,
    required this.productNameSnapshot,
    required this.qty,
    required this.unitPrice,
    required this.purchasePriceSnapshot,
    required this.discountLine,
    required this.totalLine,
    required this.lineCost,
    required this.lineProfit,
    this.productId,
    this.productCodeSnapshot,
    this.createdAt,
  });

  final int id;
  final int? productId;
  final String? productCodeSnapshot;
  final String productNameSnapshot;
  final double qty;
  final double unitPrice;
  final double purchasePriceSnapshot;
  final double discountLine;
  final double totalLine;
  final double lineCost;
  final double lineProfit;
  final DateTime? createdAt;

  factory SaleDetailItem.fromJson(Map<String, dynamic> json) {
    return SaleDetailItem(
      id: (json['id'] as num).toInt(),
      productId: (json['productId'] as num?)?.toInt(),
      productCodeSnapshot: json['productCodeSnapshot']?.toString(),
      productNameSnapshot:
          json['productNameSnapshot']?.toString() ?? 'Producto',
      qty: (json['qty'] as num?)?.toDouble() ?? 0,
      unitPrice: (json['unitPrice'] as num?)?.toDouble() ?? 0,
      purchasePriceSnapshot:
          (json['purchasePriceSnapshot'] as num?)?.toDouble() ?? 0,
      discountLine: (json['discountLine'] as num?)?.toDouble() ?? 0,
      totalLine: (json['totalLine'] as num?)?.toDouble() ?? 0,
      lineCost: (json['lineCost'] as num?)?.toDouble() ?? 0,
      lineProfit: (json['lineProfit'] as num?)?.toDouble() ?? 0,
      createdAt: json['createdAt'] != null
          ? DateTime.tryParse(json['createdAt'].toString())
          : null,
    );
  }
}

class SyncStatus {
  SyncStatus({required this.company, required this.counts, required this.last});

  final SyncCompany company;
  final SyncCounts counts;
  final SyncLast last;

  factory SyncStatus.fromJson(Map<String, dynamic> json) {
    return SyncStatus(
      company: SyncCompany.fromJson(
        (json['company'] as Map).cast<String, dynamic>(),
      ),
      counts: SyncCounts.fromJson(
        (json['counts'] as Map).cast<String, dynamic>(),
      ),
      last: SyncLast.fromJson((json['last'] as Map).cast<String, dynamic>()),
    );
  }
}

class SyncCompany {
  SyncCompany({
    required this.id,
    required this.name,
    this.rnc,
    this.cloudCompanyId,
  });

  final int id;
  final String name;
  final String? rnc;
  final String? cloudCompanyId;

  factory SyncCompany.fromJson(Map<String, dynamic> json) {
    return SyncCompany(
      id: json['id'] as int,
      name: (json['name'] as String?) ?? 'Empresa',
      rnc: json['rnc'] as String?,
      cloudCompanyId: json['cloudCompanyId'] as String?,
    );
  }
}

class SyncCounts {
  SyncCounts({
    required this.sales,
    required this.cashClosings,
    required this.cashMovements,
    required this.expenses,
    required this.quotes,
  });

  final int sales;
  final int cashClosings;
  final int cashMovements;
  final int expenses;
  final int quotes;

  factory SyncCounts.fromJson(Map<String, dynamic> json) {
    return SyncCounts(
      sales: (json['sales'] as num?)?.toInt() ?? 0,
      cashClosings: (json['cashClosings'] as num?)?.toInt() ?? 0,
      cashMovements: (json['cashMovements'] as num?)?.toInt() ?? 0,
      expenses: (json['expenses'] as num?)?.toInt() ?? 0,
      quotes: (json['quotes'] as num?)?.toInt() ?? 0,
    );
  }
}

class SyncLast {
  SyncLast({
    this.saleAt,
    this.cashClosingAt,
    this.cashMovementAt,
    this.expenseAt,
    this.quoteAt,
  });

  final DateTime? saleAt;
  final DateTime? cashClosingAt;
  final DateTime? cashMovementAt;
  final DateTime? expenseAt;
  final DateTime? quoteAt;

  static DateTime? _parseDate(dynamic value) {
    if (value == null) return null;
    try {
      return DateTime.parse(value.toString());
    } catch (_) {
      return null;
    }
  }

  factory SyncLast.fromJson(Map<String, dynamic> json) {
    return SyncLast(
      saleAt: _parseDate(json['saleAt']),
      cashClosingAt: _parseDate(json['cashClosingAt']),
      cashMovementAt: _parseDate(json['cashMovementAt']),
      expenseAt: _parseDate(json['expenseAt']),
      quoteAt: _parseDate(json['quoteAt']),
    );
  }
}

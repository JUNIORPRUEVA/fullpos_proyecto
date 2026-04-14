// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'report_models.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

_$SalesSummaryImpl _$$SalesSummaryImplFromJson(Map<String, dynamic> json) =>
    _$SalesSummaryImpl(
      total: (json['total'] as num).toDouble(),
      count: (json['count'] as num).toInt(),
      average: (json['average'] as num).toDouble(),
      totalCost: (json['totalCost'] as num?)?.toDouble() ?? 0,
      profit: (json['profit'] as num?)?.toDouble() ?? 0,
      expenses: (json['expenses'] as num?)?.toDouble() ?? 0,
    );

Map<String, dynamic> _$$SalesSummaryImplToJson(_$SalesSummaryImpl instance) =>
    <String, dynamic>{
      'total': instance.total,
      'count': instance.count,
      'average': instance.average,
      'totalCost': instance.totalCost,
      'profit': instance.profit,
      'expenses': instance.expenses,
    };

_$SalesByDayImpl _$$SalesByDayImplFromJson(Map<String, dynamic> json) =>
    _$SalesByDayImpl(
      date: json['date'] as String,
      total: (json['total'] as num).toDouble(),
      count: (json['count'] as num).toInt(),
    );

Map<String, dynamic> _$$SalesByDayImplToJson(_$SalesByDayImpl instance) =>
    <String, dynamic>{
      'date': instance.date,
      'total': instance.total,
      'count': instance.count,
    };

_$SaleRowImpl _$$SaleRowImplFromJson(Map<String, dynamic> json) =>
    _$SaleRowImpl(
      id: (json['id'] as num).toInt(),
      localCode: json['localCode'] as String,
      total: (json['total'] as num).toDouble(),
      paymentMethod: json['paymentMethod'] as String?,
      customerName: json['customerName'] as String?,
      sessionId: (json['sessionId'] as num?)?.toInt(),
      sessionStatus: json['sessionStatus'] as String?,
      sessionOpenedAt: json['sessionOpenedAt'] == null
          ? null
          : DateTime.parse(json['sessionOpenedAt'] as String),
      createdAt: json['createdAt'] == null
          ? null
          : DateTime.parse(json['createdAt'] as String),
      user: json['user'] == null
          ? null
          : UserInfo.fromJson(json['user'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$$SaleRowImplToJson(_$SaleRowImpl instance) =>
    <String, dynamic>{
      'id': instance.id,
      'localCode': instance.localCode,
      'total': instance.total,
      'paymentMethod': instance.paymentMethod,
      'customerName': instance.customerName,
      'sessionId': instance.sessionId,
      'sessionStatus': instance.sessionStatus,
      'sessionOpenedAt': instance.sessionOpenedAt?.toIso8601String(),
      'createdAt': instance.createdAt?.toIso8601String(),
      'user': instance.user,
    };

_$UserInfoImpl _$$UserInfoImplFromJson(Map<String, dynamic> json) =>
    _$UserInfoImpl(
      id: (json['id'] as num).toInt(),
      username: json['username'] as String,
      displayName: json['displayName'] as String?,
    );

Map<String, dynamic> _$$UserInfoImplToJson(_$UserInfoImpl instance) =>
    <String, dynamic>{
      'id': instance.id,
      'username': instance.username,
      'displayName': instance.displayName,
    };

_$PaginatedSalesImpl _$$PaginatedSalesImplFromJson(Map<String, dynamic> json) =>
    _$PaginatedSalesImpl(
      data: (json['data'] as List<dynamic>)
          .map((e) => SaleRow.fromJson(e as Map<String, dynamic>))
          .toList(),
      page: (json['page'] as num).toInt(),
      pageSize: (json['pageSize'] as num).toInt(),
      total: (json['total'] as num).toInt(),
    );

Map<String, dynamic> _$$PaginatedSalesImplToJson(
  _$PaginatedSalesImpl instance,
) => <String, dynamic>{
  'data': instance.data,
  'page': instance.page,
  'pageSize': instance.pageSize,
  'total': instance.total,
};

_$CashClosingImpl _$$CashClosingImplFromJson(Map<String, dynamic> json) =>
    _$CashClosingImpl(
      id: (json['id'] as num).toInt(),
      openedAt: json['openedAt'] == null
          ? null
          : DateTime.parse(json['openedAt'] as String),
      closedAt: json['closedAt'] == null
          ? null
          : DateTime.parse(json['closedAt'] as String),
      userName: json['userName'] as String,
      openedBy: json['openedBy'] == null
          ? null
          : UserInfo.fromJson(json['openedBy'] as Map<String, dynamic>),
      closedBy: json['closedBy'] == null
          ? null
          : UserInfo.fromJson(json['closedBy'] as Map<String, dynamic>),
      totalSales: (json['totalSales'] as num).toDouble(),
      cashSalesTotal: (json['cashSalesTotal'] as num?)?.toDouble() ?? 0,
      salesCount: (json['salesCount'] as num).toInt(),
      movementsInTotal: (json['movementsInTotal'] as num?)?.toDouble() ?? 0,
      movementsOutTotal: (json['movementsOutTotal'] as num?)?.toDouble() ?? 0,
      closingAmount: (json['closingAmount'] as num?)?.toDouble(),
      expectedCash: (json['expectedCash'] as num?)?.toDouble(),
      difference: (json['difference'] as num?)?.toDouble(),
    );

Map<String, dynamic> _$$CashClosingImplToJson(_$CashClosingImpl instance) =>
    <String, dynamic>{
      'id': instance.id,
      'openedAt': instance.openedAt?.toIso8601String(),
      'closedAt': instance.closedAt?.toIso8601String(),
      'userName': instance.userName,
      'openedBy': instance.openedBy,
      'closedBy': instance.closedBy,
      'totalSales': instance.totalSales,
      'cashSalesTotal': instance.cashSalesTotal,
      'salesCount': instance.salesCount,
      'movementsInTotal': instance.movementsInTotal,
      'movementsOutTotal': instance.movementsOutTotal,
      'closingAmount': instance.closingAmount,
      'expectedCash': instance.expectedCash,
      'difference': instance.difference,
    };

_$CashClosingDetailImpl _$$CashClosingDetailImplFromJson(
  Map<String, dynamic> json,
) => _$CashClosingDetailImpl(
  session: CashClosingSession.fromJson(json['session'] as Map<String, dynamic>),
  totals: CashClosingTotals.fromJson(json['totals'] as Map<String, dynamic>),
  sales: (json['sales'] as List<dynamic>)
      .map((e) => SaleMinimal.fromJson(e as Map<String, dynamic>))
      .toList(),
  movements: (json['movements'] as List<dynamic>)
      .map((e) => CashMovementRow.fromJson(e as Map<String, dynamic>))
      .toList(),
);

Map<String, dynamic> _$$CashClosingDetailImplToJson(
  _$CashClosingDetailImpl instance,
) => <String, dynamic>{
  'session': instance.session,
  'totals': instance.totals,
  'sales': instance.sales,
  'movements': instance.movements,
};

_$CashClosingSessionImpl _$$CashClosingSessionImplFromJson(
  Map<String, dynamic> json,
) => _$CashClosingSessionImpl(
  id: (json['id'] as num).toInt(),
  openedAt: json['openedAt'] == null
      ? null
      : DateTime.parse(json['openedAt'] as String),
  closedAt: json['closedAt'] == null
      ? null
      : DateTime.parse(json['closedAt'] as String),
  initialAmount: (json['initialAmount'] as num?)?.toDouble(),
  closingAmount: (json['closingAmount'] as num?)?.toDouble(),
  expectedCash: (json['expectedCash'] as num?)?.toDouble(),
  difference: (json['difference'] as num?)?.toDouble(),
  status: json['status'] as String?,
  note: json['note'] as String?,
  openedBy: json['openedBy'] == null
      ? null
      : UserInfo.fromJson(json['openedBy'] as Map<String, dynamic>),
  closedBy: json['closedBy'] == null
      ? null
      : UserInfo.fromJson(json['closedBy'] as Map<String, dynamic>),
  paymentSummary: json['paymentSummary'] as Map<String, dynamic>?,
);

Map<String, dynamic> _$$CashClosingSessionImplToJson(
  _$CashClosingSessionImpl instance,
) => <String, dynamic>{
  'id': instance.id,
  'openedAt': instance.openedAt?.toIso8601String(),
  'closedAt': instance.closedAt?.toIso8601String(),
  'initialAmount': instance.initialAmount,
  'closingAmount': instance.closingAmount,
  'expectedCash': instance.expectedCash,
  'difference': instance.difference,
  'status': instance.status,
  'note': instance.note,
  'openedBy': instance.openedBy,
  'closedBy': instance.closedBy,
  'paymentSummary': instance.paymentSummary,
};

_$CashClosingTotalsImpl _$$CashClosingTotalsImplFromJson(
  Map<String, dynamic> json,
) => _$CashClosingTotalsImpl(
  totalSales: (json['totalSales'] as num).toDouble(),
  paymentBreakdown: json['paymentBreakdown'] as Map<String, dynamic>,
);

Map<String, dynamic> _$$CashClosingTotalsImplToJson(
  _$CashClosingTotalsImpl instance,
) => <String, dynamic>{
  'totalSales': instance.totalSales,
  'paymentBreakdown': instance.paymentBreakdown,
};

_$SaleMinimalImpl _$$SaleMinimalImplFromJson(Map<String, dynamic> json) =>
    _$SaleMinimalImpl(
      id: (json['id'] as num).toInt(),
      total: (json['total'] as num).toDouble(),
      paymentMethod: json['paymentMethod'] as String?,
      createdAt: json['createdAt'] == null
          ? null
          : DateTime.parse(json['createdAt'] as String),
    );

Map<String, dynamic> _$$SaleMinimalImplToJson(_$SaleMinimalImpl instance) =>
    <String, dynamic>{
      'id': instance.id,
      'total': instance.total,
      'paymentMethod': instance.paymentMethod,
      'createdAt': instance.createdAt?.toIso8601String(),
    };

_$CashMovementRowImpl _$$CashMovementRowImplFromJson(
  Map<String, dynamic> json,
) => _$CashMovementRowImpl(
  id: (json['id'] as num).toInt(),
  type: json['type'] as String,
  amount: (json['amount'] as num).toDouble(),
  note: json['note'] as String?,
  createdAt: json['createdAt'] == null
      ? null
      : DateTime.parse(json['createdAt'] as String),
);

Map<String, dynamic> _$$CashMovementRowImplToJson(
  _$CashMovementRowImpl instance,
) => <String, dynamic>{
  'id': instance.id,
  'type': instance.type,
  'amount': instance.amount,
  'note': instance.note,
  'createdAt': instance.createdAt?.toIso8601String(),
};

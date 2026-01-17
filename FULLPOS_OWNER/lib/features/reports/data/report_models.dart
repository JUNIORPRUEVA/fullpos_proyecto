import 'package:freezed_annotation/freezed_annotation.dart';

part 'report_models.freezed.dart';
part 'report_models.g.dart';

@freezed
class SalesSummary with _$SalesSummary {
  const factory SalesSummary({
    required double total,
    required int count,
    required double average,
  }) = _SalesSummary;

  factory SalesSummary.fromJson(Map<String, dynamic> json) => _$SalesSummaryFromJson(json);
}

@freezed
class SalesByDay with _$SalesByDay {
  const factory SalesByDay({
    required String date,
    required double total,
    required int count,
  }) = _SalesByDay;

  factory SalesByDay.fromJson(Map<String, dynamic> json) => _$SalesByDayFromJson(json);
}

@freezed
class SaleRow with _$SaleRow {
  const factory SaleRow({
    required int id,
    required String localCode,
    required double total,
    String? paymentMethod,
    int? sessionId,
    String? sessionStatus,
    DateTime? sessionOpenedAt,
    DateTime? createdAt,
    UserInfo? user,
  }) = _SaleRow;

  factory SaleRow.fromJson(Map<String, dynamic> json) => _$SaleRowFromJson(json);
}

@freezed
class UserInfo with _$UserInfo {
  const factory UserInfo({
    required int id,
    required String username,
    String? displayName,
  }) = _UserInfo;

  factory UserInfo.fromJson(Map<String, dynamic> json) => _$UserInfoFromJson(json);
}

@freezed
class PaginatedSales with _$PaginatedSales {
  const factory PaginatedSales({
    required List<SaleRow> data,
    required int page,
    required int pageSize,
    required int total,
  }) = _PaginatedSales;

  factory PaginatedSales.fromJson(Map<String, dynamic> json) => _$PaginatedSalesFromJson(json);
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
    required int salesCount,
    double? closingAmount,
    double? expectedCash,
    double? difference,
  }) = _CashClosing;

  factory CashClosing.fromJson(Map<String, dynamic> json) => _$CashClosingFromJson(json);
}

@freezed
class CashClosingDetail with _$CashClosingDetail {
  const factory CashClosingDetail({
    required CashClosingSession session,
    required CashClosingTotals totals,
    required List<SaleMinimal> sales,
    required List<CashMovementRow> movements,
  }) = _CashClosingDetail;

  factory CashClosingDetail.fromJson(Map<String, dynamic> json) => _$CashClosingDetailFromJson(json);
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

  factory SaleMinimal.fromJson(Map<String, dynamic> json) => _$SaleMinimalFromJson(json);
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

  factory CashMovementRow.fromJson(Map<String, dynamic> json) => _$CashMovementRowFromJson(json);
}

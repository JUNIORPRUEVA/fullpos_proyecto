import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../core/network/api_client.dart';
import 'report_models.dart';

final reportsRepositoryProvider = Provider<ReportsRepository>((ref) {
  final dio = ref.read(apiClientProvider).dio;
  return ReportsRepository(dio);
});

class ReportsRepository {
  ReportsRepository(this._dio);
  final Dio _dio;

  Future<SalesSummary> salesSummary(String from, String to) async {
    final res = await _dio.get('/api/reports/sales/summary', queryParameters: {'from': from, 'to': to});
    return SalesSummary.fromJson(res.data as Map<String, dynamic>);
  }

  Future<List<SalesByDay>> salesByDay(String from, String to) async {
    final res = await _dio.get('/api/reports/sales/by-day', queryParameters: {'from': from, 'to': to});
    final list = res.data as List;
    return list.map((e) => SalesByDay.fromJson(e as Map<String, dynamic>)).toList();
  }

  Future<PaginatedSales> salesList(String from, String to, {int page = 1}) async {
    final res = await _dio.get('/api/reports/sales/list', queryParameters: {
      'from': from,
      'to': to,
      'page': page,
      'pageSize': 20,
    });
    return PaginatedSales.fromJson(res.data as Map<String, dynamic>);
  }

  Future<List<CashClosing>> cashClosings(String from, String to) async {
    final res = await _dio.get('/api/reports/cash/closings', queryParameters: {'from': from, 'to': to});
    final list = res.data as List;
    return list.map((e) => CashClosing.fromJson(e as Map<String, dynamic>)).toList();
  }

  Future<CashClosingDetail> cashClosingDetail(int id) async {
    final res = await _dio.get('/api/reports/cash/closing/$id');
    return CashClosingDetail.fromJson(res.data as Map<String, dynamic>);
  }
}

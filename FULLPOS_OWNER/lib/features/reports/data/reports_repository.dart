import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../core/network/api_client.dart';
import 'report_data.dart';
import 'report_models.dart';

final reportsRepositoryProvider = Provider<ReportsRepository>((ref) {
  final dio = ref.read(apiClientProvider).dio;
  return ReportsRepository(dio);
});

class ReportsRepository {
  ReportsRepository(this._dio);
  final Dio _dio;

  Options _allowNotFoundOptions() => Options(
    validateStatus: (status) =>
        status != null && ((status >= 200 && status < 300) || status == 404),
  );

  Future<ReportData> getReportData(DateFilter filter) async {
    return _guard(() async {
      final res = await _dio.get(
        '/api/reports/data',
        queryParameters: {'from': filter.fromQuery, 'to': filter.toQuery},
      );
      return ReportData.fromJson(res.data as Map<String, dynamic>);
    });
  }

  Future<SalesSummary> salesSummary(String from, String to) async {
    return _guard(() async {
      final res = await _dio.get(
        '/api/reports/sales/summary',
        queryParameters: {'from': from, 'to': to},
      );
      return SalesSummary.fromJson(res.data as Map<String, dynamic>);
    }, fallback: const SalesSummary(total: 0, count: 0, average: 0));
  }

  Future<List<SalesByDay>> salesByDay(String from, String to) async {
    return _guard(() async {
      final res = await _dio.get(
        '/api/reports/sales/by-day',
        queryParameters: {'from': from, 'to': to},
      );
      final list = res.data as List;
      return list
          .map((e) => SalesByDay.fromJson(e as Map<String, dynamic>))
          .toList();
    }, fallback: const []);
  }

  Future<SyncStatus?> syncStatus(String from, String to) async {
    return _guard(() async {
      final res = await _dio.get(
        '/api/reports/status',
        queryParameters: {'from': from, 'to': to},
      );
      return SyncStatus.fromJson(res.data as Map<String, dynamic>);
    }, fallback: null);
  }

  Future<PaginatedSales> salesList(
    String from,
    String to, {
    int page = 1,
    int pageSize = 20,
  }) async {
    return _guard(
      () async {
        final res = await _dio.get(
          '/api/reports/sales/list',
          queryParameters: {
            'from': from,
            'to': to,
            'page': page,
            'pageSize': pageSize,
          },
        );
        return PaginatedSales.fromJson(res.data as Map<String, dynamic>);
      },
      fallback: PaginatedSales(
        data: const [],
        page: page,
        pageSize: pageSize,
        total: 0,
      ),
    );
  }

  Future<SaleDetail> saleDetail(int id) async {
    return _guard(() async {
      final res = await _dio.get('/api/reports/sales/$id');
      return SaleDetail.fromJson(res.data as Map<String, dynamic>);
    });
  }

  Future<ExpensesSummary?> expensesSummary(String from, String to) async {
    return _guard(() async {
      final res = await _dio.get(
        '/api/expenses/summary',
        queryParameters: {'from': from, 'to': to},
        options: _allowNotFoundOptions(),
      );
      if (res.statusCode == 404) return null;
      return ExpensesSummary.fromJson(res.data as Map<String, dynamic>);
    }, fallback: null);
  }

  Future<T> _guard<T>(Future<T> Function() action, {T? fallback}) async {
    try {
      return await action();
    } on DioException catch (e) {
      if (fallback != null) {
        return fallback;
      }
      final message =
          e.response?.data?['message']?.toString() ?? 'Error de conexión.';
      throw Exception(message);
    } catch (error) {
      if (fallback != null) {
        return fallback;
      }
      if (error is Exception) {
        rethrow;
      }
      throw Exception('Error inesperado: ${error.toString()}');
    }
  }
}

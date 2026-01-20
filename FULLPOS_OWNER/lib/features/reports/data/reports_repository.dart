import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../core/network/api_client.dart';
import '../../../core/network/unauthorized_exception.dart';
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

  Future<Response<dynamic>> _getWithNotFoundFallback(
    String primaryPath, {
    Map<String, dynamic>? queryParameters,
    List<String> fallbackPaths = const [],
  }) async {
    return _guard(() async {
      final options = _allowNotFoundOptions();
      final primary = await _dio.get(
        primaryPath,
        queryParameters: queryParameters,
        options: options,
      );
      if (primary.statusCode != 404) return primary;

      for (final alt in fallbackPaths) {
        final res = await _dio.get(
          alt,
          queryParameters: queryParameters,
          options: options,
        );
        if (res.statusCode != 404) return res;
      }

      return primary;
    });
  }

  Future<SalesSummary> salesSummary(String from, String to) async {
    return _guard(() async {
      final res = await _dio.get(
        '/api/reports/sales/summary',
        queryParameters: {'from': from, 'to': to},
      );
      return SalesSummary.fromJson(res.data as Map<String, dynamic>);
    });
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
    });
  }

  Future<PaginatedSales> salesList(
    String from,
    String to, {
    int page = 1,
  }) async {
    return _guard(() async {
      final res = await _dio.get(
        '/api/reports/sales/list',
        queryParameters: {'from': from, 'to': to, 'page': page, 'pageSize': 20},
      );
      return PaginatedSales.fromJson(res.data as Map<String, dynamic>);
    });
  }

  Future<List<CashClosing>> cashClosings(String from, String to) async {
    return _guard(() async {
      final res = await _dio.get(
        '/api/reports/cash/closings',
        queryParameters: {'from': from, 'to': to},
      );
      final list = res.data as List;
      return list
          .map((e) => CashClosing.fromJson(e as Map<String, dynamic>))
          .toList();
    });
  }

  Future<CashClosingDetail> cashClosingDetail(int id) async {
    return _guard(() async {
      final res = await _dio.get('/api/reports/cash/closing/$id');
      return CashClosingDetail.fromJson(res.data as Map<String, dynamic>);
    });
  }

  Future<ExpensesSummary?> expensesSummary(String from, String to) async {
    return _guard(() async {
      final res = await _getWithNotFoundFallback(
        '/api/expenses/summary',
        queryParameters: {'from': from, 'to': to},
        fallbackPaths: const ['/api/reports/expenses/summary'],
      );
      if (res.statusCode == 404) return null;
      return ExpensesSummary.fromJson(res.data as Map<String, dynamic>);
    });
  }

  Future<PaginatedExpenses> expensesList(
    String from,
    String to, {
    int page = 1,
    int pageSize = 20,
  }) async {
    return _guard(() async {
      final res = await _getWithNotFoundFallback(
        '/api/expenses',
        queryParameters: {
          'from': from,
          'to': to,
          'page': page,
          'pageSize': pageSize,
        },
        fallbackPaths: const ['/api/reports/expenses/list'],
      );
      if (res.statusCode == 404) {
        return PaginatedExpenses(
          data: const [],
          page: page,
          pageSize: pageSize,
          total: 0,
        );
      }
      return PaginatedExpenses.fromJson(res.data as Map<String, dynamic>);
    });
  }

  Future<ExpenseRow> createExpense({
    required double amount,
    required String category,
    String? note,
    DateTime? incurredAt,
  }) async {
    return _guard(() async {
      final res = await _dio.post(
        '/api/expenses',
        options: _allowNotFoundOptions(),
        data: {
          'amount': amount,
          'category': category,
          'note': note,
          if (incurredAt != null) 'incurredAt': incurredAt.toIso8601String(),
        },
      );
      if (res.statusCode == 404) {
        throw Exception('La nube no tiene el módulo de gastos habilitado.');
      }
      return ExpenseRow.fromJson(res.data as Map<String, dynamic>);
    });
  }

  Future<T> _guard<T>(Future<T> Function() action) async {
    try {
      return await action();
    } on DioException catch (e) {
      if (e.response?.statusCode == 401) {
        throw const UnauthorizedException();
      }
      rethrow;
    }
  }
}

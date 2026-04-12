import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/network/api_client.dart';

final categoriesRepositoryProvider = Provider<CategoriesRepository>((ref) {
  final dio = ref.read(apiClientProvider).dio;
  return CategoriesRepository(dio);
});

class CategoriesRepository {
  CategoriesRepository(this._dio);

  final Dio _dio;

  Future<List<String>> list() async {
    try {
      final response = await _dio.get('/api/categories');
      final body = response.data;
      if (body is! Map) return const [];

      final data = body['data'];
      if (data is! List) return const [];

      final categories = data
          .map((item) {
            if (item is! Map) return null;
            final rawName = item['name'];
            if (rawName is! String) return null;
            final normalized = rawName.trim();
            return normalized.isEmpty ? null : normalized;
          })
          .whereType<String>()
          .toSet()
          .toList()
        ..sort((a, b) => a.toLowerCase().compareTo(b.toLowerCase()));

      return categories;
    } on DioException {
      return const [];
    } catch (_) {
      return const [];
    }
  }
}
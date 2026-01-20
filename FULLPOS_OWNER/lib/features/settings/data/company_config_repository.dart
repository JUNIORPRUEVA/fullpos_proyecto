import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/network/api_client.dart';
import 'company_config.dart';

final companyConfigRepositoryProvider = Provider<CompanyConfigRepository>((ref) {
  final dio = ref.read(apiClientProvider).dio;
  return CompanyConfigRepository(dio);
});

class CompanyConfigRepository {
  CompanyConfigRepository(this._dio);

  final Dio _dio;

  Options _allowNotFoundOptions() => Options(
        validateStatus: (status) =>
            status != null &&
            ((status >= 200 && status < 300) || status == 404),
      );

  Future<CompanyConfig?> fetch() async {
    final response = await _dio.get(
      '/api/companies/config',
      options: _allowNotFoundOptions(),
    );
    if (response.statusCode == 404) return null;
    return CompanyConfig.fromJson(response.data as Map<String, dynamic>);
  }

  Future<CompanyConfig?> update(Map<String, dynamic> data) async {
    final response = await _dio.put(
      '/api/companies/config',
      options: _allowNotFoundOptions(),
      data: data,
    );
    if (response.statusCode == 404) return null;
    return CompanyConfig.fromJson(response.data as Map<String, dynamic>);
  }
}

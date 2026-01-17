import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../core/network/api_client.dart';
import 'override_models.dart';

class OverrideRepository {
  OverrideRepository(this._dio);

  final Dio _dio;

  Future<List<OverrideRequestItem>> fetchRequests({
    String status = 'pending',
    int limit = 50,
  }) async {
    final response = await _dio.get(
      '/api/override/requests',
      queryParameters: {'status': status, 'limit': limit},
    );
    final data = response.data as List<dynamic>;
    return data
        .map((item) => OverrideRequestItem.fromJson(item as Map<String, dynamic>))
        .toList();
  }

  Future<ApprovedOverrideToken> approveRequest(
    int requestId, {
    int? expiresInSeconds,
  }) async {
    final response = await _dio.post(
      '/api/override/approve',
      data: {
        'requestId': requestId,
        if (expiresInSeconds != null) 'expiresInSeconds': expiresInSeconds,
      },
    );
    return ApprovedOverrideToken.fromJson(
      response.data as Map<String, dynamic>,
    );
  }
}

final overrideRepositoryProvider = Provider<OverrideRepository>((ref) {
  final dio = ref.read(apiClientProvider).dio;
  return OverrideRepository(dio);
});

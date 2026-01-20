import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../core/network/api_client.dart';
import 'override_models.dart';

class OverrideRequestsResult {
  OverrideRequestsResult({
    required this.items,
    required this.statusCode,
    this.message,
  });

  final List<OverrideRequestItem> items;
  final int statusCode;
  final String? message;
}

class ApproveRequestResult {
  ApproveRequestResult({required this.statusCode, this.token, this.message});

  final int statusCode;
  final ApprovedOverrideToken? token;
  final String? message;
}

class OverrideRepository {
  OverrideRepository(this._dio);

  final Dio _dio;

  Future<OverrideRequestsResult> fetchRequests({
    String status = 'pending',
    int limit = 50,
  }) async {
    try {
      final response = await _dio.get(
        '/api/override/requests',
        queryParameters: {'status': status, 'limit': limit},
        options: Options(validateStatus: (_) => true),
      );
      final statusCode = response.statusCode ?? 0;
      if (statusCode == 200) {
        final data = response.data as List<dynamic>;
        final items = data
            .map(
              (item) =>
                  OverrideRequestItem.fromJson(item as Map<String, dynamic>),
            )
            .toList();
        return OverrideRequestsResult(items: items, statusCode: statusCode);
      }
      return OverrideRequestsResult(
        items: const [],
        statusCode: statusCode,
        message: _readMessage(response.data),
      );
    } on DioException catch (e) {
      return OverrideRequestsResult(
        items: const [],
        statusCode: e.response?.statusCode ?? 0,
        message: _readMessage(e.response?.data) ?? 'No se pudo conectar.',
      );
    }
  }

  Future<ApproveRequestResult> approveRequest(
    int requestId, {
    int? expiresInSeconds,
  }) async {
    try {
      final response = await _dio.post(
        '/api/override/approve',
        data: {
          'requestId': requestId,
          if (expiresInSeconds != null) 'expiresInSeconds': expiresInSeconds,
        },
        options: Options(validateStatus: (_) => true),
      );
      final statusCode = response.statusCode ?? 0;
      if (statusCode == 200) {
        return ApproveRequestResult(
          statusCode: statusCode,
          token: ApprovedOverrideToken.fromJson(
            response.data as Map<String, dynamic>,
          ),
        );
      }
      return ApproveRequestResult(
        statusCode: statusCode,
        message: _readMessage(response.data),
      );
    } on DioException catch (e) {
      return ApproveRequestResult(
        statusCode: e.response?.statusCode ?? 0,
        message: _readMessage(e.response?.data) ?? 'No se pudo conectar.',
      );
    }
  }
}

String? _readMessage(dynamic data) {
  if (data is Map<String, dynamic>) {
    final message = data['message']?.toString();
    if (message != null && message.trim().isNotEmpty) return message;
  }
  return null;
}

final overrideRepositoryProvider = Provider<OverrideRepository>((ref) {
  final dio = ref.read(apiClientProvider).dio;
  return OverrideRepository(dio);
});

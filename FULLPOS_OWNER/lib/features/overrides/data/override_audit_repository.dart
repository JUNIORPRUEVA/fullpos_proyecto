import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../core/network/api_client.dart';
import 'override_audit_models.dart';

class OverrideAuditResult {
  OverrideAuditResult({
    required this.items,
    required this.statusCode,
    this.message,
  });

  final List<OverrideAuditEntry> items;
  final int statusCode;
  final String? message;
}

class OverrideAuditRepository {
  OverrideAuditRepository(this._dio);

  final Dio _dio;

  Future<OverrideAuditResult> fetchAudit({int limit = 100}) async {
    try {
      final response = await _dio.get(
        '/api/override/audit',
        queryParameters: {'limit': limit},
        options: Options(validateStatus: (_) => true),
      );
      final statusCode = response.statusCode ?? 0;
      if (statusCode == 200) {
        final data = response.data as List<dynamic>;
        final items = data
            .map(
              (item) =>
                  OverrideAuditEntry.fromJson(item as Map<String, dynamic>),
            )
            .toList();
        return OverrideAuditResult(items: items, statusCode: statusCode);
      }
      return OverrideAuditResult(
        items: const [],
        statusCode: statusCode,
        message: _readMessage(response.data),
      );
    } on DioException catch (e) {
      return OverrideAuditResult(
        items: const [],
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

final overrideAuditRepositoryProvider = Provider<OverrideAuditRepository>((
  ref,
) {
  final dio = ref.read(apiClientProvider).dio;
  return OverrideAuditRepository(dio);
});

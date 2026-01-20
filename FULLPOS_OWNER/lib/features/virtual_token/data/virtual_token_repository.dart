import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/network/api_client.dart';
import '../../../core/storage/secure_storage.dart';

class VirtualTokenProvision {
  VirtualTokenProvision({
    required this.terminalId,
    required this.secret,
    required this.digits,
    required this.periodSeconds,
    required this.otpauthUri,
  });

  final String terminalId;
  final String secret;
  final int digits;
  final int periodSeconds;
  final String otpauthUri;

  factory VirtualTokenProvision.fromJson(Map<String, dynamic> json) {
    return VirtualTokenProvision(
      terminalId: (json['terminalId'] ?? '').toString(),
      secret: (json['secret'] ?? '').toString(),
      digits: (json['digits'] as num?)?.toInt() ?? 6,
      periodSeconds: (json['periodSeconds'] as num?)?.toInt() ?? 30,
      otpauthUri: (json['otpauthUri'] ?? '').toString(),
    );
  }
}

class VirtualTokenRepository {
  VirtualTokenRepository(this._dio, this._storage);

  final Dio _dio;
  final SecureStorage _storage;

  Future<VirtualTokenProvision> provision({required String terminalId}) async {
    final uid = await _storage.getOrCreateInstallationId();
    final response = await _dio.post(
      '/api/override/virtual/provision',
      data: {
        'terminalId': terminalId.trim(),
        'uid': uid,
      },
    );
    return VirtualTokenProvision.fromJson(
      response.data as Map<String, dynamic>,
    );
  }
}

final virtualTokenRepositoryProvider = Provider<VirtualTokenRepository>((ref) {
  final dio = ref.read(apiClientProvider).dio;
  final storage = ref.read(secureStorageProvider);
  return VirtualTokenRepository(dio, storage);
});


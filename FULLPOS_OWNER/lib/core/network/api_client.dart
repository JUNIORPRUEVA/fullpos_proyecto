import 'dart:io';
import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../config/app_config.dart';
import '../storage/secure_storage.dart';

class ApiClient {
  ApiClient({required SecureStorage storage, String? baseUrl})
      : _storage = storage,
        dio = Dio(
          BaseOptions(
            baseUrl: baseUrl ?? defaultBaseUrl,
            connectTimeout: const Duration(seconds: 10),
            receiveTimeout: const Duration(seconds: 10),
          ),
        ) {
    final host = Uri.parse(baseUrl ?? defaultBaseUrl).host;
    dio.httpClientAdapter = IOHttpClientAdapter(
      createHttpClient: () {
        final client = HttpClient();
        client.badCertificateCallback = (cert, h, port) => h == host;
        return client;
      },
    );
    dio.interceptors.add(
      QueuedInterceptorsWrapper(
        onRequest: (options, handler) async {
          if (_shouldAttachBearer(options.path)) {
            final token = await _storage.readToken();
            final trimmedToken = token?.trim();
            if (trimmedToken != null && trimmedToken.isNotEmpty) {
              options.headers[HttpHeaders.authorizationHeader] =
                  'Bearer $trimmedToken';
            }
          }
          handler.next(options);
        },
      ),
    );
  }

  final SecureStorage _storage;
  final Dio dio;

  bool _shouldAttachBearer(String path) {
    final normalized = path.trim().toLowerCase();
    return normalized != '/api/auth/login' && normalized != '/api/auth/refresh';
  }
}

final apiClientProvider = Provider<ApiClient>((ref) {
  final config = ref.watch(appConfigProvider);
  final storage = ref.watch(secureStorageProvider);
  return ApiClient(storage: storage, baseUrl: config.baseUrl);
});

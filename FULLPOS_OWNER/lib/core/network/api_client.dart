import 'dart:async';
import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../storage/secure_storage.dart';
import '../config/app_config.dart';

class ApiClient {
  ApiClient(this._storage, {String? baseUrl})
      : dio = Dio(
          BaseOptions(
            baseUrl: baseUrl ?? defaultBaseUrl,
            connectTimeout: const Duration(seconds: 10),
            receiveTimeout: const Duration(seconds: 10),
          ),
        ),
        _refreshDio = Dio(
          BaseOptions(
            baseUrl: baseUrl ?? defaultBaseUrl,
            connectTimeout: const Duration(seconds: 10),
            receiveTimeout: const Duration(seconds: 10),
          ),
        ) {
    dio.interceptors.add(InterceptorsWrapper(
      onRequest: (options, handler) async {
        final token = await _storage.readToken();
        if (token != null && options.headers['Authorization'] == null) {
          options.headers['Authorization'] = 'Bearer $token';
        }
        return handler.next(options);
      },
      onError: (error, handler) async {
        if (error.response?.statusCode == 401 && error.requestOptions.extra['retry'] != true) {
          final refreshToken = await _storage.readRefreshToken();
          if (refreshToken == null) {
            await _storage.clear();
            return handler.next(error);
          }

          final newToken = await _refreshAccessToken(refreshToken);
          if (newToken == null) {
            await _storage.clear();
            return handler.next(error);
          }

          final requestOptions = error.requestOptions;
          requestOptions.headers['Authorization'] = 'Bearer $newToken';
          requestOptions.extra['retry'] = true;
          try {
            final response = await dio.fetch(requestOptions);
            return handler.resolve(response);
          } catch (retryError) {
            if (retryError is DioException) {
              return handler.next(retryError);
            }
            return handler.next(error);
          }
        }
        return handler.next(error);
      },
    ));
  }

  final Dio dio;
  final Dio _refreshDio;
  final SecureStorage _storage;
  Completer<String?>? _refreshCompleter;

  Future<String?> _refreshAccessToken(String refreshToken) {
    if (_refreshCompleter != null) {
      return _refreshCompleter!.future;
    }

    final completer = Completer<String?>();
    _refreshCompleter = completer;

    () async {
      try {
        final response = await _refreshDio.post('/api/auth/refresh', data: {
          'refreshToken': refreshToken,
        });
        final data = response.data as Map<String, dynamic>;
        final tokens = data['tokens'] as Map<String, dynamic>;
        final accessToken = tokens['accessToken'] as String?;
        final newRefreshToken = tokens['refreshToken'] as String?;
        if (accessToken != null && newRefreshToken != null) {
          await _storage.saveToken(accessToken, newRefreshToken);
        }
        completer.complete(accessToken);
      } catch (_) {
        completer.complete(null);
      } finally {
        _refreshCompleter = null;
      }
    }();

    return completer.future;
  }
}

final apiClientProvider = Provider<ApiClient>((ref) {
  final storage = ref.read(secureStorageProvider);
  final config = ref.watch(appConfigProvider);
  return ApiClient(storage, baseUrl: config.baseUrl);
});

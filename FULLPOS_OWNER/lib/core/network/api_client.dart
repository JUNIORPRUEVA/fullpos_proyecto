import 'dart:async';
import 'dart:io';
import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../config/app_config.dart';
import '../storage/secure_storage.dart';

class ApiClient {
  ApiClient({required SecureStorage storage, String? baseUrl})
      : _storage = storage,
        _baseUrl = baseUrl ?? defaultBaseUrl,
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
        onError: (error, handler) async {
          final response = error.response;
          final statusCode = response?.statusCode;
          final requestOptions = error.requestOptions;
          final alreadyRetried = requestOptions.extra['retried'] == true;

          if (statusCode != 401 ||
              alreadyRetried ||
              !_shouldAttachBearer(requestOptions.path)) {
            handler.next(error);
            return;
          }

          final refreshedToken = await _refreshAccessToken();
          if (refreshedToken == null || refreshedToken.isEmpty) {
            handler.next(error);
            return;
          }

          try {
            final retriedResponse = await _retryRequestWithToken(
              requestOptions,
              refreshedToken,
            );
            handler.resolve(retriedResponse);
          } on DioException catch (retryError) {
            handler.next(retryError);
          } catch (_) {
            handler.next(error);
          }
        },
      ),
    );
  }

  final SecureStorage _storage;
  final String _baseUrl;
  final Dio dio;
  Completer<String?>? _refreshCompleter;

  bool _shouldAttachBearer(String path) {
    final normalized = path.trim().toLowerCase();
    return normalized != '/api/auth/login' && normalized != '/api/auth/refresh';
  }

  Future<String?> _refreshAccessToken() async {
    final existingRefresh = _refreshCompleter;
    if (existingRefresh != null) {
      return existingRefresh.future;
    }

    final completer = Completer<String?>();
    _refreshCompleter = completer;

    try {
      final refreshToken = (await _storage.readRefreshToken())?.trim();
      if (refreshToken == null || refreshToken.isEmpty) {
        await _storage.clear();
        completer.complete(null);
        return completer.future;
      }

      final refreshDio = Dio(
        BaseOptions(
          baseUrl: _baseUrl,
          connectTimeout: const Duration(seconds: 10),
          receiveTimeout: const Duration(seconds: 10),
        ),
      );
      refreshDio.httpClientAdapter = dio.httpClientAdapter;

      final response = await refreshDio.post(
        '/api/auth/refresh',
        data: {'refreshToken': refreshToken},
      );

      final body = response.data;
      if (body is! Map) {
        await _storage.clear();
        completer.complete(null);
        return completer.future;
      }

      final data = Map<String, dynamic>.from(body);
      final tokens = data['tokens'] is Map
          ? Map<String, dynamic>.from(data['tokens'] as Map)
          : <String, dynamic>{};
      final newAccessToken = tokens['accessToken']?.toString().trim();
      final newRefreshToken = tokens['refreshToken']?.toString().trim();

      if (newAccessToken == null ||
          newAccessToken.isEmpty ||
          newRefreshToken == null ||
          newRefreshToken.isEmpty) {
        await _storage.clear();
        completer.complete(null);
        return completer.future;
      }

      await _storage.saveToken(newAccessToken, newRefreshToken);
      completer.complete(newAccessToken);
      return completer.future;
    } catch (_) {
      await _storage.clear();
      completer.complete(null);
      return completer.future;
    } finally {
      _refreshCompleter = null;
    }
  }

  Future<Response<dynamic>> _retryRequestWithToken(
    RequestOptions requestOptions,
    String accessToken,
  ) {
    final headers = Map<String, dynamic>.from(requestOptions.headers)
      ..[HttpHeaders.authorizationHeader] = 'Bearer $accessToken';

    final retriedOptions = requestOptions.copyWith(
      headers: headers,
      extra: Map<String, dynamic>.from(requestOptions.extra)
        ..['retried'] = true,
    );

    return dio.fetch<dynamic>(retriedOptions);
  }
}

final apiClientProvider = Provider<ApiClient>((ref) {
  final config = ref.watch(appConfigProvider);
  final storage = ref.watch(secureStorageProvider);
  return ApiClient(storage: storage, baseUrl: config.baseUrl);
});

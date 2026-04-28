import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:dio/dio.dart';
import '../../../core/errors/friendly_api_error.dart';
import '../../../core/network/api_client.dart';
import '../../../core/storage/secure_storage.dart';
import 'auth_state.dart';

final authRepositoryProvider = StateNotifierProvider<AuthRepository, AuthState>(
  (ref) => AuthRepository(ref),
);

class AuthRepository extends StateNotifier<AuthState> {
  AuthRepository(this._ref) : super(AuthState.initial());

  final Ref _ref;

  Dio get _dio => _ref.read(apiClientProvider).dio;
  SecureStorage get _storage => _ref.read(secureStorageProvider);

  String _extractErrorMessage(Object? errorBody) {
    if (errorBody == null) return 'Error de autenticacion';
    if (errorBody is Map) {
      final message = errorBody['message'];
      if (message != null) return message.toString();
    }
    if (errorBody is String && errorBody.trim().isNotEmpty) {
      return errorBody;
    }
    return 'Error de autenticacion';
  }

  int? _toInt(dynamic value) {
    if (value == null) return null;
    if (value is int) return value;
    if (value is num) return value.toInt();
    final parsed = int.tryParse(value.toString());
    return parsed;
  }

  bool _isCloudRoleAllowed(String? role) {
    final normalized = role?.trim().toLowerCase();
    return normalized == 'admin' || normalized == 'owner';
  }

  String _cleanExceptionMessage(Object error) {
    final text = error.toString().replaceFirst('Exception: ', '').trim();
    return text.isEmpty ? 'No pudimos iniciar sesion.' : text;
  }

  Future<void> login(String identifier, String password) async {
    state = state.copyWith(loading: true);
    try {
      final response = await _dio.post(
        '/api/auth/login',
        data: {'identifier': identifier, 'password': password},
      );

      final body = response.data;
      if (body is! Map) {
        throw Exception('Respuesta invalida del servidor');
      }

      final data = Map<String, dynamic>.from(body);
      final user = data['user'] is Map
          ? Map<String, dynamic>.from(data['user'] as Map)
          : <String, dynamic>{};
      final company = data['company'] is Map
          ? Map<String, dynamic>.from(data['company'] as Map)
          : <String, dynamic>{};
      final tokens = data['tokens'] is Map
          ? Map<String, dynamic>.from(data['tokens'] as Map)
          : <String, dynamic>{};

      final role = user['role']?.toString();
      if (!_isCloudRoleAllowed(role)) {
        throw Exception(
          'Solo usuarios Admin u Owner pueden usar FULLPOS Owner',
        );
      }

      final accessToken = tokens['accessToken']?.toString();
      final refreshToken = tokens['refreshToken']?.toString();
      if (accessToken == null || refreshToken == null) {
        throw Exception('Tokens invalidos');
      }
      await _storage.saveToken(accessToken, refreshToken);

      final userDisplayName =
          (user['displayName'] ?? user['name'] ?? user['fullName'])?.toString();
      final userEmail = user['email']?.toString();

      state = state.copyWith(
        accessToken: accessToken,
        refreshToken: refreshToken,
        companyName: company['name']?.toString() ?? 'Empresa',
        companyId: _toInt(company['id']),
        companyRnc: company['rnc']?.toString(),
        ownerVersion: company['version']?.toString(),
        username: user['username']?.toString(),
        displayName: userDisplayName,
        email: userEmail,
        loading: false,
      );
    } on DioException catch (e) {
      state = state.copyWith(loading: false);
      debugPrint('FULLPOS Owner login DioException: ${e.message}');
      debugPrint('FULLPOS Owner login response: ${e.response?.data}');
      final message = e.response?.statusCode == null
          ? FriendlyApiError.message(
              e,
              fallback: 'No pudimos iniciar sesion. Verifica tu conexion.',
            )
          : _extractErrorMessage(e.response?.data);
      throw Exception(message);
    } catch (e, st) {
      state = state.copyWith(loading: false);
      debugPrint('FULLPOS Owner login error: $e');
      debugPrintStack(stackTrace: st);
      throw Exception(_cleanExceptionMessage(e));
    }
  }

  Future<void> me() async {
    final token = await _storage.readToken();
    final refreshToken = await _storage.readRefreshToken();
    final trimmedToken = token?.trim();
    final trimmedRefreshToken = refreshToken?.trim();
    if (trimmedToken == null || trimmedToken.isEmpty) return;
    state = state.copyWith(loading: true);
    try {
      final response = await _dio.get('/api/auth/me');
      final body = response.data;
      if (body is! Map) {
        state = state.copyWith(loading: false);
        return;
      }
      final data = Map<String, dynamic>.from(body);
      final role = data['role']?.toString();
      if (!_isCloudRoleAllowed(role)) {
        await logout();
        return;
      }

      final company = data['company'] is Map
          ? Map<String, dynamic>.from(data['company'] as Map)
          : <String, dynamic>{};
      final userDisplayName =
          (data['displayName'] ?? data['name'] ?? data['fullName'])?.toString();
      final userEmail = data['email']?.toString();
      state = state.copyWith(
        accessToken: trimmedToken,
        refreshToken: trimmedRefreshToken,
        companyName: company['name']?.toString(),
        companyId: _toInt(company['id']),
        companyRnc: company['rnc']?.toString(),
        ownerVersion: company['version']?.toString(),
        username: data['username']?.toString(),
        displayName: userDisplayName,
        email: userEmail,
        loading: false,
      );
    } catch (_) {
      await logout();
    }
  }

  Future<void> logout() async {
    await _storage.clear();
    state = AuthState.initial();
  }
}

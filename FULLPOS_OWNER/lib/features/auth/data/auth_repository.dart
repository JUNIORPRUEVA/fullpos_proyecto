import 'dart:async';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:dio/dio.dart';
import '../../../core/network/api_client.dart';
import '../../../core/storage/secure_storage.dart';
import 'auth_state.dart';

final authRepositoryProvider =
    StateNotifierProvider<AuthRepository, AuthState>((ref) => AuthRepository(ref));

class AuthRepository extends StateNotifier<AuthState> {
  AuthRepository(this._ref) : super(AuthState.initial());

  final Ref _ref;

  Dio get _dio => _ref.read(apiClientProvider).dio;
  SecureStorage get _storage => _ref.read(secureStorageProvider);

  Future<void> login(String identifier, String password) async {
    state = state.copyWith(loading: true);
    try {
      final response = await _dio.post('/api/auth/login', data: {
        'identifier': identifier,
        'password': password,
      });

      final data = response.data as Map<String, dynamic>;
      final tokens = data['tokens'] as Map<String, dynamic>;
      await _storage.saveToken(tokens['accessToken'], tokens['refreshToken']);

      state = state.copyWith(
        accessToken: tokens['accessToken'] as String?,
        refreshToken: tokens['refreshToken'] as String?,
        companyName: (data['company']?['name'] as String?) ?? 'Empresa',
        ownerVersion: data['company']?['version'] as String?,
        username: data['user']?['username'] as String?,
        loading: false,
      );
    } on DioException catch (e) {
      state = state.copyWith(loading: false);
      throw Exception(e.response?.data?['message'] ?? 'Error de autenticación');
    }
  }

  Future<void> me() async {
    final token = await _storage.readToken();
    if (token == null) return;
    state = state.copyWith(loading: true);
    try {
      final response = await _dio.get('/api/auth/me');
      final data = response.data as Map<String, dynamic>;
      state = state.copyWith(
        companyName: data['company']?['name'] as String?,
        ownerVersion: data['company']?['version'] as String?,
        username: data['username'] as String?,
        loading: false,
      );
    } catch (_) {
      state = state.copyWith(loading: false);
    }
  }

  Future<void> logout() async {
    await _storage.clear();
    state = AuthState.initial();
  }
}

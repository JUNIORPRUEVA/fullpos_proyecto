import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

class SecureStorage {
  SecureStorage()
      : _storage = const FlutterSecureStorage(
          aOptions: AndroidOptions(
            encryptedSharedPreferences: true,
          ),
          iOptions: IOSOptions(
            accessibility: KeychainAccessibility.first_unlock,
          ),
        );

  final FlutterSecureStorage _storage;
  static const _tokenKey = 'fp_owner_token';
  static const _refreshKey = 'fp_owner_refresh';
  static const _baseUrlKey = 'fp_owner_base_url';

  Future<void> saveToken(String token, String refreshToken) async {
    await _storage.write(key: _tokenKey, value: token);
    await _storage.write(key: _refreshKey, value: refreshToken);
  }

  Future<String?> readToken() => _storage.read(key: _tokenKey);
  Future<String?> readRefreshToken() => _storage.read(key: _refreshKey);
  Future<String?> readBaseUrl() => _storage.read(key: _baseUrlKey);

  Future<void> clear() async {
    await _storage.delete(key: _tokenKey);
    await _storage.delete(key: _refreshKey);
  }

  Future<void> saveBaseUrl(String baseUrl) async {
    await _storage.write(key: _baseUrlKey, value: baseUrl);
  }

  Future<void> clearBaseUrl() async {
    await _storage.delete(key: _baseUrlKey);
  }
}

final secureStorageProvider = Provider<SecureStorage>((ref) => SecureStorage());

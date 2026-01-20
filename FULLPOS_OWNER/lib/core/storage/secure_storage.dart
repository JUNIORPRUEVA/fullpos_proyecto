import 'dart:convert';
import 'dart:math';

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
  static const _installationIdKey = 'fp_owner_installation_id';
  static const _virtualSecretsKey = 'fp_owner_virtual_secrets';
  static const _virtualActiveTerminalKey = 'fp_owner_virtual_active_terminal';

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
    await _storage.delete(key: _virtualSecretsKey);
    await _storage.delete(key: _virtualActiveTerminalKey);
  }

  Future<void> saveBaseUrl(String baseUrl) async {
    await _storage.write(key: _baseUrlKey, value: baseUrl);
  }

  Future<void> clearBaseUrl() async {
    await _storage.delete(key: _baseUrlKey);
  }

  Future<String> getOrCreateInstallationId() async {
    final existing = await _storage.read(key: _installationIdKey);
    if (existing != null && existing.trim().isNotEmpty) return existing.trim();

    final bytes = List<int>.generate(16, (_) => Random.secure().nextInt(256));
    final id = base64UrlEncode(bytes).replaceAll('=', '');
    await _storage.write(key: _installationIdKey, value: id);
    return id;
  }

  Future<Map<String, String>> readVirtualSecrets() async {
    final raw = await _storage.read(key: _virtualSecretsKey);
    if (raw == null || raw.trim().isEmpty) return {};
    try {
      final decoded = jsonDecode(raw) as Map<String, dynamic>;
      return decoded.map((k, v) => MapEntry(k, (v ?? '').toString()));
    } catch (_) {
      return {};
    }
  }

  Future<String?> readVirtualSecret(String terminalId) async {
    final map = await readVirtualSecrets();
    final secret = map[terminalId];
    if (secret == null || secret.trim().isEmpty) return null;
    return secret.trim();
  }

  Future<void> saveVirtualSecret({
    required String terminalId,
    required String secretBase32,
  }) async {
    final map = await readVirtualSecrets();
    map[terminalId] = secretBase32.trim();
    await _storage.write(key: _virtualSecretsKey, value: jsonEncode(map));
  }

  Future<void> removeVirtualSecret(String terminalId) async {
    final map = await readVirtualSecrets();
    map.remove(terminalId);
    await _storage.write(key: _virtualSecretsKey, value: jsonEncode(map));
  }

  Future<void> setActiveVirtualTerminal(String terminalId) async {
    await _storage.write(key: _virtualActiveTerminalKey, value: terminalId);
  }

  Future<String?> readActiveVirtualTerminal() async {
    final value = await _storage.read(key: _virtualActiveTerminalKey);
    if (value == null || value.trim().isEmpty) return null;
    return value.trim();
  }
}

final secureStorageProvider = Provider<SecureStorage>((ref) => SecureStorage());

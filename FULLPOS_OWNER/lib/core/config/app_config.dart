import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../storage/secure_storage.dart';

const String defaultBaseUrl = String.fromEnvironment(
  'OWNER_BACKEND_BASE_URL',
  defaultValue: 'https://fullpos-backend-fullpos-backend.onqyr1.easypanel.host',
);

const String enforcedOwnerBackendBaseUrl =
    'https://fullpos-backend-fullpos-backend.onqyr1.easypanel.host';

class AppConfigState {
  final String baseUrl;

  const AppConfigState({required this.baseUrl});
}

class AppConfigNotifier extends StateNotifier<AppConfigState> {
  AppConfigNotifier(this._storage)
    : super(const AppConfigState(baseUrl: enforcedOwnerBackendBaseUrl)) {
    _load();
  }

  final SecureStorage _storage;

  static String normalizeBaseUrl(String input) {
    var value = input.trim();
    if (value.isEmpty) return enforcedOwnerBackendBaseUrl;

    if (!value.startsWith('http://') && !value.startsWith('https://')) {
      value = 'https://$value';
    }

    while (value.endsWith('/')) {
      value = value.substring(0, value.length - 1);
    }

    return value;
  }

  Future<void> _load() async {
    // FULLPOS Owner debe usar exclusivamente el backend oficial.
    await _storage.clearBaseUrl();
    state = const AppConfigState(baseUrl: enforcedOwnerBackendBaseUrl);
  }

  Future<void> setBaseUrl(String baseUrl) async {
    await _storage.clearBaseUrl();
    state = const AppConfigState(baseUrl: enforcedOwnerBackendBaseUrl);
  }

  Future<void> resetBaseUrl() async {
    await _storage.clearBaseUrl();
    state = const AppConfigState(baseUrl: enforcedOwnerBackendBaseUrl);
  }
}

final appConfigProvider =
    StateNotifierProvider<AppConfigNotifier, AppConfigState>((ref) {
      final storage = ref.read(secureStorageProvider);
      return AppConfigNotifier(storage);
    });

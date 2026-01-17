import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../storage/secure_storage.dart';

const String defaultBaseUrl = String.fromEnvironment(
  'OWNER_BACKEND_BASE_URL',
  defaultValue: 'http://localhost:4000',
);

class AppConfigState {
  final String baseUrl;

  const AppConfigState({required this.baseUrl});
}

class AppConfigNotifier extends StateNotifier<AppConfigState> {
  AppConfigNotifier(this._storage)
      : super(const AppConfigState(baseUrl: defaultBaseUrl)) {
    _load();
  }

  final SecureStorage _storage;

  Future<void> _load() async {
    final stored = await _storage.readBaseUrl();
    if (stored != null && stored.trim().isNotEmpty) {
      state = AppConfigState(baseUrl: stored.trim());
    }
  }

  Future<void> setBaseUrl(String baseUrl) async {
    final normalized = baseUrl.trim();
    await _storage.saveBaseUrl(normalized);
    state = AppConfigState(baseUrl: normalized);
  }

  Future<void> resetBaseUrl() async {
    await _storage.clearBaseUrl();
    state = const AppConfigState(baseUrl: defaultBaseUrl);
  }
}

final appConfigProvider =
    StateNotifierProvider<AppConfigNotifier, AppConfigState>((ref) {
  final storage = ref.read(secureStorageProvider);
  return AppConfigNotifier(storage);
});

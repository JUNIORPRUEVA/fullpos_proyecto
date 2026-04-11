import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../storage/secure_storage.dart';

const String defaultBaseUrl = String.fromEnvironment(
  'OWNER_BACKEND_BASE_URL',
  defaultValue:
  'https://fullpos-backend-fullpos-backend.onqyr1.easypanel.host',
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
    // Mantener la URL fija desde el código. Ignorar valores guardados.
    await _storage.clearBaseUrl();
    state = const AppConfigState(baseUrl: defaultBaseUrl);
  }

  Future<void> setBaseUrl(String baseUrl) async {
    // URL fija: no permitir cambios desde UI.
    await _storage.clearBaseUrl();
    state = const AppConfigState(baseUrl: defaultBaseUrl);
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

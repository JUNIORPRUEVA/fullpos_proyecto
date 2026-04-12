import 'package:flutter_test/flutter_test.dart';
import 'package:fullpos_owner/core/config/app_config.dart';
import 'package:fullpos_owner/core/storage/secure_storage.dart';

class _FakeSecureStorage extends SecureStorage {
  String? storedBaseUrl;
  var clearBaseUrlCalls = 0;

  @override
  Future<String?> readBaseUrl() async => storedBaseUrl;

  @override
  Future<void> saveBaseUrl(String baseUrl) async {
    storedBaseUrl = baseUrl;
  }

  @override
  Future<void> clearBaseUrl() async {
    clearBaseUrlCalls += 1;
    storedBaseUrl = null;
  }
}

void main() {
  group('AppConfigNotifier', () {
    test('normalizeBaseUrl agrega esquema y quita slash final', () {
      expect(
        AppConfigNotifier.normalizeBaseUrl('mi-backend.com/'),
        'https://mi-backend.com',
      );
      expect(
        AppConfigNotifier.normalizeBaseUrl('http://localhost:4000///'),
        'http://localhost:4000',
      );
    });

    test('ignora baseUrl guardada y fuerza backend oficial', () async {
      final storage = _FakeSecureStorage()
        ..storedBaseUrl = 'https://mi-nube.example.com/';

      final notifier = AppConfigNotifier(storage);
      await Future<void>.delayed(Duration.zero);

      expect(storage.storedBaseUrl, isNull);
      expect(storage.clearBaseUrlCalls, 1);
      expect(notifier.state.baseUrl, enforcedOwnerBackendBaseUrl);
    });

    test('setBaseUrl no cambia el backend oficial', () async {
      final storage = _FakeSecureStorage()
        ..storedBaseUrl = 'https://mi-servidor.local';
      final notifier = AppConfigNotifier(storage);

      await notifier.setBaseUrl('mi-servidor.local/');

      expect(storage.storedBaseUrl, isNull);
      expect(notifier.state.baseUrl, enforcedOwnerBackendBaseUrl);
    });

    test('resetBaseUrl limpia storage y vuelve al default', () async {
      final storage = _FakeSecureStorage()
        ..storedBaseUrl = 'https://otra-nube.example.com';
      final notifier = AppConfigNotifier(storage);

      await notifier.resetBaseUrl();

      expect(storage.clearBaseUrlCalls, greaterThanOrEqualTo(1));
      expect(storage.storedBaseUrl, isNull);
      expect(notifier.state.baseUrl, enforcedOwnerBackendBaseUrl);
    });
  });
}
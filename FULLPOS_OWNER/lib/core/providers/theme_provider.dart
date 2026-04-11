import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../storage/secure_storage.dart';
import '../theme/app_themes.dart';

final themeModeProvider =
    StateNotifierProvider<ThemeModeController, ThemeMode>((ref) {
      return ThemeModeController(ref.read(secureStorageProvider));
    });

final themeDataProvider = Provider<ThemeData>((ref) {
  return AppThemes.getTheme(AppThemeKey.corporate);
});

final darkThemeDataProvider = Provider<ThemeData>((ref) {
  return AppThemes.getDarkTheme(AppThemeKey.corporate);
});

class ThemeModeController extends StateNotifier<ThemeMode> {
  ThemeModeController(this._storage) : super(ThemeMode.light) {
    _load();
  }

  final SecureStorage _storage;

  Future<void> _load() async {
    final savedMode = await _storage.readThemeMode();
    switch (savedMode) {
      case 'dark':
        state = ThemeMode.dark;
      case 'light':
      default:
        state = ThemeMode.light;
    }
  }

  Future<void> setThemeMode(ThemeMode mode) async {
    if (mode == state) return;
    state = mode;
    await _storage.saveThemeMode(mode == ThemeMode.dark ? 'dark' : 'light');
  }
}

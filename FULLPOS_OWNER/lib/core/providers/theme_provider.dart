import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../theme/app_themes.dart';

final appThemeProvider = StateNotifierProvider<AppThemeNotifier, AppThemeEnum>(
  (ref) => AppThemeNotifier(),
);

final themeDataProvider = Provider<ThemeData>((ref) {
  final theme = ref.watch(appThemeProvider);
  return AppThemes.getTheme(theme);
});

class AppThemeNotifier extends StateNotifier<AppThemeEnum> {
  AppThemeNotifier() : super(AppThemeEnum.proPos);

  void setTheme(AppThemeEnum theme) => state = theme;

  void setThemeByKey(String key) {
    state = AppThemes.getThemeEnumByKey(key);
  }
}

import 'package:flutter/material.dart';

import 'app_colors.dart';

enum AppThemeEnum {
  original,
  azulBlancoNegro,
  proPos,
}

extension AppThemeExtension on AppThemeEnum {
  String get label {
    switch (this) {
      case AppThemeEnum.azulBlancoNegro:
        return 'Azul / Blanco / Negro';
      case AppThemeEnum.proPos:
        return 'Profesional POS';
      case AppThemeEnum.original:
        return 'FULLPOS Premium';
    }
  }

  String get key => toString().split('.').last;
}

class AppThemes {
  AppThemes._();

  static ThemeData get original {
    const scheme = ColorScheme.light(
      primary: AppColors.teal700,
      onPrimary: AppColors.textLight,
      secondary: AppColors.gold,
      onSecondary: AppColors.textDark,
      surface: AppColors.surfaceLight,
      onSurface: AppColors.textDark,
    );

    return ThemeData(
      useMaterial3: true,
      colorScheme: scheme,
      scaffoldBackgroundColor: AppColors.bgLight,
      appBarTheme: const AppBarTheme(
        backgroundColor: AppColors.teal800,
        foregroundColor: AppColors.textLight,
        elevation: 0,
        iconTheme: IconThemeData(color: AppColors.textLight),
      ),
      cardTheme: CardThemeData(
        color: AppColors.surfaceLight,
        elevation: 2,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: AppColors.gold,
          foregroundColor: AppColors.textDark,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        ),
      ),
      textTheme: _textTheme(AppColors.textDark),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: AppColors.surfaceLight,
        border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
      ),
    );
  }

  static ThemeData get azulBlancoNegro {
    final scheme = ColorScheme.fromSeed(
      seedColor: const Color(0xFF003366),
      brightness: Brightness.light,
      primary: const Color(0xFF003366),
      secondary: const Color(0xFF00B8D9),
      surface: Colors.white,
      onSurface: const Color(0xFF111827),
    );

    return ThemeData(
      useMaterial3: true,
      colorScheme: scheme,
      scaffoldBackgroundColor: const Color(0xFFF5F7FB),
      appBarTheme: const AppBarTheme(
        backgroundColor: Color(0xFF003366),
        foregroundColor: Colors.white,
        elevation: 0,
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: const Color(0xFF003366),
          foregroundColor: Colors.white,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        ),
      ),
      cardTheme: CardThemeData(
        color: Colors.white,
        elevation: 2,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      ),
      textTheme: _textTheme(AppColors.textDark),
    );
  }

  static ThemeData get proPos {
    const scheme = ColorScheme.dark(
      primary: AppColors.teal500,
      onPrimary: AppColors.textLight,
      secondary: AppColors.gold,
      onSecondary: AppColors.textDark,
      surface: AppColors.surface,
      onSurface: AppColors.textLightSecondary,
    );

    return ThemeData(
      useMaterial3: true,
      colorScheme: scheme,
      scaffoldBackgroundColor: AppColors.bgDark,
      appBarTheme: const AppBarTheme(
        backgroundColor: AppColors.surface,
        foregroundColor: AppColors.textLight,
        elevation: 0,
      ),
      cardTheme: CardThemeData(
        color: AppColors.surfaceVariant,
        elevation: 3,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
      ),
      textTheme: _textTheme(AppColors.textLight),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: AppColors.teal600,
          foregroundColor: AppColors.textLight,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
        ),
      ),
    );
  }

  static ThemeData getTheme(AppThemeEnum theme) {
    switch (theme) {
      case AppThemeEnum.azulBlancoNegro:
        return azulBlancoNegro;
      case AppThemeEnum.proPos:
        return proPos;
      case AppThemeEnum.original:
        return original;
    }
  }

  static AppThemeEnum getThemeEnumByKey(String key) {
    return AppThemeEnum.values.firstWhere(
      (option) => option.key == key,
      orElse: () => AppThemeEnum.proPos,
    );
  }

  static TextTheme _textTheme(Color color) {
    final base = Typography.material2018().black;
    return base
        .apply(bodyColor: color, displayColor: color)
        .copyWith(
          titleLarge: const TextStyle(fontWeight: FontWeight.bold, fontSize: 20)
              .copyWith(color: color),
        );
  }
}

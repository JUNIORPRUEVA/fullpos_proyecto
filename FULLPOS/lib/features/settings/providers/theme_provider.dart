import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../data/theme_settings_model.dart';
import '../data/theme_settings_repository.dart';
import '../../../core/constants/app_sizes.dart';

/// Notifier para manejar el estado del tema
class ThemeNotifier extends StateNotifier<ThemeSettings> {
  final ThemeSettingsRepository _repository;

  ThemeNotifier(this._repository) : super(ThemeSettings.defaultSettings) {
    _loadSettings();
  }

  /// Cargar configuración guardada
  Future<void> _loadSettings() async {
    final settings = await _repository.loadThemeSettings();
    state = settings;
  }

  /// Actualizar color primario
  Future<void> updatePrimaryColor(Color color) async {
    final newSettings = state.copyWith(primaryColor: color);
    state = newSettings;
    await _repository.saveThemeSettings(newSettings);
  }

  /// Actualizar color de acento
  Future<void> updateAccentColor(Color color) async {
    final newSettings = state.copyWith(accentColor: color);
    state = newSettings;
    await _repository.saveThemeSettings(newSettings);
  }

  /// Actualizar color de fondo
  Future<void> updateBackgroundColor(Color color) async {
    final newSettings = state.copyWith(backgroundColor: color);
    state = newSettings;
    await _repository.saveThemeSettings(newSettings);
  }

  /// Actualizar color de superficie
  Future<void> updateSurfaceColor(Color color) async {
    final newSettings = state.copyWith(surfaceColor: color);
    state = newSettings;
    await _repository.saveThemeSettings(newSettings);
  }

  /// Actualizar color de texto
  Future<void> updateTextColor(Color color) async {
    final newSettings = state.copyWith(textColor: color);
    state = newSettings;
    await _repository.saveThemeSettings(newSettings);
  }

  /// Actualizar color del AppBar
  Future<void> updateAppBarColor(Color color) async {
    final newSettings = state.copyWith(appBarColor: color);
    state = newSettings;
    await _repository.saveThemeSettings(newSettings);
  }

  /// Actualizar color del texto del AppBar
  Future<void> updateAppBarTextColor(Color color) async {
    final newSettings = state.copyWith(appBarTextColor: color);
    state = newSettings;
    await _repository.saveThemeSettings(newSettings);
  }

  /// Actualizar color de cards
  Future<void> updateCardColor(Color color) async {
    final newSettings = state.copyWith(cardColor: color);
    state = newSettings;
    await _repository.saveThemeSettings(newSettings);
  }

  /// Actualizar color de botones
  Future<void> updateButtonColor(Color color) async {
    final newSettings = state.copyWith(buttonColor: color);
    state = newSettings;
    await _repository.saveThemeSettings(newSettings);
  }

  /// Actualizar color de éxito
  Future<void> updateSuccessColor(Color color) async {
    final newSettings = state.copyWith(successColor: color);
    state = newSettings;
    await _repository.saveThemeSettings(newSettings);
  }

  /// Actualizar color de error
  Future<void> updateErrorColor(Color color) async {
    final newSettings = state.copyWith(errorColor: color);
    state = newSettings;
    await _repository.saveThemeSettings(newSettings);
  }

  /// Actualizar color de advertencia
  Future<void> updateWarningColor(Color color) async {
    final newSettings = state.copyWith(warningColor: color);
    state = newSettings;
    await _repository.saveThemeSettings(newSettings);
  }

  /// Actualizar color del sidebar
  Future<void> updateSidebarColor(Color color) async {
    final newSettings = state.copyWith(sidebarColor: color);
    state = newSettings;
    await _repository.saveThemeSettings(newSettings);
  }

  /// Actualizar color del texto del sidebar
  Future<void> updateSidebarTextColor(Color color) async {
    final newSettings = state.copyWith(sidebarTextColor: color);
    state = newSettings;
    await _repository.saveThemeSettings(newSettings);
  }

  /// Actualizar color activo del sidebar
  Future<void> updateSidebarActiveColor(Color color) async {
    final newSettings = state.copyWith(sidebarActiveColor: color);
    state = newSettings;
    await _repository.saveThemeSettings(newSettings);
  }

  /// Actualizar color del footer
  Future<void> updateFooterColor(Color color) async {
    final newSettings = state.copyWith(footerColor: color);
    state = newSettings;
    await _repository.saveThemeSettings(newSettings);
  }

  /// Actualizar color del texto del footer
  Future<void> updateFooterTextColor(Color color) async {
    final newSettings = state.copyWith(footerTextColor: color);
    state = newSettings;
    await _repository.saveThemeSettings(newSettings);
  }

  /// Actualizar tamaño de fuente
  Future<void> updateFontSize(double size) async {
    final newSettings = state.copyWith(fontSize: size);
    state = newSettings;
    await _repository.saveThemeSettings(newSettings);
  }

  /// Actualizar familia de fuente
  Future<void> updateFontFamily(String family) async {
    final newSettings = state.copyWith(fontFamily: family);
    state = newSettings;
    await _repository.saveThemeSettings(newSettings);
  }

  /// Cambiar modo oscuro
  Future<void> toggleDarkMode() async {
    final targetIsDark = !state.isDarkMode;
    final base = state.copyWith(isDarkMode: targetIsDark);
    // Auto-ajuste: si el usuario aún tiene colores "de claro" al pasar a oscuro
    // (o viceversa), ajustamos fondo/surface/texto/appbar/sidebar/footer para que
    // el modo se vea diferente. Si ya están configurados para ese modo, se respetan.
    final newSettings = _autoAdjustForMode(base, isDark: targetIsDark);
    state = newSettings;
    await _repository.saveThemeSettings(newSettings);
  }

  /// Aplicar tema preset
  Future<void> applyPreset(String presetName) async {
    final preset = PresetThemes.getPreset(presetName);
    state = preset;
    await _repository.saveThemeSettings(preset);
  }

  /// Resetear a valores por defecto
  Future<void> resetToDefault() async {
    await _repository.resetToDefault();
    state = ThemeSettings.defaultSettings;
  }

  /// Guardar configuración actual
  Future<void> saveSettings(ThemeSettings settings) async {
    state = settings;
    await _repository.saveThemeSettings(settings);
  }

  ThemeSettings _autoAdjustForMode(
    ThemeSettings settings, {
    required bool isDark,
  }) {
    bool isTooLight(Color c) => c.computeLuminance() > 0.45;
    bool isTooDark(Color c) => c.computeLuminance() < 0.25;
    Color contrast(Color c) =>
        c.computeLuminance() > 0.5 ? Colors.black : Colors.white;

    // Paleta base para modo oscuro (corporativa neutra)
    const darkBg = Color(0xFF0B1220);
    const darkSurface = Color(0xFF111827);
    const darkText = Color(0xFFE5E7EB);
    const darkMuted = Color(0xFF94A3B8);

    // Paleta base para modo claro (surface gris claro solicitado)
    const lightBg = Color(0xFFF3F6F5);
    const lightSurface = Color(0xFFF8F9F9);
    const lightText = Color(0xFF1F2937);

    if (isDark) {
      final nextAppBarColor = isTooLight(settings.appBarColor)
          ? darkBg
          : settings.appBarColor;
      final nextSidebarColor = isTooLight(settings.sidebarColor)
          ? darkBg
          : settings.sidebarColor;
      return settings.copyWith(
        backgroundColor: isTooLight(settings.backgroundColor)
            ? darkBg
            : settings.backgroundColor,
        surfaceColor: isTooLight(settings.surfaceColor)
            ? darkSurface
            : settings.surfaceColor,
        cardColor: isTooLight(settings.cardColor)
            ? darkSurface
            : settings.cardColor,
        textColor: isTooDark(settings.textColor)
            ? darkText
            : settings.textColor,
        appBarColor: nextAppBarColor,
        appBarTextColor: isTooDark(settings.appBarTextColor)
            ? contrast(nextAppBarColor)
            : settings.appBarTextColor,
        sidebarColor: nextSidebarColor,
        sidebarTextColor: isTooDark(settings.sidebarTextColor)
            ? contrast(nextSidebarColor)
            : settings.sidebarTextColor,
        footerColor: isTooLight(settings.footerColor)
            ? darkBg
            : settings.footerColor,
        footerTextColor: isTooDark(settings.footerTextColor)
            ? darkMuted
            : settings.footerTextColor,
      );
    }

    final nextAppBarColor = isTooDark(settings.appBarColor)
        ? settings.primaryColor
        : settings.appBarColor;
    // En modo claro: solo corregimos fondo/surface/texto/appbar si venimos de un esquema muy oscuro.
    // Sidebar/Footer pueden ser oscuros en modo claro, así que no los forzamos.
    return settings.copyWith(
      backgroundColor: isTooDark(settings.backgroundColor)
          ? lightBg
          : settings.backgroundColor,
      surfaceColor: isTooDark(settings.surfaceColor)
          ? lightSurface
          : settings.surfaceColor,
      cardColor: isTooDark(settings.cardColor)
          ? Colors.white
          : settings.cardColor,
      textColor: isTooLight(settings.textColor)
          ? lightText
          : settings.textColor,
      appBarColor: nextAppBarColor,
      appBarTextColor: (nextAppBarColor != settings.appBarColor)
          ? contrast(nextAppBarColor)
          : settings.appBarTextColor,
      // Mantener sidebar/footer tal cual (configuración del usuario o preset)
      footerTextColor: settings.footerTextColor,
    );
  }
}

/// Provider del repositorio
final themeRepositoryProvider = Provider<ThemeSettingsRepository>((ref) {
  return ThemeSettingsRepository();
});

/// Provider del tema
final themeProvider = StateNotifierProvider<ThemeNotifier, ThemeSettings>((
  ref,
) {
  final repository = ref.watch(themeRepositoryProvider);
  return ThemeNotifier(repository);
});

/// Provider que genera el ThemeData a partir de ThemeSettings
final themeDataProvider = Provider<ThemeData>((ref) {
  final settings = ref.watch(themeProvider);
  return _buildThemeData(settings);
});

/// Construye el ThemeData a partir de ThemeSettings
ThemeData _buildThemeData(ThemeSettings settings) {
  final brightness = settings.isDarkMode ? Brightness.dark : Brightness.light;
  final onPrimary = _getContrastColor(settings.primaryColor);
  final onAccent = _getContrastColor(settings.accentColor);
  final onSurface = settings.textColor;
  final scaffoldBg = settings.backgroundColor.opacity == 0
      ? Colors.white
      : settings.backgroundColor;
  final surfaceColor = settings.surfaceColor.opacity == 0
      ? Colors.white
      : settings.surfaceColor;

  return ThemeData(
    useMaterial3: true,
    brightness: brightness,

    colorScheme: ColorScheme(
      brightness: brightness,
      primary: settings.primaryColor,
      onPrimary: onPrimary,
      secondary: settings.accentColor,
      onSecondary: onAccent,
      surface: surfaceColor,
      onSurface: onSurface,
      error: settings.errorColor,
      onError: Colors.white,
      surfaceContainerHighest: surfaceColor.withAlpha(230),
      background: scaffoldBg,
      onBackground: onSurface,
    ),

    scaffoldBackgroundColor: scaffoldBg,

    // AppBar
    appBarTheme: AppBarTheme(
      backgroundColor: settings.appBarColor,
      foregroundColor: _getContrastColor(settings.appBarColor),
      elevation: 0,
      centerTitle: false,
      iconTheme: IconThemeData(color: _getContrastColor(settings.appBarColor)),
    ),

    // Cards
    cardTheme: CardThemeData(
      color: settings.cardColor,
      elevation: 1,
      shadowColor: Colors.black.withAlpha(20),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(AppSizes.radiusL),
        side: BorderSide(color: settings.textColor.withAlpha(25), width: 1),
      ),
    ),

    // Input decoration
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: surfaceColor,
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(AppSizes.radiusM),
        borderSide: BorderSide(
          color: settings.textColor.withAlpha(30),
          width: 1,
        ),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(AppSizes.radiusM),
        borderSide: BorderSide(
          color: settings.textColor.withAlpha(30),
          width: 1,
        ),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(AppSizes.radiusM),
        borderSide: BorderSide(color: settings.primaryColor, width: 2),
      ),
      errorBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(AppSizes.radiusM),
        borderSide: BorderSide(color: settings.errorColor, width: 2),
      ),
      contentPadding: const EdgeInsets.symmetric(
        horizontal: AppSizes.paddingM,
        vertical: AppSizes.paddingM,
      ),
    ),

    // Elevated Button
    elevatedButtonTheme: ElevatedButtonThemeData(
      style: ElevatedButton.styleFrom(
        backgroundColor: settings.buttonColor,
        foregroundColor: _getContrastColor(settings.buttonColor),
        minimumSize: const Size(0, 48),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(AppSizes.radiusM),
        ),
        elevation: 2,
        textStyle: TextStyle(
          fontWeight: FontWeight.w600,
          fontSize: settings.fontSize + 1,
          fontFamily: settings.fontFamily,
        ),
      ),
    ),

    // Outlined Button
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: settings.primaryColor,
        side: BorderSide(color: settings.primaryColor, width: 1.5),
        minimumSize: const Size(0, 48),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(AppSizes.radiusM),
        ),
      ),
    ),

    // Text Button
    textButtonTheme: TextButtonThemeData(
      style: TextButton.styleFrom(
        foregroundColor: settings.primaryColor,
        minimumSize: const Size(0, 48),
      ),
    ),

    // Divider
    dividerTheme: DividerThemeData(
      color: settings.textColor.withAlpha(30),
      thickness: 1,
      space: 1,
    ),

    // Text theme
    textTheme: TextTheme(
      displayLarge: TextStyle(
        color: settings.textColor,
        fontSize: settings.fontSize + 18,
        fontWeight: FontWeight.bold,
        fontFamily: settings.fontFamily,
      ),
      displayMedium: TextStyle(
        color: settings.textColor,
        fontSize: settings.fontSize + 14,
        fontWeight: FontWeight.bold,
        fontFamily: settings.fontFamily,
      ),
      titleLarge: TextStyle(
        color: settings.textColor,
        fontSize: settings.fontSize + 8,
        fontWeight: FontWeight.w600,
        fontFamily: settings.fontFamily,
      ),
      titleMedium: TextStyle(
        color: settings.textColor,
        fontSize: settings.fontSize + 4,
        fontWeight: FontWeight.w600,
        fontFamily: settings.fontFamily,
      ),
      bodyLarge: TextStyle(
        color: settings.textColor,
        fontSize: settings.fontSize + 2,
        fontWeight: FontWeight.normal,
        fontFamily: settings.fontFamily,
      ),
      bodyMedium: TextStyle(
        color: settings.textColor,
        fontSize: settings.fontSize,
        fontWeight: FontWeight.normal,
        fontFamily: settings.fontFamily,
      ),
      labelLarge: TextStyle(
        color: settings.textColor.withAlpha(180),
        fontSize: settings.fontSize,
        fontWeight: FontWeight.w500,
        fontFamily: settings.fontFamily,
      ),
    ),
  );
}

/// Obtiene el color de contraste (blanco o negro) según la luminosidad
Color _getContrastColor(Color color) {
  final luminance = color.computeLuminance();
  return luminance > 0.5 ? Colors.black : Colors.white;
}

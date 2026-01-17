import 'package:flutter/material.dart';

/// Modelo para la configuración del tema personalizado
class ThemeSettings {
  final Color primaryColor;
  final Color accentColor;
  final Color backgroundColor;
  final Color surfaceColor;
  final Color textColor;
  final Color appBarColor;
  final Color appBarTextColor;
  final Color cardColor;
  final Color buttonColor;
  final Color successColor;
  final Color errorColor;
  final Color warningColor;
  // Nuevos colores para sidebar y footer
  final Color sidebarColor;
  final Color sidebarTextColor;
  final Color sidebarActiveColor;
  final Color footerColor;
  final Color footerTextColor;
  final double fontSize;
  final String fontFamily;
  final bool isDarkMode;

  const ThemeSettings({
    required this.primaryColor,
    required this.accentColor,
    required this.backgroundColor,
    required this.surfaceColor,
    required this.textColor,
    required this.appBarColor,
    required this.appBarTextColor,
    required this.cardColor,
    required this.buttonColor,
    required this.successColor,
    required this.errorColor,
    required this.warningColor,
    required this.sidebarColor,
    required this.sidebarTextColor,
    required this.sidebarActiveColor,
    required this.footerColor,
    required this.footerTextColor,
    required this.fontSize,
    required this.fontFamily,
    required this.isDarkMode,
  });

  /// Valores por defecto (tema azul ejecutivo)
  static const ThemeSettings defaultSettings = ThemeSettings(
    primaryColor: Color(0xFF0D84FF), // azul eléctrico premium
    accentColor: Color(0xFF0D84FF), // un solo acento
    backgroundColor: Color(0xFF050915), // base negro-azul
    surfaceColor: Color(0xFF0F1B2C), // superficies oscuras
    textColor: Color(0xFFE8EEF7),
    appBarColor: Color(0xFF0B2038),
    appBarTextColor: Color(0xFFFFFFFF),
    cardColor: Color(0xFF0F1B2C),
    buttonColor: Color(0xFF0D84FF),
    successColor: Color(0xFF10B981), // success
    errorColor: Color(0xFFEF4444), // error
    warningColor: Color(0xFFF59E0B), // warning
    sidebarColor: Color(0xFF050915),
    sidebarTextColor: Color(0xFFD8E5F5),
    sidebarActiveColor: Color(0xFF0D84FF),
    footerColor: Color(0xFF0B2038),
    footerTextColor: Color(0xFFAEBED6),
    fontSize: 14.0,
    fontFamily: 'Roboto',
    isDarkMode: false,
  );

  /// Crear desde Map (para cargar desde DB)
  factory ThemeSettings.fromMap(Map<String, dynamic> map) {
    return ThemeSettings(
      primaryColor: Color(map['primaryColor'] as int? ?? 0xFF0D84FF),
      accentColor: Color(map['accentColor'] as int? ?? 0xFF0D84FF),
      backgroundColor: Color(map['backgroundColor'] as int? ?? 0xFF050915),
      surfaceColor: Color(map['surfaceColor'] as int? ?? 0xFF0F1B2C),
      textColor: Color(map['textColor'] as int? ?? 0xFFE8EEF7),
      appBarColor: Color(map['appBarColor'] as int? ?? 0xFF0B2038),
      appBarTextColor: Color(map['appBarTextColor'] as int? ?? 0xFFFFFFFF),
      cardColor: Color(map['cardColor'] as int? ?? 0xFF0F1B2C),
      buttonColor: Color(map['buttonColor'] as int? ?? 0xFF0D84FF),
      successColor: Color(map['successColor'] as int? ?? 0xFF10B981),
      errorColor: Color(map['errorColor'] as int? ?? 0xFFEF4444),
      warningColor: Color(map['warningColor'] as int? ?? 0xFFF59E0B),
      sidebarColor: Color(map['sidebarColor'] as int? ?? 0xFF050915),
      sidebarTextColor: Color(
        map['sidebarTextColor'] as int? ?? 0xFFD8E5F5,
      ),
      sidebarActiveColor: Color(
        map['sidebarActiveColor'] as int? ?? 0xFF0D84FF,
      ),
      footerColor: Color(map['footerColor'] as int? ?? 0xFF0B2038),
      footerTextColor: Color(map['footerTextColor'] as int? ?? 0xFFAEBED6),
      fontSize: (map['fontSize'] as num?)?.toDouble() ?? 14.0,
      fontFamily: map['fontFamily'] as String? ?? 'Roboto',
      isDarkMode: (map['isDarkMode'] as int? ?? 0) == 1,
    );
  }

  /// Convertir a Map (para guardar en DB)
  Map<String, dynamic> toMap() {
    return {
      'primaryColor': primaryColor.toARGB32(),
      'accentColor': accentColor.toARGB32(),
      'backgroundColor': backgroundColor.toARGB32(),
      'surfaceColor': surfaceColor.toARGB32(),
      'textColor': textColor.toARGB32(),
      'appBarColor': appBarColor.toARGB32(),
      'appBarTextColor': appBarTextColor.toARGB32(),
      'cardColor': cardColor.toARGB32(),
      'buttonColor': buttonColor.toARGB32(),
      'successColor': successColor.toARGB32(),
      'errorColor': errorColor.toARGB32(),
      'warningColor': warningColor.toARGB32(),
      'sidebarColor': sidebarColor.toARGB32(),
      'sidebarTextColor': sidebarTextColor.toARGB32(),
      'sidebarActiveColor': sidebarActiveColor.toARGB32(),
      'footerColor': footerColor.toARGB32(),
      'footerTextColor': footerTextColor.toARGB32(),
      'fontSize': fontSize,
      'fontFamily': fontFamily,
      'isDarkMode': isDarkMode ? 1 : 0,
    };
  }

  /// Crear copia con modificaciones
  ThemeSettings copyWith({
    Color? primaryColor,
    Color? accentColor,
    Color? backgroundColor,
    Color? surfaceColor,
    Color? textColor,
    Color? appBarColor,
    Color? appBarTextColor,
    Color? cardColor,
    Color? buttonColor,
    Color? successColor,
    Color? errorColor,
    Color? warningColor,
    Color? sidebarColor,
    Color? sidebarTextColor,
    Color? sidebarActiveColor,
    Color? footerColor,
    Color? footerTextColor,
    double? fontSize,
    String? fontFamily,
    bool? isDarkMode,
  }) {
    return ThemeSettings(
      primaryColor: primaryColor ?? this.primaryColor,
      accentColor: accentColor ?? this.accentColor,
      backgroundColor: backgroundColor ?? this.backgroundColor,
      surfaceColor: surfaceColor ?? this.surfaceColor,
      textColor: textColor ?? this.textColor,
      appBarColor: appBarColor ?? this.appBarColor,
      appBarTextColor: appBarTextColor ?? this.appBarTextColor,
      cardColor: cardColor ?? this.cardColor,
      buttonColor: buttonColor ?? this.buttonColor,
      successColor: successColor ?? this.successColor,
      errorColor: errorColor ?? this.errorColor,
      warningColor: warningColor ?? this.warningColor,
      sidebarColor: sidebarColor ?? this.sidebarColor,
      sidebarTextColor: sidebarTextColor ?? this.sidebarTextColor,
      sidebarActiveColor: sidebarActiveColor ?? this.sidebarActiveColor,
      footerColor: footerColor ?? this.footerColor,
      footerTextColor: footerTextColor ?? this.footerTextColor,
      fontSize: fontSize ?? this.fontSize,
      fontFamily: fontFamily ?? this.fontFamily,
      isDarkMode: isDarkMode ?? this.isDarkMode,
    );
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    return other is ThemeSettings &&
        other.primaryColor == primaryColor &&
        other.accentColor == accentColor &&
        other.backgroundColor == backgroundColor &&
        other.surfaceColor == surfaceColor &&
        other.textColor == textColor &&
        other.appBarColor == appBarColor &&
        other.cardColor == cardColor &&
        other.buttonColor == buttonColor &&
        other.successColor == successColor &&
        other.errorColor == errorColor &&
        other.warningColor == warningColor &&
        other.sidebarColor == sidebarColor &&
        other.sidebarTextColor == sidebarTextColor &&
        other.sidebarActiveColor == sidebarActiveColor &&
        other.footerColor == footerColor &&
        other.footerTextColor == footerTextColor &&
        other.fontSize == fontSize &&
        other.fontFamily == fontFamily &&
        other.isDarkMode == isDarkMode;
  }

  @override
  int get hashCode => Object.hash(
    primaryColor,
    accentColor,
    backgroundColor,
    surfaceColor,
    textColor,
    appBarColor,
    cardColor,
    buttonColor,
    successColor,
    errorColor,
    warningColor,
    sidebarColor,
    sidebarTextColor,
    sidebarActiveColor,
    footerColor,
    footerTextColor,
    fontSize,
    fontFamily,
    isDarkMode,
  );
}

/// Temas predefinidos para selección rápida
class PresetThemes {
  PresetThemes._();

  static const Map<String, ThemeSettings> presets = {
    'default': ThemeSettings.defaultSettings,
    'ocean': ThemeSettings(
      // Corporativo: Negro/Azul/Blanco (elegante)
      primaryColor: Color(0xFF0F4C81),
      accentColor: Color(0xFF38BDF8),
      backgroundColor: Color(0xFFF5F7FB),
      surfaceColor: Color(0xFFF8F9F9),
      textColor: Color(0xFF0F172A),
      appBarColor: Color(0xFF0B1220),
      appBarTextColor: Color(0xFFF8FAFC),
      cardColor: Color(0xFFFFFFFF),
      buttonColor: Color(0xFF0F4C81),
      successColor: Color(0xFF16A34A),
      errorColor: Color(0xFFDC2626),
      warningColor: Color(0xFFF59E0B),
      sidebarColor: Color(0xFF0B1220),
      sidebarTextColor: Color(0xFFE2E8F0),
      sidebarActiveColor: Color(0xFF38BDF8),
      footerColor: Color(0xFF0B1220),
      footerTextColor: Color(0xFF94A3B8),
      fontSize: 14.0,
      fontFamily: 'Poppins',
      isDarkMode: false,
    ),
    'sunset': ThemeSettings(
      primaryColor: Color(0xFFE65100), // deep orange
      accentColor: Color(0xFFFFB74D), // amber
      backgroundColor: Color(0xFFFFF3E0),
      surfaceColor: Color(0xFFFFFFFF),
      textColor: Color(0xFF3E2723),
      appBarColor: Color(0xFFBF360C),
      appBarTextColor: Color(0xFFFFFFFF),
      cardColor: Color(0xFFFFFFFF),
      buttonColor: Color(0xFFFFB74D),
      successColor: Color(0xFF66BB6A),
      errorColor: Color(0xFFE53935),
      warningColor: Color(0xFFFFCA28),
      sidebarColor: Color(0xFF4E342E),
      sidebarTextColor: Color(0xFFFFCCBC),
      sidebarActiveColor: Color(0xFFFFB74D),
      footerColor: Color(0xFF4E342E),
      footerTextColor: Color(0xFFBCAAA4),
      fontSize: 14.0,
      fontFamily: 'Roboto',
      isDarkMode: false,
    ),
    'forest': ThemeSettings(
      // Corporativo: Naranja/Blanco/Azul (energético y profesional)
      primaryColor: Color(0xFF0B3A60),
      accentColor: Color(0xFFF97316),
      backgroundColor: Color(0xFFF7FAFF),
      surfaceColor: Color(0xFFF8F9F9),
      textColor: Color(0xFF0F172A),
      appBarColor: Color(0xFF0B3A60),
      appBarTextColor: Color(0xFFFFFFFF),
      cardColor: Color(0xFFFFFFFF),
      buttonColor: Color(0xFFF97316),
      successColor: Color(0xFF16A34A),
      errorColor: Color(0xFFDC2626),
      warningColor: Color(0xFFF59E0B),
      sidebarColor: Color(0xFF0B3A60),
      sidebarTextColor: Color(0xFFE2E8F0),
      sidebarActiveColor: Color(0xFFF97316),
      footerColor: Color(0xFF0B3A60),
      footerTextColor: Color(0xFFCBD5E1),
      fontSize: 14.0,
      fontFamily: 'Poppins',
      isDarkMode: false,
    ),
    'purple': ThemeSettings(
      // Corporativo: Grafito/Blanco/Teal (sobrio y elegante)
      primaryColor: Color(0xFF1F2937),
      accentColor: Color(0xFF14B8A6),
      backgroundColor: Color(0xFFF3F4F6),
      surfaceColor: Color(0xFFF8F9F9),
      textColor: Color(0xFF111827),
      appBarColor: Color(0xFF111827),
      appBarTextColor: Color(0xFFFFFFFF),
      cardColor: Color(0xFFFFFFFF),
      buttonColor: Color(0xFF14B8A6),
      successColor: Color(0xFF16A34A),
      errorColor: Color(0xFFDC2626),
      warningColor: Color(0xFFF59E0B),
      sidebarColor: Color(0xFF111827),
      sidebarTextColor: Color(0xFFD1D5DB),
      sidebarActiveColor: Color(0xFF14B8A6),
      footerColor: Color(0xFF111827),
      footerTextColor: Color(0xFF9CA3AF),
      fontSize: 14.0,
      fontFamily: 'Poppins',
      isDarkMode: false,
    ),
    'dark': ThemeSettings(
      primaryColor: Color(0xFF00796B),
      accentColor: Color(0xFFD4AF37),
      backgroundColor: Color(0xFF121212),
      surfaceColor: Color(0xFF1E1E1E),
      textColor: Color(0xFFE0E0E0),
      appBarColor: Color(0xFF1E1E1E),
      appBarTextColor: Color(0xFFE0E0E0),
      cardColor: Color(0xFF2D2D2D),
      buttonColor: Color(0xFFD4AF37),
      successColor: Color(0xFF4CAF50),
      errorColor: Color(0xFFCF6679),
      warningColor: Color(0xFFFFB74D),
      sidebarColor: Color(0xFF1E1E1E),
      sidebarTextColor: Color(0xFFBDBDBD),
      sidebarActiveColor: Color(0xFFD4AF37),
      footerColor: Color(0xFF1E1E1E),
      footerTextColor: Color(0xFF757575),
      fontSize: 14.0,
      fontFamily: 'Roboto',
      isDarkMode: true,
    ),
  };

  static List<String> get presetNames => presets.keys.toList();

  static ThemeSettings getPreset(String name) {
    return presets[name] ?? ThemeSettings.defaultSettings;
  }
}

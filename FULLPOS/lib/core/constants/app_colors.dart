import 'package:flutter/material.dart';

/// Colores del tema LOS NILKAS (Teal + Gold)
class AppColors {
  AppColors._();

  // Teal principal (marca)
  static const Color teal = Color(0xFF00695C); // Alias principal
  static const Color teal900 = Color(0xFF004D40);
  static const Color teal800 = Color(0xFF00695C);
  static const Color teal700 = Color(0xFF00796B);
  static const Color teal600 = Color(0xFF00897B);
  static const Color teal500 = Color(0xFF009688);
  static const Color teal400 = Color(0xFF26A69A);
  static const Color teal300 = Color(0xFF4DB6AC);

  // Gold/Dorado (acento)
  static const Color gold = Color(0xFFD4AF37);
  static const Color goldBright = Color(0xFFFFD700);
  static const Color goldSoft = Color(0xFFFFC107);
  static const Color goldDark = Color(0xFFA67C00);

  // Backgrounds claros (nuevo)
  static const Color bgLight = Color(
    0xFFF3F6F5,
  ); // gris casi blanco con toque teal
  static const Color bgLightAlt = Color(0xFFF1F5F3);

  // Surfaces claras
  static const Color surfaceLight = Color(0xFFFFFFFF); // blanco
  static const Color surfaceLightVariant = Color(0xFFF8F9F9); // gris muy claro
  static const Color surfaceLightBorder = Color(0xFFE0E5E4); // bordes sutiles

  // Backgrounds oscuros (para sidebar/topbar)
  static const Color bgDark = Color(0xFF1A1A1A);
  static const Color surfaceDark = Color(0xFF242424);
  static const Color surfaceDarkVariant = Color(0xFF2E2E2E);

  // Textos en fondos claros
  static const Color textDark = Color(0xFF1F2937); // gris oscuro casi negro
  static const Color textDarkSecondary = Color(0xFF6B7280); // gris medio
  static const Color textDarkMuted = Color(0xFF9CA3AF); // gris claro

  // Textos en fondos oscuros
  static const Color textLight = Color(0xFFFFFFFF);
  static const Color textLightSecondary = Color(0xFFE5E7EB);
  static const Color textLightMuted = Color(0xFFB0BEC5);

  // Aliases para compatibilidad (legacy)
  static const Color textPrimary = textLight;
  static const Color textSecondary = textLightSecondary;
  static const Color textMuted = textLightMuted;
  static const Color surface = surfaceDark;
  static const Color surfaceVariant = surfaceDarkVariant;

  // Estados
  static const Color success = Color(0xFF10B981);
  static const Color successLight = Color(0xFFD1FAE5);
  static const Color error = Color(0xFFEF4444);
  static const Color errorLight = Color(0xFFFEE2E2);
  static const Color warning = Color(0xFFF59E0B);
  static const Color warningLight = Color(0xFFFEF3C7);
  static const Color info = Color(0xFF3B82F6);
  static const Color infoLight = Color(0xFFDBEAFE);
}

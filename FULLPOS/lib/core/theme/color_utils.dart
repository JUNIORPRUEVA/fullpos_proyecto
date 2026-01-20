import 'package:flutter/material.dart';

class ColorUtils {
  ColorUtils._();

  /// Returns the best foreground color (dark or light) for the provided [background].
  static Color foregroundFor(
    Color background, {
    Color dark = Colors.black,
    Color light = Colors.white,
  }) {
    return background.computeLuminance() > 0.5 ? dark : light;
  }

  /// Returns whether the provided color is considered "light" for contrast decisions.
  static bool isLight(Color color) => color.computeLuminance() > 0.5;
}

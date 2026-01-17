import 'package:flutter/material.dart';

import '../constants/app_colors.dart';

class AppToast {
  AppToast._();

  static void show(
    BuildContext context,
    String message, {
    Color backgroundColor = AppColors.teal900,
  }) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: backgroundColor,
      ),
    );
  }
}


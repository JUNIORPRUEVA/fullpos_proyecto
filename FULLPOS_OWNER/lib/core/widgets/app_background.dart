import 'package:flutter/material.dart';

import '../theme/app_colors.dart';

class AppBackground extends StatelessWidget {
  const AppBackground({super.key, required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          colors: [AppColors.background, AppColors.white],
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
        ),
      ),
      child: Stack(
        fit: StackFit.expand,
        children: [
          Positioned(
            top: -90,
            right: -40,
            child: DecoratedBox(
              decoration: BoxDecoration(
                color: AppColors.primaryBlueSoft.withAlpha((0.9 * 255).round()),
                shape: BoxShape.circle,
              ),
              child: const SizedBox(width: 220, height: 220),
            ),
          ),
          const Positioned(
            bottom: -70,
            left: -20,
            child: DecoratedBox(
              decoration: BoxDecoration(
                color: AppColors.surfaceMuted,
                shape: BoxShape.circle,
              ),
              child: SizedBox(width: 180, height: 180),
            ),
          ),
          child,
        ],
      ),
    );
  }
}

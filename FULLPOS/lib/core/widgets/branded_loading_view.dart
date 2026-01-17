import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../constants/app_colors.dart';
import '../constants/app_sizes.dart';
import '../../features/settings/providers/business_settings_provider.dart';

class BrandedLoadingView extends ConsumerWidget {
  final String message;
  final bool fullScreen;

  const BrandedLoadingView({
    super.key,
    this.message = 'Cargando...',
    this.fullScreen = true,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final business = ref.watch(businessSettingsProvider);
    final businessName = business.businessName.isNotEmpty
        ? business.businessName
        : 'MI NEGOCIO';
    final logoPath = business.logoPath;
    final hasLogo = logoPath != null && File(logoPath).existsSync();

    final content = Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Container(
            width: 150,
            height: 150,
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(20),
              boxShadow: [
                BoxShadow(
                  color: AppColors.gold.withOpacity(0.3),
                  blurRadius: 30,
                  spreadRadius: 5,
                ),
              ],
            ),
            child: ClipRRect(
              borderRadius: BorderRadius.circular(20),
              child: hasLogo
                  ? Image.file(File(logoPath), fit: BoxFit.cover)
                  : Image.asset(
                      'assets/imagen/app.icon.png',
                      fit: BoxFit.cover,
                    ),
            ),
          ),
          const SizedBox(height: AppSizes.spaceL),
          Text(
            '$businessName POS',
            style: const TextStyle(
              color: AppColors.gold,
              fontSize: 38,
              fontWeight: FontWeight.bold,
              letterSpacing: 2.5,
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: AppSizes.spaceXL * 2),
          const CircularProgressIndicator(color: AppColors.gold),
          const SizedBox(height: AppSizes.spaceL),
          Text(
            message,
            style: const TextStyle(color: AppColors.textMuted, fontSize: 16),
          ),
        ],
      ),
    );

    if (!fullScreen) {
      return Material(color: Colors.transparent, child: content);
    }

    return Scaffold(
      backgroundColor: AppColors.bgDark,
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [AppColors.bgDark, AppColors.teal900],
          ),
        ),
        child: content,
      ),
    );
  }
}

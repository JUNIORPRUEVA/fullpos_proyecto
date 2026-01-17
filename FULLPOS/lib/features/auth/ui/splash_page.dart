import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/bootstrap/app_bootstrap_controller.dart';
import '../../../core/constants/app_colors.dart';
import '../../../core/constants/app_sizes.dart';
import '../../settings/providers/business_settings_provider.dart';

/// Pantalla de splash (carga inicial)
class SplashPage extends ConsumerWidget {
  const SplashPage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final boot = ref.watch(appBootstrapProvider).snapshot;

    final business = ref.watch(businessSettingsProvider);
    final businessName = business.businessName.isNotEmpty
        ? business.businessName
        : 'MI NEGOCIO';
    final logoPath = business.logoPath;
    final hasLogo = logoPath != null && File(logoPath).existsSync();

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
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 520),
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24),
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
                      fontSize: 42,
                      fontWeight: FontWeight.bold,
                      letterSpacing: 3,
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: AppSizes.spaceXL * 2),
                  if (boot.status == BootStatus.error) ...[
                    const Icon(
                      Icons.error_outline,
                      color: AppColors.error,
                      size: 46,
                    ),
                    const SizedBox(height: AppSizes.spaceM),
                    Text(
                      boot.errorMessage ?? 'No se pudo iniciar la aplicación.',
                      style: const TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 15,
                        height: 1.3,
                      ),
                      textAlign: TextAlign.center,
                    ),
                    const SizedBox(height: AppSizes.spaceL),
                    FilledButton.icon(
                      onPressed: () => ref.read(appBootstrapProvider).retry(),
                      icon: const Icon(Icons.refresh),
                      label: const Text('Reintentar'),
                    ),
                  ] else ...[
                    const CircularProgressIndicator(color: AppColors.gold),
                    const SizedBox(height: AppSizes.spaceL),
                    Text(
                      boot.message.isNotEmpty ? boot.message : 'Iniciando...',
                      style: const TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 16,
                      ),
                      textAlign: TextAlign.center,
                    ),
                  ],
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}


import 'dart:io';

import 'package:flutter/material.dart';

import '../../features/settings/data/business_settings_repository.dart';
import '../constants/app_colors.dart';
import '../constants/app_sizes.dart';

class BootstrapLoadingScreen extends StatefulWidget {
  final String message;

  const BootstrapLoadingScreen({super.key, this.message = 'Iniciando...'});

  @override
  State<BootstrapLoadingScreen> createState() => _BootstrapLoadingScreenState();
}

class _BootstrapLoadingScreenState extends State<BootstrapLoadingScreen> {
  late final Future<_BootstrapBranding> _future;

  @override
  void initState() {
    super.initState();
    _future = _load();
  }

  Future<_BootstrapBranding> _load() async {
    try {
      final settings = await BusinessSettingsRepository().loadSettings();
      final name = settings.businessName.isNotEmpty
          ? settings.businessName
          : 'MI NEGOCIO';
      final logoPath = settings.logoPath;
      final hasLogo = logoPath != null && File(logoPath).existsSync();
      return _BootstrapBranding(
        businessName: name,
        logoPath: hasLogo ? logoPath : null,
      );
    } catch (_) {
      return const _BootstrapBranding(
        businessName: 'MI NEGOCIO',
        logoPath: null,
      );
    }
  }

  @override
  Widget build(BuildContext context) {
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
        child: FutureBuilder<_BootstrapBranding>(
          future: _future,
          builder: (context, snapshot) {
            final branding =
                snapshot.data ??
                const _BootstrapBranding(
                  businessName: 'MI NEGOCIO',
                  logoPath: null,
                );
            final hasLogo = branding.logoPath != null;

            return Center(
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
                          ? Image.file(
                              File(branding.logoPath!),
                              fit: BoxFit.cover,
                            )
                          : Image.asset(
                              'assets/imagen/app.icon.png',
                              fit: BoxFit.cover,
                            ),
                    ),
                  ),
                  const SizedBox(height: AppSizes.spaceL),
                  Text(
                    '${branding.businessName} POS',
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
                    widget.message,
                    style: const TextStyle(
                      color: AppColors.textMuted,
                      fontSize: 16,
                    ),
                  ),
                ],
              ),
            );
          },
        ),
      ),
    );
  }
}

class _BootstrapBranding {
  final String businessName;
  final String? logoPath;

  const _BootstrapBranding({
    required this.businessName,
    required this.logoPath,
  });
}

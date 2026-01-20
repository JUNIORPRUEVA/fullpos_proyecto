import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../core/providers/theme_provider.dart';
import '../core/config/app_router.dart';
import '../features/auth/data/auth_repository.dart';
import '../features/auth/data/auth_state.dart';
import '../features/settings/data/company_config.dart';
import '../features/settings/providers/company_config_provider.dart';

class OwnerApp extends ConsumerWidget {
  const OwnerApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final router = ref.watch(appRouterProvider);
    final theme = ref.watch(themeDataProvider);
    ref.listen<AuthState>(authRepositoryProvider, (previous, next) {
      final companyId = next.companyId;
      if (companyId != null && companyId != previous?.companyId) {
        ref.read(companyConfigProvider.notifier).load(companyId);
      }
    });
    ref.listen<AsyncValue<CompanyConfig?>>(companyConfigProvider, (previous, next) {
      next.whenData((config) {
        if (config != null) {
          ref.read(appThemeProvider.notifier).setThemeByKey(config.themeKey);
        }
      });
    });

    return MaterialApp.router(
      title: 'FULLPOS Owner',
      debugShowCheckedModeBanner: false,
      theme: theme.copyWith(
        textTheme: GoogleFonts.poppinsTextTheme(theme.textTheme),
      ),
      routerConfig: router,
    );
  }
}

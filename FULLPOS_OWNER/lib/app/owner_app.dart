import 'dart:async';

import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../core/providers/theme_provider.dart';
import '../core/config/app_router.dart';
import '../features/auth/data/auth_repository.dart';

class OwnerApp extends ConsumerStatefulWidget {
  const OwnerApp({super.key});

  @override
  ConsumerState<OwnerApp> createState() => _OwnerAppState();
}

class _OwnerAppState extends ConsumerState<OwnerApp> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      unawaited(ref.read(authRepositoryProvider.notifier).me());
    });
  }

  @override
  Widget build(BuildContext context) {
    final router = ref.watch(appRouterProvider);
    final theme = ref.watch(themeDataProvider);
    final darkTheme = ref.watch(darkThemeDataProvider);
    final themeMode = ref.watch(themeModeProvider);

    return MaterialApp.router(
      title: 'FULLPOS Owner',
      debugShowCheckedModeBanner: false,
      theme: theme.copyWith(
        textTheme: GoogleFonts.poppinsTextTheme(theme.textTheme),
      ),
      darkTheme: darkTheme.copyWith(
        textTheme: GoogleFonts.poppinsTextTheme(darkTheme.textTheme),
      ),
      themeMode: themeMode,
      routerConfig: router,
    );
  }
}

import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'app/app.dart';
import 'core/debug/render_diagnostics.dart';
import 'core/db/db_init.dart';
import 'core/db_hardening/db_hardening.dart';
import 'core/logging/app_logger.dart';
import 'core/window/window_service.dart';
import 'features/settings/data/business_settings_model.dart';
import 'features/settings/data/business_settings_repository.dart';
import 'features/settings/providers/business_settings_provider.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  final diagnostics = RenderDiagnostics.instance;
  await diagnostics.ensureInitialized();
  diagnostics.installGlobalErrorHandlers();

  try {
    await AppLogger.instance.init();
  } catch (_) {
    // Si falla el logger, no detenemos el arranque.
  }

  if (Platform.isWindows || Platform.isLinux || Platform.isMacOS) {
    await WindowService.init();
    WindowService.scheduleInitialLayoutFix();
    WindowService.scheduleShowAfterFirstFrame();
  }

  DbInit.ensureInitialized();
  // FULLPOS DB HARDENING: validar la base antes de iniciar la UI.
  await DbHardening.instance.preflight();

  final businessRepo = BusinessSettingsRepository();
  final initialSettings = BusinessSettings.defaultSettings;

  diagnostics.markRunAppStart();
  runApp(
    ProviderScope(
      overrides: [
        businessRepositoryProvider.overrideWithValue(businessRepo),
        businessSettingsProvider.overrideWith(
          (ref) => BusinessSettingsNotifier(
            businessRepo,
            initial: initialSettings,
          ),
        ),
      ],
      child: const FullPosApp(),
    ),
  );
}

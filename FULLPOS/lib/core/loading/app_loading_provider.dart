import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../debug/render_diagnostics.dart';

/// Controlador global de loading.
/// Usa un contador para soportar cargas anidadas sin apagarse antes de tiempo.
class AppLoadingController extends StateNotifier<int> {
  AppLoadingController() : super(0);

  void show() {
    state = state + 1;
    unawaited(
      RenderDiagnostics.instance.logOverlay(
        'show',
        data: {'depth': state},
      ),
    );
  }

  void hide() {
    final next = state - 1;
    state = next < 0 ? 0 : next;
    unawaited(
      RenderDiagnostics.instance.logOverlay(
        'hide',
        data: {'depth': state},
      ),
    );
  }

  Future<T> wrap<T>(Future<T> Function() action) async {
    show();
    try {
      return await action();
    } finally {
      hide();
    }
  }
}

final appLoadingProvider = StateNotifierProvider<AppLoadingController, int>((
  ref,
) {
  return AppLoadingController();
});

final appIsLoadingProvider = Provider<bool>((ref) {
  return ref.watch(appLoadingProvider) > 0;
});

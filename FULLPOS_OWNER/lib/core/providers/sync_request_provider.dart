import 'package:flutter_riverpod/flutter_riverpod.dart';

enum SyncRequestScope { currentScreen, fullApp }

class SyncRequest {
  const SyncRequest({required this.revision, required this.scope, this.route});

  final int revision;
  final SyncRequestScope scope;
  final String? route;

  static const idle = SyncRequest(
    revision: 0,
    scope: SyncRequestScope.currentScreen,
  );

  bool appliesTo(String routePrefix) {
    if (revision == 0) return false;
    if (scope == SyncRequestScope.fullApp) return true;

    final target = route?.trim();
    if (target == null || target.isEmpty) return false;

    return target == routePrefix ||
        target.startsWith('$routePrefix/') ||
        routePrefix.startsWith('$target/');
  }
}

class SyncRequestNotifier extends StateNotifier<SyncRequest> {
  SyncRequestNotifier() : super(SyncRequest.idle);

  void syncCurrentScreen(String route) {
    state = SyncRequest(
      revision: state.revision + 1,
      scope: SyncRequestScope.currentScreen,
      route: route,
    );
  }

  void syncFullApp() {
    state = SyncRequest(
      revision: state.revision + 1,
      scope: SyncRequestScope.fullApp,
    );
  }
}

final syncRequestProvider =
    StateNotifierProvider<SyncRequestNotifier, SyncRequest>((ref) {
      return SyncRequestNotifier();
    });

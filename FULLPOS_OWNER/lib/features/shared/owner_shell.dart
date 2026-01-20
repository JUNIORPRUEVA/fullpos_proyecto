import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import '../../core/widgets/app_shell_scaffold.dart';
import '../auth/data/auth_repository.dart';
import '../cash/presentation/cash_closings_page.dart';
import '../products/presentation/products_page.dart';
import '../reports/presentation/dashboard_page.dart';
import '../settings/providers/company_config_provider.dart';

class OwnerShell extends ConsumerStatefulWidget {
  const OwnerShell({super.key, required this.child});

  final Widget child;

  @override
  ConsumerState<OwnerShell> createState() => _OwnerShellState();
}

class _OwnerShellState extends ConsumerState<OwnerShell> {
  static const _tabRoutes = ['/products', '/cash/closings', '/dashboard'];
  final _tabs = [
    const ProductsPage(key: PageStorageKey('tab_catalog')),
    const CashClosingsPage(key: PageStorageKey('tab_cortes')),
    const DashboardPage(key: PageStorageKey('tab_reportes')),
  ];
  int _lastMainIndex = 0;

  int _resolveRouteIndex(String location) {
    for (var i = 0; i < _tabRoutes.length; i++) {
      final route = _tabRoutes[i];
      if (location == route || location.startsWith('$route/')) return i;
    }
    return -1;
  }

  @override
  Widget build(BuildContext context) {
    final authState = ref.watch(authRepositoryProvider);
    final repo = ref.read(authRepositoryProvider.notifier);
    final config = ref.watch(companyConfigProvider).valueOrNull;
    final currentRoute = GoRouterState.of(context).matchedLocation;
    final routeIndex = _resolveRouteIndex(currentRoute);
    final showTabs = routeIndex >= 0;
    if (showTabs) {
      _lastMainIndex = routeIndex;
    }

    final body = showTabs
        ? IndexedStack(index: routeIndex, children: _tabs)
        : widget.child;

    final company = config?.companyName ?? authState.companyName ?? 'FULLPOS';
    final subtitle = config?.slogan ?? 'Control total';

    return AppShellScaffold(
      title: '$company · Control total',
      companyName: company,
      companySubtitle: subtitle,
      username: null,
      version: authState.ownerVersion,
      body: body,
      currentIndex: _lastMainIndex,
      onTabSelected: (index) {
        if (index >= 0 && index < _tabRoutes.length) {
          context.go(_tabRoutes[index]);
        }
      },
      onLogout: () async {
        await repo.logout();
        if (context.mounted) context.go('/login');
      },
      onDrawerNavigate: (path) {
        context.go(path);
      },
    );
  }
}

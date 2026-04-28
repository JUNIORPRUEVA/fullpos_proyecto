import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import '../../features/auth/data/auth_repository.dart';
import '../../features/auth/presentation/login_page.dart';
import '../../features/inventory/presentation/inventory_page.dart';
import '../../features/products/presentation/products_page.dart';
import '../../features/reports/presentation/dashboard_page.dart';
import '../../features/reports/presentation/sale_detail_page.dart';
import '../../features/reports/presentation/sales_list_page.dart';
import '../../features/reports/presentation/sales_by_day_page.dart';
import '../../features/settings/presentation/owner_settings_page.dart';
import '../../features/shared/owner_shell.dart';

final appRouterProvider = Provider<GoRouter>((ref) {
  final hasSession = ref.watch(
    authRepositoryProvider.select(
      (authState) =>
          (authState.accessToken?.trim().isNotEmpty ?? false) ||
          (authState.refreshToken?.trim().isNotEmpty ?? false),
    ),
  );

  return GoRouter(
    initialLocation: '/dashboard',
    redirect: (context, state) {
      final isLoginRoute = state.matchedLocation == '/login';
      if (!hasSession && !isLoginRoute) {
        return '/login';
      }
      if (hasSession && isLoginRoute) {
        return '/dashboard';
      }
      return null;
    },
    routes: [
      GoRoute(path: '/', redirect: (context, state) => '/dashboard'),
      GoRoute(path: '/login', builder: (context, state) => const LoginPage()),
      ShellRoute(
        builder: (context, state, child) => OwnerShell(child: child),
        routes: [
          GoRoute(path: '/reports', redirect: (context, state) => '/dashboard'),
          GoRoute(path: '/profile', redirect: (context, state) => '/dashboard'),
          GoRoute(
            path: '/settings',
            builder: (context, state) => const OwnerSettingsPage(),
          ),
          GoRoute(path: '/cash', redirect: (context, state) => '/dashboard'),
          GoRoute(
            path: '/cash/closing/:id',
            redirect: (context, state) => '/dashboard',
          ),
          GoRoute(
            path: '/dashboard',
            builder: (context, state) => const DashboardPage(),
          ),
          GoRoute(
            path: '/products',
            builder: (context, state) => const ProductsPage(),
          ),
          GoRoute(
            path: '/sales/list',
            builder: (context, state) {
              DateTime? from;
              DateTime? to;
              try {
                final qp = state.uri.queryParameters;
                final fromStr = qp['from'];
                final toStr = qp['to'];
                if (fromStr != null) from = DateTime.tryParse(fromStr);
                if (toStr != null) to = DateTime.tryParse(toStr);
              } catch (_) {
                // Ignore parse errors.
              }

              return SalesListPage(initialFrom: from, initialTo: to);
            },
          ),
          GoRoute(
            path: '/sales/detail/:id',
            builder: (context, state) {
              final id = int.tryParse(state.pathParameters['id'] ?? '');
              return SaleDetailPage(id: id ?? 0);
            },
          ),
          GoRoute(
            path: '/sales/by-day',
            builder: (context, state) {
              DateTime? from;
              DateTime? to;
              try {
                final qp = state.uri.queryParameters;
                final fromStr = qp['from'];
                final toStr = qp['to'];
                if (fromStr != null) from = DateTime.tryParse(fromStr);
                if (toStr != null) to = DateTime.tryParse(toStr);
              } catch (_) {
                // Ignore parse errors.
              }

              return SalesByDayPage(initialFrom: from, initialTo: to);
            },
          ),
          GoRoute(
            path: '/inventory',
            builder: (context, state) => const InventoryPage(),
          ),
        ],
      ),
    ],
  );
});

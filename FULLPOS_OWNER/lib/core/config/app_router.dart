import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import '../../features/auth/presentation/login_page.dart';
import '../../features/reports/presentation/dashboard_page.dart';
import '../../features/reports/presentation/sales_list_page.dart';
import '../../features/reports/presentation/sales_by_day_page.dart';
import '../../features/cash/presentation/cash_closings_page.dart';
import '../../features/cash/presentation/cash_closing_detail_page.dart';
import '../../features/products/presentation/products_page.dart';
import '../../features/overrides/presentation/override_requests_page.dart';
import '../../features/settings/presentation/owner_settings_page.dart';
import '../../features/shared/owner_shell.dart';
import '../storage/secure_storage.dart';

final appRouterProvider = Provider<GoRouter>((ref) {
  final storage = ref.read(secureStorageProvider);

  return GoRouter(
    initialLocation: '/login',
    redirect: (context, state) async {
      final token = await storage.readToken();
      final isPublicRoute = state.matchedLocation == '/login' || state.matchedLocation == '/settings';
      if (token == null && !isPublicRoute) return '/login';
      if (token != null && state.matchedLocation == '/login') return '/dashboard';
      return null;
    },
    routes: [
      GoRoute(
        path: '/login',
        builder: (context, state) => const LoginPage(),
      ),
      GoRoute(
        path: '/settings',
        builder: (context, state) => const OwnerSettingsPage(),
      ),
      GoRoute(
        path: '/',
        redirect: (_, __) => '/dashboard',
      ),
      ShellRoute(
        builder: (context, state, child) => OwnerShell(child: child),
        routes: [
          GoRoute(
            path: '/dashboard',
            builder: (context, state) => const DashboardPage(),
          ),
          GoRoute(
            path: '/products',
            builder: (context, state) => const ProductsPage(),
          ),
          GoRoute(
            path: '/overrides',
            builder: (context, state) => const OverrideRequestsPage(),
          ),
          GoRoute(
            path: '/sales/list',
            builder: (context, state) => const SalesListPage(),
          ),
          GoRoute(
            path: '/sales/by-day',
            builder: (context, state) => const SalesByDayPage(),
          ),
          GoRoute(
            path: '/cash/closings',
            builder: (context, state) => const CashClosingsPage(),
          ),
          GoRoute(
            path: '/cash/closing/:id',
            builder: (context, state) {
              final id = int.tryParse(state.pathParameters['id'] ?? '');
              return CashClosingDetailPage(id: id ?? 0);
            },
          ),
        ],
      ),
    ],
  );
});

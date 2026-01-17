import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../core/bootstrap/app_bootstrap_controller.dart';
import '../core/errors/error_handler.dart';
import '../core/layout/app_shell.dart';
import '../features/account/ui/account_page.dart';
import '../features/auth/ui/login_page.dart';
import '../features/cash/ui/cash_box_page.dart';
import '../features/clients/ui/clients_page.dart';
import '../features/loans/ui/loans_page.dart';
import '../features/products/ui/add_stock_page.dart';
import '../features/products/ui/products_page.dart';
import '../features/purchases/ui/purchase_order_create_auto_page.dart';
import '../features/purchases/ui/purchase_order_create_manual_page.dart';
import '../features/purchases/ui/purchase_order_receive_page.dart';
import '../features/purchases/ui/purchase_orders_list_page.dart';
import '../features/reports/ui/reports_page.dart';
import '../features/sales/ui/credits_page.dart';
import '../features/sales/ui/quotes_page.dart';
import '../features/sales/ui/returns_list_page.dart';
import '../features/sales/ui/sales_list_page.dart';
import '../features/sales/ui/sales_page.dart';
import '../features/settings/data/user_model.dart';
import '../features/settings/ui/printer_settings_page.dart';
import '../features/settings/ui/logs_page.dart';
import '../features/settings/ui/backup_settings_page.dart';
import '../features/settings/ui/settings_page.dart';
import '../features/tools/ui/ncf_page.dart';
import '../features/tools/ui/tools_page.dart';

final appRouterProvider = Provider<GoRouter>((ref) {
  final bootstrap = ref.read(appBootstrapProvider);

  return GoRouter(
    navigatorKey: ErrorHandler.navigatorKey,
    // Nota: La pantalla de arranque se maneja fuera del router (AppEntry).
    // Mantener una ruta inicial estable evita “rebotes” visuales.
    initialLocation: '/sales',
    refreshListenable: bootstrap,
    redirect: (context, state) {
      final path = state.uri.path;
      final isOnLogin = path == '/login';

      final boot = bootstrap.snapshot;
      // Mientras el bootstrap corre, no redirigir rutas: AppEntry muestra Splash/Error.
      if (boot.status != BootStatus.ready) return null;

      final isLoggedIn = boot.isLoggedIn;
      if (!isLoggedIn) {
        return isOnLogin ? null : '/login';
      }

      final isAdmin = boot.isAdmin;
      final permissions = boot.permissions;
      final fallback = _fallbackLocation(isAdmin, permissions);

      if (isOnLogin) return fallback;
      if (isAdmin) return null;

      // Verificar permisos por ruta (sync, sin I/O).
      if (path == '/sales' && !permissions.canSell) return fallback;
      if (path == '/sales-list' && !permissions.canViewSalesHistory) {
        return fallback;
      }
      if ((path == '/quotes' || path == '/quotes-list') &&
          !permissions.canViewQuotes) {
        return fallback;
      }
      if ((path == '/credits' || path == '/credits-list') &&
          !permissions.canViewCredits) {
        return fallback;
      }
      if (path == '/products' && !permissions.canViewProducts) return fallback;
      if (path.startsWith('/products/add-stock') &&
          !permissions.canAdjustStock) {
        return fallback;
      }
      if (path == '/clients' && !permissions.canViewClients) return fallback;
      if (path == '/loans' && !permissions.canViewLoans) return fallback;
      if (path == '/reports' && !permissions.canViewReports) return fallback;
      if (path == '/tools' && !permissions.canAccessTools) return fallback;
      if (path == '/ncf' && !permissions.canAccessTools) return fallback;
      if (path == '/settings' && !permissions.canAccessSettings) {
        return fallback;
      }
      if (path == '/settings/printer' && !permissions.canAccessSettings) {
        return fallback;
      }
      if (path == '/cash' &&
          !permissions.canOpenCash &&
          !permissions.canCloseCash) {
        return fallback;
      }
      if ((path == '/returns' || path == '/returns-list') &&
          !permissions.canProcessReturns) {
        return fallback;
      }

      // Compras / Órdenes de compra: reusa permiso existente de inventario.
      if (path.startsWith('/purchases') && !permissions.canAdjustStock) {
        return fallback;
      }

      return null;
    },
    routes: [
      GoRoute(path: '/login', builder: (context, state) => const LoginPage()),
      ShellRoute(
        builder: (context, state, child) => AppShell(child: child),
        routes: [
          GoRoute(path: '/sales', builder: (context, state) => const SalesPage()),
          GoRoute(
            path: '/products',
            builder: (context, state) => const ProductsPage(),
          ),
          GoRoute(
            path: '/products/add-stock/:productId',
            builder: (context, state) {
              final productId = int.parse(
                state.pathParameters['productId'] ?? '0',
              );
              return AddStockPage(productId: productId);
            },
          ),
          GoRoute(
            path: '/clients',
            builder: (context, state) => const ClientsPage(),
          ),
          GoRoute(path: '/loans', builder: (context, state) => const LoansPage()),
          GoRoute(
            path: '/reports',
            builder: (context, state) => const ReportsPage(),
          ),
          GoRoute(path: '/tools', builder: (context, state) => const ToolsPage()),
          GoRoute(path: '/ncf', builder: (context, state) => const NcfPage()),
          GoRoute(
            path: '/settings',
            builder: (context, state) => const SettingsPage(),
          ),
          GoRoute(
            path: '/settings/printer',
            builder: (context, state) => const PrinterSettingsPage(),
          ),
          GoRoute(
            path: '/settings/logs',
            builder: (context, state) => const LogsPage(),
          ),
          GoRoute(
            path: '/settings/backup',
            builder: (context, state) => const BackupSettingsPage(),
          ),
          GoRoute(
            path: '/account',
            builder: (context, state) => const AccountPage(),
          ),

          // Rutas de ventas
          GoRoute(
            path: '/sales-list',
            builder: (context, state) => const SalesListPage(),
          ),
          GoRoute(path: '/quotes', builder: (context, state) => const QuotesPage()),
          GoRoute(
            path: '/quotes-list',
            builder: (context, state) => const QuotesPage(),
          ),
          GoRoute(
            path: '/returns',
            builder: (context, state) => const ReturnsListPage(),
          ),
          GoRoute(
            path: '/returns-list',
            builder: (context, state) => const ReturnsListPage(),
          ),
          GoRoute(
            path: '/credits',
            builder: (context, state) => const CreditsPage(),
          ),
          GoRoute(
            path: '/credits-list',
            builder: (context, state) => const CreditsPage(),
          ),
          GoRoute(path: '/cash', builder: (context, state) => const CashBoxPage()),

          // Compras / Órdenes de compra
          GoRoute(
            path: '/purchases',
            builder: (context, state) => const PurchaseOrdersListPage(),
          ),
          GoRoute(
            path: '/purchases/new',
            builder: (context, state) => const PurchaseOrderCreateManualPage(),
          ),
          GoRoute(
            path: '/purchases/edit/:id',
            builder: (context, state) {
              final id = int.tryParse(state.pathParameters['id'] ?? '');
              return PurchaseOrderCreateManualPage(orderId: id);
            },
          ),
          GoRoute(
            path: '/purchases/auto',
            builder: (context, state) => const PurchaseOrderCreateAutoPage(),
          ),
          GoRoute(
            path: '/purchases/receive/:id',
            builder: (context, state) {
              final id = int.tryParse(state.pathParameters['id'] ?? '');
              return PurchaseOrderReceivePage(orderId: id ?? 0);
            },
          ),
        ],
      ),
    ],
  );
});

String _fallbackLocation(bool isAdmin, UserPermissions permissions) {
  if (isAdmin) return '/sales';
  if (permissions.canSell) return '/sales';
  if (permissions.canViewProducts) return '/products';
  if (permissions.canViewClients) return '/clients';
  if (permissions.canViewLoans) return '/loans';
  if (permissions.canViewReports) return '/reports';
  if (permissions.canAdjustStock) return '/purchases';
  if (permissions.canAccessTools) return '/tools';
  if (permissions.canAccessSettings) return '/settings';
  return '/account';
}

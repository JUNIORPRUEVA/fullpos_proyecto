import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import '../../core/realtime/company_realtime_service.dart';
import '../../core/providers/sync_request_provider.dart';
import '../../core/widgets/app_shell_scaffold.dart';
import '../auth/data/auth_repository.dart';
import '../auth/data/auth_state.dart';
import '../inventory/presentation/inventory_page.dart';
import '../products/data/product_realtime_service.dart';
import '../products/presentation/products_page.dart';
import '../reports/data/sale_realtime_service.dart';
import '../reports/presentation/dashboard_page.dart';

class OwnerShell extends ConsumerStatefulWidget {
  const OwnerShell({super.key, required this.child});

  final Widget child;

  @override
  ConsumerState<OwnerShell> createState() => _OwnerShellState();
}

class _OwnerShellState extends ConsumerState<OwnerShell> {
  static const _mainRoutes = ['/dashboard', '/products', '/inventory'];

  StreamSubscription<CompanyRealtimeMessage>? _companyRealtimeSubscription;
  Timer? _realtimeRefreshDebounce;

  late final List<Widget> _pages = [
    const DashboardPage(key: PageStorageKey('tab_reportes')),
    const ProductsPage(key: PageStorageKey('tab_catalog')),
    const InventoryPage(key: PageStorageKey('tab_inventory')),
  ];

  Future<void> _syncRealtimeConnections() async {
    final authState = ref.read(authRepositoryProvider);
    final companyRealtime = ref.read(companyRealtimeServiceProvider);
    final productRealtime = ref.read(productRealtimeServiceProvider);
    final saleRealtime = ref.read(saleRealtimeServiceProvider);

    final hasSession =
        (authState.accessToken?.trim().isNotEmpty ?? false) ||
        (authState.refreshToken?.trim().isNotEmpty ?? false);

    if (!hasSession) {
      companyRealtime.disconnect();
      productRealtime.disconnect();
      saleRealtime.disconnect();
      return;
    }

    await Future.wait<void>([
      companyRealtime.connect(authState),
      productRealtime.connect(authState),
      saleRealtime.connect(authState),
    ]);
  }

  void _bindCompanyRealtime() {
    _companyRealtimeSubscription?.cancel();
    _companyRealtimeSubscription = ref
        .read(companyRealtimeServiceProvider)
        .stream
        .listen((_) {
          _realtimeRefreshDebounce?.cancel();
          _realtimeRefreshDebounce = Timer(
            const Duration(milliseconds: 250),
            () => ref.read(syncRequestProvider.notifier).syncFullApp(),
          );
        });
  }

  @override
  void initState() {
    super.initState();
    _bindCompanyRealtime();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      unawaited(_syncRealtimeConnections());
    });
  }

  @override
  void dispose() {
    _realtimeRefreshDebounce?.cancel();
    _companyRealtimeSubscription?.cancel();
    super.dispose();
  }

  String _titleForRoute(String route, {required int routeIndex}) {
    if (routeIndex == 0) return 'Reporte';
    if (routeIndex == 1) return 'Productos';
    if (routeIndex == 2) return 'Inventario';

    if (route.startsWith('/settings')) return 'Configuración';
    if (route.startsWith('/sales/by-day')) return 'Ventas diarias';
    if (route.startsWith('/sales/list')) return 'Registro de ventas';
    if (route.startsWith('/sales/detail')) return 'Ticket de venta';
    if (route.startsWith('/inventory')) return 'Inventario';

    return '';
  }

  bool _isSecondaryRoute(String route, {required int routeIndex}) {
    if (routeIndex >= 0) return false;
    return route != '/login';
  }

  String _parentRouteFor(String route) {
    if (route.startsWith('/sales/')) return '/dashboard';
    if (route.startsWith('/products/')) return '/products';
    if (route.startsWith('/inventory/')) return '/inventory';
    return '/dashboard';
  }

  Widget? _buildBackButton(
    BuildContext context, {
    required String currentRoute,
    required int routeIndex,
  }) {
    if (!_isSecondaryRoute(currentRoute, routeIndex: routeIndex)) {
      return null;
    }

    final targetRoute = _parentRouteFor(currentRoute);
    return IconButton(
      tooltip: 'Regresar',
      icon: const Icon(Icons.arrow_back_rounded),
      onPressed: () {
        context.go(targetRoute);
      },
    );
  }

  Future<void> _handleSyncAction(
    BuildContext context, {
    required _SyncMenuAction action,
    required String currentRoute,
  }) async {
    if (action == _SyncMenuAction.currentScreen) {
      ref.read(syncRequestProvider.notifier).syncCurrentScreen(currentRoute);
    } else {
      ref.read(syncRequestProvider.notifier).syncFullApp();
    }

    await _syncRealtimeConnections();
    if (!context.mounted) return;

    final message = action == _SyncMenuAction.currentScreen
        ? 'Pantalla actual sincronizada.'
        : 'Se lanzó una sincronización global.';
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), behavior: SnackBarBehavior.floating),
    );
  }

  List<Widget> _buildAppBarActions(
    BuildContext context,
    AuthState authState, {
    required String currentRoute,
  }) {
    return [
      PopupMenuButton<_SyncMenuAction>(
        tooltip: 'Sincronizar',
        offset: const Offset(0, 10),
        position: PopupMenuPosition.under,
        icon: const Icon(Icons.sync_rounded),
        onSelected: (value) => _handleSyncAction(
          context,
          action: value,
          currentRoute: currentRoute,
        ),
        itemBuilder: (context) => const [
          PopupMenuItem<_SyncMenuAction>(
            value: _SyncMenuAction.currentScreen,
            child: Row(
              children: [
                Icon(Icons.sync_outlined, size: 18),
                SizedBox(width: 10),
                Text('Solo esta pantalla'),
              ],
            ),
          ),
          PopupMenuItem<_SyncMenuAction>(
            value: _SyncMenuAction.fullApp,
            child: Row(
              children: [
                Icon(Icons.sync_alt_rounded, size: 18),
                SizedBox(width: 10),
                Text('Toda la app'),
              ],
            ),
          ),
        ],
      ),
      Padding(
        padding: const EdgeInsets.only(right: 6),
        child: PopupMenuButton<_SessionMenuAction>(
          tooltip: 'Sesión activa',
          offset: const Offset(0, 10),
          position: PopupMenuPosition.under,
          surfaceTintColor: Colors.transparent,
          color: Colors.transparent,
          elevation: 0,
          padding: EdgeInsets.zero,
          icon: const Icon(Icons.account_circle_outlined),
          onSelected: (value) async {
            if (value != _SessionMenuAction.logout) return;

            await ref.read(authRepositoryProvider.notifier).logout();
            if (!context.mounted) return;
            context.go('/login');
          },
          itemBuilder: (menuContext) => [
            PopupMenuItem<_SessionMenuAction>(
              enabled: false,
              padding: EdgeInsets.zero,
              child: SizedBox(
                width: 312,
                child: _SessionInfoMenu(authState: authState),
              ),
            ),
            const PopupMenuDivider(height: 10),
            const PopupMenuItem<_SessionMenuAction>(
              value: _SessionMenuAction.logout,
              child: Row(
                children: [
                  Icon(Icons.logout_rounded, size: 18),
                  SizedBox(width: 10),
                  Text('Cerrar sesión'),
                ],
              ),
            ),
          ],
        ),
      ),
    ];
  }

  PreferredSizeWidget _buildAppBar(
    BuildContext context, {
    required String currentRoute,
    required int routeIndex,
    required AuthState authState,
  }) {
    final title = _titleForRoute(currentRoute, routeIndex: routeIndex);
    final theme = Theme.of(context);
    final leading = _buildBackButton(
      context,
      currentRoute: currentRoute,
      routeIndex: routeIndex,
    );

    if (routeIndex == 0) {
      return AppBar(
        toolbarHeight: 58,
        elevation: 0,
        scrolledUnderElevation: 1,
        surfaceTintColor: Colors.transparent,
        backgroundColor: theme.colorScheme.surface,
        centerTitle: false,
        leading: leading,
        titleSpacing: 12,
        actions: _buildAppBarActions(
          context,
          authState,
          currentRoute: currentRoute,
        ),
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Text(
              title,
              style: theme.textTheme.titleLarge?.copyWith(
                fontWeight: FontWeight.w800,
                letterSpacing: -0.2,
                height: 1.0,
              ),
            ),
            const SizedBox(height: 2),
            Text(
              'Ventas y rendimiento',
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      );
    }

    if (routeIndex == 1) {
      return AppBar(
        toolbarHeight: 52,
        elevation: 0,
        scrolledUnderElevation: 1,
        surfaceTintColor: Colors.transparent,
        backgroundColor: theme.colorScheme.surface,
        centerTitle: false,
        leading: leading,
        titleSpacing: 12,
        title: Text(
          title,
          style: theme.textTheme.titleLarge?.copyWith(
            fontWeight: FontWeight.w800,
            letterSpacing: -0.2,
          ),
        ),
        actions: _buildAppBarActions(
          context,
          authState,
          currentRoute: currentRoute,
        ),
      );
    }

    return AppBar(
      toolbarHeight: 52,
      elevation: 0,
      scrolledUnderElevation: 1,
      surfaceTintColor: Colors.transparent,
      backgroundColor: theme.colorScheme.surface,
      leading: leading,
      title: Text(title, style: const TextStyle(fontWeight: FontWeight.w700)),
      centerTitle: false,
      actions: _buildAppBarActions(
        context,
        authState,
        currentRoute: currentRoute,
      ),
    );
  }

  int _resolveRouteIndex(String location) {
    for (var i = 0; i < _mainRoutes.length; i++) {
      final route = _mainRoutes[i];
      if (location == route || location.startsWith('$route/')) return i;
    }
    return -1;
  }

  @override
  Widget build(BuildContext context) {
    ref.listen<AuthState>(authRepositoryProvider, (previous, next) {
      final sessionChanged =
          previous?.accessToken != next.accessToken ||
          previous?.refreshToken != next.refreshToken;
      if (sessionChanged) {
        unawaited(_syncRealtimeConnections());
      }
    });

    final authState = ref.watch(authRepositoryProvider);
    final currentRoute = GoRouterState.of(context).matchedLocation;
    final routeIndex = _resolveRouteIndex(currentRoute);
    final showMainPages = routeIndex >= 0;

    final body = showMainPages
        ? IndexedStack(index: routeIndex, children: _pages)
        : widget.child;

    return AppShellScaffold(
      appBar: _buildAppBar(
        context,
        currentRoute: currentRoute,
        routeIndex: routeIndex,
        authState: authState,
      ),
      title: _titleForRoute(currentRoute, routeIndex: routeIndex),
      companyName: authState.companyName?.trim().isNotEmpty == true
          ? authState.companyName!.trim()
          : 'FULLPOS',
      companySubtitle: _buildCompanySubtitle(authState),
      username: authState.displayName ?? authState.username,
      version: authState.ownerVersion,
      body: body,
      currentRoute: currentRoute,
      onDrawerNavigate: (path) {
        context.go(path);
      },
      onLogout: () async {
        await ref.read(authRepositoryProvider.notifier).logout();
        if (!context.mounted) return;
        context.go('/login');
      },
    );
  }

  String? _buildCompanySubtitle(AuthState authState) {
    final details = <String>[];
    final companyRnc = authState.companyRnc?.trim();
    final companyId = authState.companyId?.toString();

    if (companyRnc != null && companyRnc.isNotEmpty) {
      details.add('RNC $companyRnc');
    }
    if (companyId != null && companyId.isNotEmpty) {
      details.add('ID $companyId');
    }

    if (details.isEmpty) return null;
    return details.join(' · ');
  }
}

class _SessionInfoRow extends StatelessWidget {
  const _SessionInfoRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 82,
            child: Text(
              label,
              style: theme.textTheme.labelMedium?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
                fontWeight: FontWeight.w700,
                letterSpacing: 0.1,
              ),
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              value,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.bodyMedium?.copyWith(
                fontWeight: FontWeight.w700,
                height: 1.15,
                letterSpacing: -0.1,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _SessionDetailsPanel extends StatelessWidget {
  const _SessionDetailsPanel({required this.children});

  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(
          color: theme.colorScheme.outlineVariant.withValues(alpha: 0.85),
        ),
      ),
      child: Column(children: children),
    );
  }
}

class _SessionInfoMenu extends StatelessWidget {
  const _SessionInfoMenu({required this.authState});

  final AuthState authState;

  String get _displayName {
    final displayName = authState.displayName?.trim();
    if (displayName != null && displayName.isNotEmpty) return displayName;

    final username = authState.username?.trim();
    if (username != null && username.isNotEmpty) return username;

    return 'Usuario activo';
  }

  String get _initials {
    final source = _displayName.trim();
    if (source.isEmpty) return 'U';

    final parts = source
        .split(RegExp(r'\s+'))
        .where((part) => part.isNotEmpty)
        .take(2)
        .toList();
    if (parts.isEmpty) return 'U';

    return parts.map((part) => part.characters.first.toUpperCase()).join();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final username = authState.username?.trim();
    final email = authState.email?.trim();
    final companyName = authState.companyName?.trim();
    final companyRnc = authState.companyRnc?.trim();
    final companyId = authState.companyId?.toString();
    final version = authState.ownerVersion?.trim();
    final detailRows = <Widget>[
      const _SessionInfoRow(label: 'Rol', value: 'Admin'),
      if (companyId != null && companyId.isNotEmpty)
        _buildSessionDetailRow(
          label: 'ID empresa',
          value: companyId,
        ),
      if (username != null && username.isNotEmpty)
        _buildSessionDetailRow(
          label: 'Usuario',
          value: username,
        ),
      if (version != null && version.isNotEmpty)
        _buildSessionDetailRow(
          label: 'Versión',
          value: version,
        ),
      if (email != null && email.isNotEmpty)
        _buildSessionDetailRow(
          label: 'Correo',
          value: email,
        ),
      if (companyName != null && companyName.isNotEmpty)
        _buildSessionDetailRow(
          label: 'Empresa',
          value: companyName,
        ),
      if (companyRnc != null && companyRnc.isNotEmpty)
        _buildSessionDetailRow(
          label: 'RNC',
          value: companyRnc,
          isLast: true,
        ),
    ];

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: theme.colorScheme.outlineVariant),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withAlpha((0.08 * 255).round()),
            blurRadius: 16,
            offset: const Offset(0, 6),
          ),
        ],
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            'OWNER PANEL',
            style: theme.textTheme.labelMedium?.copyWith(
              color: theme.colorScheme.primary.withValues(alpha: 0.82),
              fontWeight: FontWeight.w800,
              letterSpacing: 0.9,
            ),
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Container(
                width: 50,
                height: 50,
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [
                      theme.colorScheme.primary.withAlpha((0.16 * 255).round()),
                      theme.colorScheme.primary.withAlpha((0.08 * 255).round()),
                    ],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  ),
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(
                    color: theme.colorScheme.primary.withAlpha(
                      (0.16 * 255).round(),
                    ),
                  ),
                ),
                alignment: Alignment.center,
                child: Text(
                  _initials,
                  style: theme.textTheme.titleMedium?.copyWith(
                    color: theme.colorScheme.primary,
                    fontWeight: FontWeight.w900,
                    letterSpacing: 0.3,
                  ),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      _displayName,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: theme.textTheme.titleMedium?.copyWith(
                        fontWeight: FontWeight.w800,
                        letterSpacing: -0.35,
                      ),
                    ),
                    const SizedBox(height: 1),
                    Text(
                      'Sesión activa',
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                        fontWeight: FontWeight.w600,
                        height: 1.05,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              Container(
                width: 34,
                height: 3,
                decoration: BoxDecoration(
                  color: theme.colorScheme.primary.withValues(alpha: 0.85),
                  borderRadius: BorderRadius.circular(999),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Container(
                  height: 1,
                  decoration: BoxDecoration(
                    gradient: LinearGradient(
                      colors: [
                        theme.colorScheme.primary.withValues(alpha: 0.22),
                        theme.colorScheme.outlineVariant.withValues(alpha: 0.55),
                        Colors.transparent,
                      ],
                    ),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          _SessionDetailsPanel(
            children: detailRows,
          ),
        ],
      ),
    );
  }
}

Widget _buildSessionDetailRow({
  required String label,
  required String value,
  bool isLast = false,
}) {
  return Column(
    mainAxisSize: MainAxisSize.min,
    children: [
      _SessionInfoRow(label: label, value: value),
      if (!isLast) const Divider(height: 1),
    ],
  );
}

enum _SessionMenuAction { logout }

enum _SyncMenuAction { currentScreen, fullApp }

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/realtime/company_realtime_service.dart';
import '../../core/providers/sync_request_provider.dart';
import '../../core/theme/app_colors.dart';
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
  static const _mainNavItems = [
    _MainNavItem(
      route: '/dashboard',
      label: 'Reporte',
      icon: Icons.analytics_outlined,
    ),
    _MainNavItem(
      route: '/products',
      label: 'Categorias',
      icon: Icons.category_outlined,
    ),
    _MainNavItem(
      route: '/inventory',
      label: 'Inventario',
      icon: Icons.inventory_2_outlined,
    ),
  ];

  StreamSubscription<CompanyRealtimeMessage>? _companyRealtimeSubscription;
  Timer? _realtimeRefreshDebounce;
  bool _isSyncing = false;
  late final ProductsPageController _productsPageController =
      ProductsPageController();

  late final List<Widget> _pages = [
    const DashboardPage(key: PageStorageKey('tab_reportes')),
    ProductsPage(
      key: const PageStorageKey('tab_catalog'),
      controller: _productsPageController,
      showEmbeddedToolbar: false,
    ),
    const InventoryPage(key: PageStorageKey('tab_inventory')),
  ];

  static const _allCategoriesValue = '__all_categories__';

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
    _productsPageController.dispose();
    super.dispose();
  }

  String _titleForRoute(String route, {required int routeIndex}) {
    if (routeIndex == 0) return 'Reporte';
    if (routeIndex == 1) return 'Categorias';
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

  Future<void> _handleSyncAction(BuildContext context) async {
    if (_isSyncing) return;

    setState(() {
      _isSyncing = true;
    });

    try {
      ref.read(syncRequestProvider.notifier).syncFullApp();
      await _syncRealtimeConnections();
      if (!context.mounted) return;

      final messenger = ScaffoldMessenger.of(context);
      messenger.hideCurrentSnackBar();
      messenger.showSnackBar(
        const SnackBar(
          content: Text('App sincronizada'),
          behavior: SnackBarBehavior.floating,
          duration: Duration(milliseconds: 1200),
        ),
      );
    } finally {
      if (mounted) {
        setState(() {
          _isSyncing = false;
        });
      }
    }
  }

  String? _activeMainRoute(String currentRoute, {required int routeIndex}) {
    if (routeIndex >= 0) {
      return _mainRoutes[routeIndex];
    }
    if (currentRoute.startsWith('/sales/')) {
      return '/dashboard';
    }
    if (currentRoute.startsWith('/settings')) {
      return null;
    }
    return _mainRoutes.firstWhere(
      (route) => currentRoute == route || currentRoute.startsWith('$route/'),
      orElse: () => '/dashboard',
    );
  }

  Future<void> _handleSessionAction(
    BuildContext context, {
    required _SessionMenuAction action,
    required AuthState authState,
  }) async {
    switch (action) {
      case _SessionMenuAction.profile:
        await showGeneralDialog<void>(
          context: context,
          barrierLabel: 'Perfil',
          barrierDismissible: true,
          barrierColor: Colors.black.withValues(alpha: 0.14),
          transitionDuration: const Duration(milliseconds: 240),
          pageBuilder: (dialogContext, animation, secondaryAnimation) {
            return SafeArea(
              child: Padding(
                padding: const EdgeInsets.fromLTRB(12, 76, 12, 12),
                child: Align(
                  alignment: Alignment.topRight,
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 360),
                    child: _ProfileSheet(authState: authState),
                  ),
                ),
              ),
            );
          },
          transitionBuilder: (context, animation, secondaryAnimation, child) {
            final curved = CurvedAnimation(
              parent: animation,
              curve: Curves.easeOutCubic,
              reverseCurve: Curves.easeInCubic,
            );

            return FadeTransition(
              opacity: curved,
              child: SlideTransition(
                position: Tween<Offset>(
                  begin: const Offset(0.04, -0.05),
                  end: Offset.zero,
                ).animate(curved),
                child: ScaleTransition(
                  alignment: Alignment.topRight,
                  scale: Tween<double>(begin: 0.94, end: 1).animate(curved),
                  child: child,
                ),
              ),
            );
          },
        );
        return;
      case _SessionMenuAction.settings:
        context.go('/settings');
        return;
      case _SessionMenuAction.logout:
        await ref.read(authRepositoryProvider.notifier).logout();
        if (!context.mounted) return;
        context.go('/login');
        return;
    }
  }

  Future<void> _openCatalogSearchDialog(BuildContext context) async {
    final theme = Theme.of(context);

    await showGeneralDialog<void>(
      context: context,
      barrierLabel: 'Buscar producto',
      barrierDismissible: true,
      barrierColor: Colors.black.withValues(alpha: 0.18),
      transitionDuration: const Duration(milliseconds: 220),
      pageBuilder: (dialogContext, animation, secondaryAnimation) {
        return SafeArea(
          child: Align(
            alignment: Alignment.topCenter,
            child: Padding(
              padding: const EdgeInsets.fromLTRB(16, 82, 16, 16),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 520),
                child: Material(
                  color: Colors.transparent,
                  child: Container(
                    padding: const EdgeInsets.fromLTRB(16, 16, 16, 14),
                    decoration: BoxDecoration(
                      color: theme.colorScheme.surface,
                      borderRadius: BorderRadius.circular(24),
                      border: Border.all(
                        color: theme.colorScheme.outlineVariant,
                      ),
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withValues(alpha: 0.10),
                          blurRadius: 24,
                          offset: const Offset(0, 12),
                        ),
                      ],
                    ),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Buscar en catálogo',
                          style: theme.textTheme.titleMedium?.copyWith(
                            fontWeight: FontWeight.w800,
                            letterSpacing: -0.2,
                          ),
                        ),
                        const SizedBox(height: 12),
                        ValueListenableBuilder<TextEditingValue>(
                          valueListenable:
                              _productsPageController.searchController,
                          builder: (context, value, child) {
                            return TextField(
                              controller:
                                  _productsPageController.searchController,
                              autofocus: true,
                              textInputAction: TextInputAction.search,
                              onChanged:
                                  _productsPageController.applySearchChange,
                              onSubmitted: (_) {
                                _productsPageController.submitSearch();
                                Navigator.of(dialogContext).pop();
                              },
                              decoration: InputDecoration(
                                hintText: 'Buscar producto...',
                                prefixIcon: const Icon(Icons.search_rounded),
                                suffixIcon: value.text.isEmpty
                                    ? null
                                    : IconButton(
                                        tooltip: 'Limpiar búsqueda',
                                        icon: const Icon(Icons.close_rounded),
                                        onPressed:
                                            _productsPageController.clearSearch,
                                      ),
                              ),
                            );
                          },
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ),
          ),
        );
      },
      transitionBuilder: (context, animation, secondaryAnimation, child) {
        final curved = CurvedAnimation(
          parent: animation,
          curve: Curves.easeOutCubic,
          reverseCurve: Curves.easeInCubic,
        );

        return FadeTransition(
          opacity: curved,
          child: SlideTransition(
            position: Tween<Offset>(
              begin: const Offset(0, -0.04),
              end: Offset.zero,
            ).animate(curved),
            child: child,
          ),
        );
      },
    );
  }

  List<Widget> _buildCatalogAppBarActions(BuildContext context) {
    return [
      ListenableBuilder(
        listenable: _productsPageController,
        builder: (context, child) {
          return IconButton(
            tooltip: 'Buscar en catálogo',
            onPressed: () => _openCatalogSearchDialog(context),
            icon: _AppBarActionIcon(
              icon: Icons.search_rounded,
              active: _productsPageController.hasSearchQuery,
            ),
          );
        },
      ),
      ListenableBuilder(
        listenable: _productsPageController,
        builder: (context, child) {
          final theme = Theme.of(context);
          final categories = _productsPageController.categories;

          return PopupMenuButton<String>(
            tooltip: 'Filtrar por categoría',
            offset: const Offset(0, 10),
            position: PopupMenuPosition.under,
            surfaceTintColor: theme.colorScheme.surface,
            color: theme.colorScheme.surface,
            elevation: 10,
            shadowColor: Colors.black.withValues(alpha: 0.16),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(18),
              side: BorderSide(
                color: theme.colorScheme.outlineVariant.withValues(alpha: 0.75),
              ),
            ),
            onSelected: (value) {
              _productsPageController.selectCategory(
                value == _allCategoriesValue ? null : value,
              );
            },
            itemBuilder: (context) => [
              CheckedPopupMenuItem<String>(
                value: _allCategoriesValue,
                checked: _productsPageController.selectedCategory == null,
                child: const Text('Todas las categorías'),
              ),
              ...categories.map(
                (category) => CheckedPopupMenuItem<String>(
                  value: category,
                  checked: _productsPageController.selectedCategory == category,
                  child: Text(category),
                ),
              ),
            ],
            icon: _AppBarActionIcon(
              icon: Icons.filter_list_rounded,
              active: _productsPageController.hasActiveFilter,
            ),
          );
        },
      ),
    ];
  }

  List<Widget> _buildAppBarActions(
    BuildContext context,
    AuthState authState, {
    required String currentRoute,
    required int routeIndex,
  }) {
    final theme = Theme.of(context);
    final isCatalogRoute =
        routeIndex == 1 ||
        currentRoute == '/products' ||
        currentRoute.startsWith('/products/');
    final catalogActions = isCatalogRoute
        ? _buildCatalogAppBarActions(context)
        : const <Widget>[];

    return [
      ...catalogActions,
      IconButton(
        tooltip: _isSyncing ? 'Sincronizando app' : 'Sincronizar app',
        onPressed: _isSyncing ? null : () => _handleSyncAction(context),
        icon: AnimatedSwitcher(
          duration: const Duration(milliseconds: 180),
          child: _isSyncing
              ? SizedBox(
                  key: const ValueKey('syncing'),
                  width: 20,
                  height: 20,
                  child: CircularProgressIndicator(
                    strokeWidth: 2.2,
                    valueColor: AlwaysStoppedAnimation<Color>(
                      theme.colorScheme.primary,
                    ),
                  ),
                )
              : const Icon(Icons.sync_rounded, key: ValueKey('sync')),
        ),
      ),
      Padding(
        padding: const EdgeInsets.only(right: 6),
        child: PopupMenuButton<_SessionMenuAction>(
          tooltip: 'Sesión activa',
          offset: const Offset(0, 12),
          position: PopupMenuPosition.under,
          surfaceTintColor: theme.colorScheme.surface,
          color: theme.colorScheme.surface,
          elevation: 10,
          shadowColor: Colors.black.withValues(alpha: 0.16),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(22),
            side: BorderSide(
              color: theme.colorScheme.outlineVariant.withValues(alpha: 0.75),
            ),
          ),
          constraints: const BoxConstraints(minWidth: 248, maxWidth: 264),
          padding: EdgeInsets.zero,
          icon: _UserMenuButton(authState: authState),
          onSelected: (value) => _handleSessionAction(
            context,
            action: value,
            authState: authState,
          ),
          itemBuilder: (menuContext) => [
            PopupMenuItem<_SessionMenuAction>(
              enabled: false,
              padding: EdgeInsets.zero,
              child: SizedBox(
                width: 256,
                child: _SessionMenuHeader(authState: authState),
              ),
            ),
            const PopupMenuDivider(height: 1),
            const PopupMenuItem<_SessionMenuAction>(
              value: _SessionMenuAction.profile,
              height: 48,
              child: _SessionActionTile(
                title: 'Perfil',
                icon: Icons.account_circle_outlined,
              ),
            ),
            const PopupMenuItem<_SessionMenuAction>(
              value: _SessionMenuAction.settings,
              height: 48,
              child: _SessionActionTile(
                title: 'Configuracion',
                icon: Icons.settings_outlined,
              ),
            ),
            const PopupMenuItem<_SessionMenuAction>(
              value: _SessionMenuAction.logout,
              height: 48,
              child: _SessionActionTile(
                title: 'Cerrar sesión',
                icon: Icons.logout_rounded,
                destructive: true,
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

    return AppBar(
      toolbarHeight: 64,
      elevation: 0,
      scrolledUnderElevation: 1,
      surfaceTintColor: Colors.transparent,
      backgroundColor: theme.colorScheme.surface,
      leading: leading,
      titleSpacing: leading == null ? 18 : 8,
      title: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Text(
            title,
            style: theme.textTheme.titleLarge?.copyWith(
              fontWeight: FontWeight.w800,
              letterSpacing: -0.3,
            ),
          ),
          if (routeIndex != 0) ...[
            const SizedBox(height: 2),
            Text(
              'Panel administrativo',
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
                fontWeight: FontWeight.w600,
                fontSize: 11,
              ),
            ),
          ],
        ],
      ),
      centerTitle: false,
      actions: _buildAppBarActions(
        context,
        authState,
        currentRoute: currentRoute,
        routeIndex: routeIndex,
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
    final selectedMainRoute = _activeMainRoute(
      currentRoute,
      routeIndex: routeIndex,
    );

    final mainBody = showMainPages
        ? IndexedStack(index: routeIndex, children: _pages)
        : widget.child;

    final body = Column(
      children: [
        Expanded(child: mainBody),
        _FooterNavigationBar(
          items: _mainNavItems,
          selectedRoute: selectedMainRoute,
          onSelected: (route) {
            if (route == selectedMainRoute) return;
            context.go(route);
          },
        ),
      ],
    );

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

class _UserIdentity {
  const _UserIdentity({required this.displayName, required this.initials});

  final String displayName;
  final String initials;
}

_UserIdentity _resolveUserIdentity(AuthState authState) {
  final displayName = authState.displayName?.trim();
  final username = authState.username?.trim();
  final name = (displayName != null && displayName.isNotEmpty)
      ? displayName
      : (username != null && username.isNotEmpty ? username : 'Usuario activo');

  final parts = name
      .split(RegExp(r'\s+'))
      .where((part) => part.isNotEmpty)
      .take(2)
      .toList();
  final initials = parts.isEmpty
      ? 'U'
      : parts.map((part) => part.characters.first.toUpperCase()).join();

  return _UserIdentity(displayName: name, initials: initials);
}

class _UserMenuButton extends StatelessWidget {
  const _UserMenuButton({required this.authState});

  final AuthState authState;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final identity = _resolveUserIdentity(authState);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 4),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(999),
        border: Border.all(
          color: theme.colorScheme.outlineVariant.withValues(alpha: 0.75),
        ),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 34,
            height: 34,
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: [
                  theme.colorScheme.primary.withValues(alpha: 0.98),
                  Color.lerp(
                        theme.colorScheme.primary,
                        theme.colorScheme.secondary,
                        0.35,
                      ) ??
                      theme.colorScheme.primary,
                ],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              borderRadius: BorderRadius.circular(999),
            ),
            alignment: Alignment.center,
            child: Text(
              identity.initials,
              style: theme.textTheme.labelLarge?.copyWith(
                color: theme.colorScheme.onPrimary,
                fontWeight: FontWeight.w900,
              ),
            ),
          ),
          const SizedBox(width: 8),
          Icon(
            Icons.keyboard_arrow_down_rounded,
            color: theme.colorScheme.onSurfaceVariant,
            size: 20,
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
    final displayName = authState.displayName?.trim();
    final email = authState.email?.trim();
    final companyName = authState.companyName?.trim();
    final companyRnc = authState.companyRnc?.trim();
    final companyId = authState.companyId?.toString();
    final version = authState.ownerVersion?.trim();
    final normalizedDisplayName = displayName?.toLowerCase();
    final normalizedUsername = username?.toLowerCase();
    final shouldShowUsername =
        normalizedUsername != null &&
        normalizedUsername.isNotEmpty &&
        normalizedUsername != normalizedDisplayName;
    final detailRows = <Widget>[
      const _SessionInfoRow(label: 'Rol', value: 'Admin'),
      if (companyId != null && companyId.isNotEmpty)
        _buildSessionDetailRow(label: 'ID empresa', value: companyId),
      if (shouldShowUsername)
        _buildSessionDetailRow(label: 'Usuario', value: username!),
      if (version != null && version.isNotEmpty)
        _buildSessionDetailRow(label: 'Versión', value: version),
      if (email != null && email.isNotEmpty)
        _buildSessionDetailRow(label: 'Correo', value: email),
      if (companyName != null && companyName.isNotEmpty)
        _buildSessionDetailRow(label: 'Empresa', value: companyName),
      if (companyRnc != null && companyRnc.isNotEmpty)
        _buildSessionDetailRow(label: 'RNC', value: companyRnc, isLast: true),
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
                        theme.colorScheme.outlineVariant.withValues(
                          alpha: 0.55,
                        ),
                        Colors.transparent,
                      ],
                    ),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          _SessionDetailsPanel(children: detailRows),
        ],
      ),
    );
  }
}

class _AppBarActionIcon extends StatelessWidget {
  const _AppBarActionIcon({required this.icon, required this.active});

  final IconData icon;
  final bool active;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Stack(
      clipBehavior: Clip.none,
      children: [
        Container(
          width: 36,
          height: 36,
          decoration: BoxDecoration(
            color: active
                ? theme.colorScheme.primary.withValues(alpha: 0.12)
                : Colors.transparent,
            borderRadius: BorderRadius.circular(12),
          ),
          alignment: Alignment.center,
          child: Icon(
            icon,
            size: 20,
            color: active
                ? theme.colorScheme.primary
                : theme.colorScheme.onSurfaceVariant,
          ),
        ),
        if (active)
          Positioned(
            right: 3,
            top: 3,
            child: Container(
              width: 7,
              height: 7,
              decoration: const BoxDecoration(
                color: AppColors.success,
                shape: BoxShape.circle,
              ),
            ),
          ),
      ],
    );
  }
}

class _SessionMenuHeader extends StatelessWidget {
  const _SessionMenuHeader({required this.authState});

  final AuthState authState;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final identity = _resolveUserIdentity(authState);
    final username = authState.username?.trim();
    final companyName = authState.companyName?.trim();
    final normalizedDisplayName = identity.displayName.trim().toLowerCase();
    final normalizedUsername = username?.trim().toLowerCase();
    final String secondaryLabel =
        (normalizedUsername != null &&
            normalizedUsername.isNotEmpty &&
            normalizedUsername != normalizedDisplayName)
        ? username!
        : (companyName != null && companyName.isNotEmpty
              ? companyName
              : 'Administrador activo');

    return Container(
      padding: const EdgeInsets.fromLTRB(12, 12, 12, 10),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [
            theme.colorScheme.surface,
            theme.colorScheme.surfaceContainerLowest,
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: const BorderRadius.vertical(top: Radius.circular(22)),
      ),
      child: Row(
        children: [
          Container(
            width: 42,
            height: 42,
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: [
                  theme.colorScheme.primary,
                  Color.lerp(
                        theme.colorScheme.primary,
                        theme.colorScheme.secondary,
                        0.4,
                      ) ??
                      theme.colorScheme.primary,
                ],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              borderRadius: BorderRadius.circular(14),
              boxShadow: [
                BoxShadow(
                  color: theme.colorScheme.primary.withValues(alpha: 0.15),
                  blurRadius: 10,
                  offset: const Offset(0, 4),
                ),
              ],
            ),
            alignment: Alignment.center,
            child: Text(
              identity.initials,
              style: theme.textTheme.titleSmall?.copyWith(
                color: theme.colorScheme.onPrimary,
                fontWeight: FontWeight.w900,
              ),
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  identity.displayName,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.bodyLarge?.copyWith(
                    fontWeight: FontWeight.w900,
                    letterSpacing: -0.2,
                  ),
                ),
                const SizedBox(height: 1),
                Text(
                  secondaryLabel,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                    fontWeight: FontWeight.w600,
                    fontSize: 11.5,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _SessionActionTile extends StatelessWidget {
  const _SessionActionTile({
    required this.title,
    required this.icon,
    this.destructive = false,
  });

  final String title;
  final IconData icon;
  final bool destructive;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final color = destructive
        ? theme.colorScheme.error
        : theme.colorScheme.onSurface;

    return Row(
      children: [
        Container(
          width: 32,
          height: 32,
          decoration: BoxDecoration(
            color: destructive
                ? theme.colorScheme.errorContainer.withValues(alpha: 0.36)
                : theme.colorScheme.primary.withValues(alpha: 0.07),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(icon, size: 16, color: color),
        ),
        const SizedBox(width: 9),
        Expanded(
          child: Text(
            title,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: theme.textTheme.bodyMedium?.copyWith(
              color: color,
              fontWeight: FontWeight.w800,
              letterSpacing: -0.1,
            ),
          ),
        ),
        Icon(
          Icons.chevron_right_rounded,
          size: 16,
          color: destructive
              ? theme.colorScheme.error.withValues(alpha: 0.7)
              : theme.colorScheme.onSurfaceVariant.withValues(alpha: 0.7),
        ),
      ],
    );
  }
}

class _ProfileSheet extends StatelessWidget {
  const _ProfileSheet({required this.authState});

  final AuthState authState;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Container(
      padding: const EdgeInsets.fromLTRB(12, 12, 12, 12),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(24),
        border: Border.all(
          color: theme.colorScheme.outlineVariant.withValues(alpha: 0.85),
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.14),
            blurRadius: 24,
            offset: const Offset(0, 10),
          ),
        ],
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              Text(
                'Perfil',
                style: theme.textTheme.titleMedium?.copyWith(
                  fontWeight: FontWeight.w900,
                  letterSpacing: -0.25,
                ),
              ),
              const Spacer(),
              Icon(
                Icons.account_circle_outlined,
                color: theme.colorScheme.primary,
                size: 18,
              ),
            ],
          ),
          const SizedBox(height: 10),
          _SessionInfoMenu(authState: authState),
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

class _FooterNavigationBar extends StatelessWidget {
  const _FooterNavigationBar({
    required this.items,
    required this.selectedRoute,
    required this.onSelected,
  });

  final List<_MainNavItem> items;
  final String? selectedRoute;
  final ValueChanged<String> onSelected;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final safeBottom = MediaQuery.paddingOf(context).bottom;

    return Padding(
      padding: EdgeInsets.fromLTRB(
        0,
        8,
        0,
        safeBottom > 0 ? safeBottom - 2 : 4,
      ),
      child: DecoratedBox(
        decoration: BoxDecoration(
          color: theme.colorScheme.surface.withValues(alpha: 0.96),
          borderRadius: BorderRadius.circular(18),
          border: Border.all(
            color: theme.colorScheme.outlineVariant.withValues(alpha: 0.72),
          ),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.06),
              blurRadius: 16,
              offset: const Offset(0, 6),
            ),
          ],
        ),
        child: Padding(
          padding: const EdgeInsets.fromLTRB(6, 6, 6, 6),
          child: Row(
            children: [
              for (var index = 0; index < items.length; index++)
                Expanded(
                  child: Padding(
                    padding: EdgeInsets.only(
                      right: index == items.length - 1 ? 0 : 8,
                    ),
                    child: _FooterNavButton(
                      item: items[index],
                      selected: items[index].route == selectedRoute,
                      onTap: () => onSelected(items[index].route),
                    ),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }
}

class _FooterNavButton extends StatelessWidget {
  const _FooterNavButton({
    required this.item,
    required this.selected,
    required this.onTap,
  });

  final _MainNavItem item;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final activeColor = selected ? theme.colorScheme.primary : AppColors.ink;

    return Material(
      color: selected
          ? theme.colorScheme.primary.withValues(alpha: 0.12)
          : Colors.transparent,
      borderRadius: BorderRadius.circular(14),
      child: InkWell(
        borderRadius: BorderRadius.circular(14),
        onTap: onTap,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 180),
          curve: Curves.easeOutCubic,
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(14),
            gradient: selected
                ? LinearGradient(
                    colors: [
                      theme.colorScheme.primary.withValues(alpha: 0.15),
                      theme.colorScheme.primary.withValues(alpha: 0.06),
                    ],
                    begin: Alignment.topCenter,
                    end: Alignment.bottomCenter,
                  )
                : null,
            border: Border.all(
              color: selected
                  ? theme.colorScheme.primary.withValues(alpha: 0.24)
                  : Colors.transparent,
            ),
            boxShadow: selected
                ? [
                    BoxShadow(
                      color: theme.colorScheme.primary.withValues(alpha: 0.10),
                      blurRadius: 16,
                      offset: const Offset(0, 4),
                    ),
                  ]
                : null,
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(item.icon, size: 18, color: activeColor),
              const SizedBox(height: 4),
              Text(
                item.label,
                textAlign: TextAlign.center,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: theme.textTheme.titleSmall?.copyWith(
                  color: activeColor,
                  fontWeight: selected ? FontWeight.w800 : FontWeight.w600,
                  letterSpacing: -0.1,
                  fontSize: 11.5,
                ),
              ),
              const SizedBox(height: 2),
              AnimatedContainer(
                duration: const Duration(milliseconds: 180),
                curve: Curves.easeOutCubic,
                width: selected ? 18 : 0,
                height: 2.5,
                decoration: BoxDecoration(
                  color: theme.colorScheme.primary,
                  borderRadius: BorderRadius.circular(999),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _MainNavItem {
  const _MainNavItem({
    required this.route,
    required this.label,
    required this.icon,
  });

  final String route;
  final String label;
  final IconData icon;
}

enum _SessionMenuAction { profile, settings, logout }

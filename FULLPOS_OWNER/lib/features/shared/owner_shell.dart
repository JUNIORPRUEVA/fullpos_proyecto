import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/providers/sync_request_provider.dart';
import '../../core/realtime/company_realtime_service.dart';
import '../../core/theme/app_colors.dart';
import '../../core/widgets/app_shell_scaffold.dart';
import '../auth/data/auth_repository.dart';
import '../auth/data/auth_state.dart';
import '../inventory/presentation/inventory_page.dart';
import '../products/data/product_realtime_service.dart';
import '../products/presentation/products_page.dart';
import '../reports/application/sales_date_filter_controller.dart';
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
      label: 'Panel',
      icon: Icons.space_dashboard_rounded,
    ),
    _MainNavItem(
      route: '/products',
      label: 'Catalogo',
      icon: Icons.category_outlined,
    ),
    _MainNavItem(
      route: '/inventory',
      label: 'Inventario',
      icon: Icons.inventory_2_outlined,
    ),
  ];
  static const _allCategoriesValue = '__all_categories__';

  final GlobalKey<ScaffoldState> _scaffoldKey = GlobalKey<ScaffoldState>();
  late final ProductsPageController _productsPageController =
      ProductsPageController();
  late final InventoryPageController _inventoryPageController =
      InventoryPageController();
  late final List<Widget> _pages = [
    const DashboardPage(key: PageStorageKey('tab_panel')),
    ProductsPage(
      key: const PageStorageKey('tab_catalogo'),
      controller: _productsPageController,
      showEmbeddedToolbar: false,
    ),
    InventoryPage(
      key: const PageStorageKey('tab_inventory'),
      controller: _inventoryPageController,
      showEmbeddedToolbar: false,
    ),
  ];

  StreamSubscription<CompanyRealtimeMessage>? _companyRealtimeSubscription;
  Timer? _realtimeRefreshDebounce;
  bool _isSyncing = false;
  bool _isCatalogSearchVisible = false;
  final FocusNode _catalogSearchFocusNode = FocusNode();

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
    _catalogSearchFocusNode.dispose();
    _productsPageController.dispose();
    _inventoryPageController.dispose();
    super.dispose();
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

  int _resolveRouteIndex(String location) {
    for (var i = 0; i < _mainRoutes.length; i++) {
      final route = _mainRoutes[i];
      if (location == route || location.startsWith('$route/')) return i;
    }
    return -1;
  }

  String _titleForRoute(String route, {required int routeIndex}) {
    if (routeIndex == 0) return 'Panel';
    if (routeIndex == 1) return 'Catalogo';
    if (routeIndex == 2) return 'Inventario';
    if (route.startsWith('/settings')) return 'Configuracion';
    if (route.startsWith('/sales/by-day')) return 'Ventas diarias';
    if (route.startsWith('/sales/list')) return 'Registro de ventas';
    if (route.startsWith('/sales/detail')) return 'Ticket de venta';
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

  String? _activeMainRoute(String currentRoute, {required int routeIndex}) {
    if (routeIndex >= 0) return _mainRoutes[routeIndex];
    if (currentRoute.startsWith('/sales/')) return '/dashboard';
    return _mainRoutes.firstWhere(
      (route) => currentRoute == route || currentRoute.startsWith('$route/'),
      orElse: () => '/dashboard',
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

  Future<void> _handleSessionAction(
    BuildContext context, {
    required _SessionMenuAction action,
    required AuthState authState,
  }) async {
    if (Scaffold.maybeOf(context)?.isDrawerOpen ?? false) {
      Navigator.of(context).pop();
    }

    switch (action) {
      case _SessionMenuAction.profile:
        await _showProfileSheet(context, authState: authState);
        return;
      case _SessionMenuAction.settings:
        if (context.mounted) context.go('/settings');
        return;
      case _SessionMenuAction.logout:
        await ref.read(authRepositoryProvider.notifier).logout();
        if (!context.mounted) return;
        context.go('/login');
        return;
    }
  }

  Future<void> _showProfileSheet(
    BuildContext context, {
    required AuthState authState,
  }) {
    final width = MediaQuery.sizeOf(context).width;
    if (width < 900) {
      return showModalBottomSheet<void>(
        context: context,
        showDragHandle: true,
        useSafeArea: true,
        backgroundColor: Colors.transparent,
        builder: (sheetContext) {
          return Padding(
            padding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
            child: _ProfileSheet(authState: authState),
          );
        },
      );
    }

    return showGeneralDialog<void>(
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
  }

  void _openInlineCatalogSearch() {
    if (_isCatalogSearchVisible) return;
    setState(() {
      _isCatalogSearchVisible = true;
    });
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      _catalogSearchFocusNode.requestFocus();
    });
  }

  void _closeInlineCatalogSearch() {
    if (!_isCatalogSearchVisible) return;
    _catalogSearchFocusNode.unfocus();
    setState(() {
      _isCatalogSearchVisible = false;
    });
  }

  Future<void> _openDashboardFilterMenu(BuildContext context) async {
    final state = ref.read(salesDateFilterProvider);
    final selected = await showModalBottomSheet<SalesDatePreset>(
      context: context,
      showDragHandle: true,
      backgroundColor: Theme.of(context).colorScheme.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(26)),
      ),
      builder: (sheetContext) {
        final theme = Theme.of(sheetContext);
        final options = <SalesDatePreset>[
          SalesDatePreset.today,
          SalesDatePreset.yesterday,
          SalesDatePreset.week,
          SalesDatePreset.fortnight,
          SalesDatePreset.month,
          SalesDatePreset.custom,
        ];

        return SafeArea(
          top: false,
          child: Padding(
            padding: const EdgeInsets.fromLTRB(18, 4, 18, 18),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Filtrar panel',
                  style: theme.textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w900,
                    letterSpacing: -0.2,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  state.fullRangeLabel,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 14),
                for (final option in options) ...[
                  ListTile(
                    dense: true,
                    contentPadding: EdgeInsets.zero,
                    leading: Icon(presetIcon(option)),
                    title: Text(presetLabel(option)),
                    trailing: state.preset == option
                        ? Icon(
                            Icons.check_circle_rounded,
                            color: theme.colorScheme.primary,
                          )
                        : const Icon(Icons.chevron_right_rounded),
                    onTap: () => Navigator.of(sheetContext).pop(option),
                  ),
                  if (option != options.last) const Divider(height: 1),
                ],
              ],
            ),
          ),
        );
      },
    );

    if (selected == null || !context.mounted) return;
    if (selected == SalesDatePreset.custom) {
      await _pickCustomDashboardRange(context);
      return;
    }
    ref.read(salesDateFilterProvider.notifier).applyPreset(selected);
  }

  Future<void> _pickCustomDashboardRange(BuildContext context) async {
    final current = ref.read(salesDateFilterProvider).range;
    final today = localDateOnly(DateTime.now());
    final firstAllowedDate = today.subtract(
      const Duration(days: maxSalesDateFilterDays - 1),
    );
    var start = clampLocalDate(current.start, firstAllowedDate, today);
    var end = clampLocalDate(current.end, firstAllowedDate, today);
    if (start.isAfter(end)) start = end;

    final picked = await showDateRangePicker(
      context: context,
      firstDate: firstAllowedDate,
      lastDate: today,
      initialDateRange: DateTimeRange(start: start, end: end),
      helpText: 'Rango personalizado',
      cancelText: 'Cancelar',
      confirmText: 'Aplicar',
      fieldStartLabelText: 'Fecha inicial',
      fieldEndLabelText: 'Fecha final',
      errorInvalidRangeText: 'La fecha inicial no puede ser mayor que la final',
    );

    if (picked == null) return;
    ref
        .read(salesDateFilterProvider.notifier)
        .applyCustomRange(picked.start, picked.end);
  }

  List<Widget> _buildCatalogAppBarActions(BuildContext context) {
    return [
      ListenableBuilder(
        listenable: _productsPageController,
        builder: (context, child) {
          return IconButton(
            tooltip: _isCatalogSearchVisible
                ? 'Cerrar busqueda'
                : 'Buscar en catalogo',
            onPressed: _isCatalogSearchVisible
                ? _closeInlineCatalogSearch
                : _openInlineCatalogSearch,
            icon: _AppBarActionIcon(
              icon: _isCatalogSearchVisible
                  ? Icons.close_rounded
                  : Icons.search_rounded,
              active:
                  _isCatalogSearchVisible ||
                  _productsPageController.hasSearchQuery,
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
            tooltip: 'Filtrar por categoria',
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
                child: const Text('Todas las categorias'),
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
    BuildContext context, {
    required String currentRoute,
    required int routeIndex,
    required bool hasSidebar,
  }) {
    final theme = Theme.of(context);
    final isCatalogRoute =
        routeIndex == 1 ||
        currentRoute == '/products' ||
        currentRoute.startsWith('/products/');
    final isInventoryRoute =
        routeIndex == 2 ||
        currentRoute == '/inventory' ||
        currentRoute.startsWith('/inventory/');
    final catalogActions = isCatalogRoute
        ? _buildCatalogAppBarActions(context)
        : const <Widget>[];
    final inventoryActions = isInventoryRoute
        ? _buildInventoryAppBarActions(context)
        : const <Widget>[];
    final dashboardActions = routeIndex == 0
        ? <Widget>[
            IconButton(
              tooltip: 'Filtrar panel',
              onPressed: () => _openDashboardFilterMenu(context),
              icon: const _AppBarActionIcon(
                icon: Icons.tune_rounded,
                active: false,
              ),
            ),
          ]
        : const <Widget>[];

    return [
      ...catalogActions,
      ...inventoryActions,
      ...dashboardActions,
      Padding(
        padding: const EdgeInsets.only(right: 4),
        child: IconButton(
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
                : const _AppBarActionIcon(
                    key: ValueKey('sync'),
                    icon: Icons.sync_rounded,
                    active: false,
                  ),
          ),
        ),
      ),
    ];
  }

  List<Widget> _buildInventoryAppBarActions(BuildContext context) {
    return [
      ListenableBuilder(
        listenable: _inventoryPageController,
        builder: (context, child) {
          final theme = Theme.of(context);
          final categories = _inventoryPageController.categories;

          return PopupMenuButton<String>(
            tooltip: 'Filtrar por categoria',
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
              _inventoryPageController.selectCategory(
                value == _allCategoriesValue ? null : value,
              );
            },
            itemBuilder: (context) => [
              CheckedPopupMenuItem<String>(
                value: _allCategoriesValue,
                checked: _inventoryPageController.selectedCategory == null,
                child: const Text('Todas las categorias'),
              ),
              ...categories.map(
                (category) => CheckedPopupMenuItem<String>(
                  value: category,
                  checked:
                      _inventoryPageController.selectedCategory == category,
                  child: Text(category),
                ),
              ),
            ],
            icon: _AppBarActionIcon(
              icon: Icons.category_outlined,
              active: _inventoryPageController.selectedCategory != null,
            ),
          );
        },
      ),
      ListenableBuilder(
        listenable: _inventoryPageController,
        builder: (context, child) {
          return IconButton(
            tooltip: _inventoryPageController.outOfStockOnly
                ? 'Mostrar todo'
                : 'Mostrar agotados',
            onPressed: () => _inventoryPageController.toggleOutOfStock(
              !_inventoryPageController.outOfStockOnly,
            ),
            icon: _AppBarActionIcon(
              icon: Icons.remove_shopping_cart_outlined,
              active: _inventoryPageController.outOfStockOnly,
            ),
          );
        },
      ),
    ];
  }

  PreferredSizeWidget _buildAppBar(
    BuildContext context, {
    required String currentRoute,
    required int routeIndex,
    required bool hasSidebar,
  }) {
    final theme = Theme.of(context);
    final title = _titleForRoute(currentRoute, routeIndex: routeIndex);
    final isCatalogRoute =
        routeIndex == 1 ||
        currentRoute == '/products' ||
        currentRoute.startsWith('/products/');
    final leading = routeIndex >= 0 && !hasSidebar
        ? Padding(
            padding: const EdgeInsets.only(left: 10),
            child: _DrawerLauncherButton(
              onTap: () => _scaffoldKey.currentState?.openDrawer(),
            ),
          )
        : _isSecondaryRoute(currentRoute, routeIndex: routeIndex)
        ? IconButton(
            tooltip: 'Regresar',
            icon: const Icon(Icons.arrow_back_rounded),
            onPressed: () {
              context.go(_parentRouteFor(currentRoute));
            },
          )
        : null;

    return AppBar(
      toolbarHeight: routeIndex == 0 ? 76 : 70,
      elevation: 0,
      scrolledUnderElevation: 0,
      surfaceTintColor: Colors.transparent,
      backgroundColor: theme.colorScheme.surface,
      leading: leading,
      leadingWidth: routeIndex >= 0 && !hasSidebar ? 64 : null,
      titleSpacing: leading == null ? 18 : 6,
      title: AnimatedSwitcher(
        duration: const Duration(milliseconds: 180),
        switchInCurve: Curves.easeOutCubic,
        switchOutCurve: Curves.easeInCubic,
        child: isCatalogRoute && _isCatalogSearchVisible
            ? _InlineCatalogSearchField(
                key: const ValueKey('catalog-search'),
                controller: _productsPageController.searchController,
                focusNode: _catalogSearchFocusNode,
                onChanged: _productsPageController.applySearchChange,
                onSubmitted: (_) => _productsPageController.submitSearch(),
                onClear: _productsPageController.clearSearch,
              )
            : Text(
                key: ValueKey('title-$title'),
                title,
                style: theme.textTheme.titleLarge?.copyWith(
                  fontWeight: FontWeight.w900,
                  fontSize: routeIndex == 0 ? 29 : 21,
                  letterSpacing: -1.15,
                  color: const Color(0xFF131B2D),
                ),
              ),
      ),
      actions: _buildAppBarActions(
        context,
        currentRoute: currentRoute,
        routeIndex: routeIndex,
        hasSidebar: hasSidebar,
      ),
    );
  }

  String? _buildCompanySubtitle(AuthState authState) {
    final parts = <String>[];
    final companyRnc = authState.companyRnc?.trim();
    final companyId = authState.companyId;

    if (companyRnc != null && companyRnc.isNotEmpty) {
      parts.add('RNC $companyRnc');
    }
    if (companyId != null) {
      parts.add('ID $companyId');
    }

    if (parts.isEmpty) return null;
    return parts.join(' · ');
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
    final selectedMainRoute = _activeMainRoute(
      currentRoute,
      routeIndex: routeIndex,
    );
    final mainBody = routeIndex >= 0
        ? IndexedStack(index: routeIndex, children: _pages)
        : widget.child;

    return LayoutBuilder(
      builder: (context, constraints) {
        final hasSidebar = constraints.maxWidth >= 980;

        void selectRoute(String route) {
          if (route == selectedMainRoute) return;
          context.go(route);
        }

        final shellBody = Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (hasSidebar)
              Padding(
                padding: const EdgeInsets.only(right: 18),
                child: _OwnerSidebar(
                  authState: authState,
                  items: _mainNavItems,
                  selectedRoute: selectedMainRoute,
                  onSelected: selectRoute,
                  onActionSelected: (action) => _handleSessionAction(
                    context,
                    action: action,
                    authState: authState,
                  ),
                ),
              ),
            Expanded(child: mainBody),
          ],
        );

        return AppShellScaffold(
          scaffoldKey: _scaffoldKey,
          drawer: hasSidebar
              ? null
              : Drawer(
                  width: constraints.maxWidth > 420
                      ? 340
                      : constraints.maxWidth * 0.88,
                  backgroundColor: Colors.transparent,
                  surfaceTintColor: Colors.transparent,
                  child: _OwnerDrawer(
                    authState: authState,
                    items: _mainNavItems,
                    selectedRoute: selectedMainRoute,
                    onSelected: selectRoute,
                    onActionSelected: (action) => _handleSessionAction(
                      context,
                      action: action,
                      authState: authState,
                    ),
                  ),
                ),
          appBar: _buildAppBar(
            context,
            currentRoute: currentRoute,
            routeIndex: routeIndex,
            hasSidebar: hasSidebar,
          ),
          title: _titleForRoute(currentRoute, routeIndex: routeIndex),
          companyName: authState.companyName?.trim().isNotEmpty == true
              ? authState.companyName!.trim()
              : 'FULLPOS',
          companySubtitle: _buildCompanySubtitle(authState),
          username: authState.displayName ?? authState.username,
          version: authState.ownerVersion,
          body: shellBody,
          currentRoute: currentRoute,
          onDrawerNavigate: selectRoute,
          onLogout: () async {
            await ref.read(authRepositoryProvider.notifier).logout();
            if (!context.mounted) return;
            context.go('/login');
          },
        );
      },
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

class _DrawerLauncherButton extends StatelessWidget {
  const _DrawerLauncherButton({required this.onTap});

  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(14),
        onTap: onTap,
        child: Ink(
          width: 40,
          height: 40,
          decoration: BoxDecoration(
            gradient: LinearGradient(
              colors: [
                theme.colorScheme.primary.withValues(alpha: 0.18),
                const Color(0xFFEAF3FF),
              ],
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
            ),
            borderRadius: BorderRadius.circular(14),
            border: Border.all(
              color: theme.colorScheme.primary.withValues(alpha: 0.22),
            ),
            boxShadow: [
              BoxShadow(
                color: theme.colorScheme.primary.withValues(alpha: 0.12),
                blurRadius: 14,
                offset: const Offset(0, 6),
              ),
            ],
          ),
          child: Icon(
            Icons.menu_rounded,
            color: theme.colorScheme.primary,
            size: 18,
          ),
        ),
      ),
    );
  }
}

class _OwnerSidebar extends StatelessWidget {
  const _OwnerSidebar({
    required this.authState,
    required this.items,
    required this.selectedRoute,
    required this.onSelected,
    required this.onActionSelected,
  });

  final AuthState authState;
  final List<_MainNavItem> items;
  final String? selectedRoute;
  final ValueChanged<String> onSelected;
  final ValueChanged<_SessionMenuAction> onActionSelected;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    const accentColor = Color(0xFF5DB2FF);
    const textColor = Color(0xFFEAF2FF);
    const mutedColor = Color(0xFF8EA3BF);

    return Container(
      width: 228,
      height: double.infinity,
      padding: const EdgeInsets.fromLTRB(16, 18, 16, 16),
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          colors: [Color(0xFF0C1726), Color(0xFF102033), Color(0xFF0B1624)],
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
        ),
        borderRadius: BorderRadius.circular(28),
        border: Border.all(color: Colors.white12),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.18),
            blurRadius: 24,
            offset: const Offset(8, 0),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _BrandHeader(authState: authState),
          const SizedBox(height: 18),
          Text(
            'Navegacion',
            style: theme.textTheme.labelLarge?.copyWith(
              color: mutedColor,
              fontWeight: FontWeight.w800,
              fontSize: 11,
              letterSpacing: 1.1,
            ),
          ),
          const SizedBox(height: 8),
          for (final item in items) ...[
            _SidebarNavTile(
              item: item,
              selected: item.route == selectedRoute,
              onTap: () => onSelected(item.route),
              accentColor: accentColor,
              textColor: textColor,
              mutedColor: mutedColor,
            ),
            const SizedBox(height: 6),
          ],
          const Spacer(),
          _MenuActionTile(
            icon: Icons.account_circle_outlined,
            label: 'Perfil',
            onTap: () => onActionSelected(_SessionMenuAction.profile),
            textColor: textColor,
            mutedColor: mutedColor,
          ),
          const SizedBox(height: 6),
          _MenuActionTile(
            icon: Icons.settings_outlined,
            label: 'Configuracion',
            onTap: () => onActionSelected(_SessionMenuAction.settings),
            textColor: textColor,
            mutedColor: mutedColor,
          ),
          const SizedBox(height: 6),
          _MenuActionTile(
            icon: Icons.logout_rounded,
            label: 'Cerrar sesion',
            destructive: true,
            onTap: () => onActionSelected(_SessionMenuAction.logout),
            textColor: textColor,
            mutedColor: mutedColor,
          ),
        ],
      ),
    );
  }
}

class _OwnerDrawer extends StatelessWidget {
  const _OwnerDrawer({
    required this.authState,
    required this.items,
    required this.selectedRoute,
    required this.onSelected,
    required this.onActionSelected,
  });

  final AuthState authState;
  final List<_MainNavItem> items;
  final String? selectedRoute;
  final ValueChanged<String> onSelected;
  final ValueChanged<_SessionMenuAction> onActionSelected;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(12, 8, 28, 12),
        child: Container(
          decoration: BoxDecoration(
            color: theme.colorScheme.surface,
            borderRadius: BorderRadius.circular(30),
            border: Border.all(
              color: theme.colorScheme.outlineVariant.withValues(alpha: 0.78),
            ),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: 0.12),
                blurRadius: 28,
                offset: const Offset(0, 12),
              ),
            ],
          ),
          child: Padding(
            padding: const EdgeInsets.fromLTRB(18, 18, 18, 16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    const Expanded(child: SizedBox()),
                    IconButton(
                      tooltip: 'Cerrar menu',
                      onPressed: () => Navigator.of(context).pop(),
                      icon: const Icon(Icons.close_rounded),
                    ),
                  ],
                ),
                _BrandHeader(authState: authState, darkSurface: false),
                const SizedBox(height: 22),
                Text(
                  'Panel principal',
                  style: theme.textTheme.labelLarge?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                    fontWeight: FontWeight.w800,
                  ),
                ),
                const SizedBox(height: 10),
                for (final item in items) ...[
                  _SidebarNavTile(
                    item: item,
                    selected: item.route == selectedRoute,
                    onTap: () => onSelected(item.route),
                    accentColor: const Color(0xFF2C7BE5),
                    textColor: const Color(0xFF142033),
                    mutedColor: const Color(0xFF6C7C93),
                  ),
                  const SizedBox(height: 8),
                ],
                const Spacer(),
                _MenuActionTile(
                  icon: Icons.account_circle_outlined,
                  label: 'Perfil',
                  onTap: () => onActionSelected(_SessionMenuAction.profile),
                  textColor: const Color(0xFF142033),
                  mutedColor: const Color(0xFF6C7C93),
                ),
                const SizedBox(height: 8),
                _MenuActionTile(
                  icon: Icons.settings_outlined,
                  label: 'Configuracion',
                  onTap: () => onActionSelected(_SessionMenuAction.settings),
                  textColor: const Color(0xFF142033),
                  mutedColor: const Color(0xFF6C7C93),
                ),
                const SizedBox(height: 8),
                _MenuActionTile(
                  icon: Icons.logout_rounded,
                  label: 'Cerrar sesion',
                  destructive: true,
                  onTap: () => onActionSelected(_SessionMenuAction.logout),
                  textColor: const Color(0xFF142033),
                  mutedColor: const Color(0xFF6C7C93),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _BrandHeader extends StatelessWidget {
  const _BrandHeader({required this.authState, this.darkSurface = true});

  final AuthState authState;
  final bool darkSurface;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final identity = _resolveUserIdentity(authState);
    final companyName = authState.companyName?.trim();
    final companyMeta = <String>[
      if (authState.companyRnc?.trim().isNotEmpty == true)
        'RNC ${authState.companyRnc!.trim()}',
      if (authState.companyId != null) 'ID ${authState.companyId}',
    ].join(' · ');

    return Container(
      padding: const EdgeInsets.fromLTRB(14, 14, 14, 14),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [
            darkSurface
                ? Colors.white.withValues(alpha: 0.08)
                : const Color(0xFFEDF4FF),
            darkSurface ? Colors.white.withValues(alpha: 0.02) : Colors.white,
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(22),
        border: Border.all(
          color: darkSurface
              ? Colors.white.withValues(alpha: 0.08)
              : const Color(0xFFD7E4F7),
        ),
      ),
      child: Row(
        children: [
          Container(
            width: 48,
            height: 48,
            decoration: BoxDecoration(
              gradient: const LinearGradient(
                colors: [Color(0xFF5DB2FF), Color(0xFF2C7BE5)],
              ),
              borderRadius: BorderRadius.circular(16),
              boxShadow: [
                BoxShadow(
                  color: const Color(0xFF5DB2FF).withValues(alpha: 0.28),
                  blurRadius: 14,
                  offset: const Offset(0, 6),
                ),
              ],
            ),
            alignment: Alignment.center,
            child: Text(
              identity.initials,
              style: theme.textTheme.titleMedium?.copyWith(
                color: Colors.white,
                fontWeight: FontWeight.w900,
              ),
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  companyName != null && companyName.isNotEmpty
                      ? companyName
                      : 'FULLPOS OWNER',
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.titleMedium?.copyWith(
                    color: darkSurface
                        ? const Color(0xFFEAF2FF)
                        : const Color(0xFF1A2740),
                    fontWeight: FontWeight.w900,
                    fontSize: 15,
                    letterSpacing: -0.2,
                  ),
                ),
                const SizedBox(height: 3),
                Text(
                  identity.displayName,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: darkSurface
                        ? const Color(0xFF8EA3BF)
                        : const Color(0xFF5F7290),
                    fontWeight: FontWeight.w700,
                    fontSize: 12,
                  ),
                ),
                if (companyMeta.isNotEmpty) ...[
                  const SizedBox(height: 4),
                  Text(
                    companyMeta,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: darkSurface
                          ? const Color(0xFFC7D5E8)
                          : const Color(0xFF6A7B94),
                      fontWeight: FontWeight.w600,
                      height: 1.25,
                    ),
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _SidebarNavTile extends StatelessWidget {
  const _SidebarNavTile({
    required this.item,
    required this.selected,
    required this.onTap,
    required this.accentColor,
    required this.textColor,
    required this.mutedColor,
  });

  final _MainNavItem item;
  final bool selected;
  final VoidCallback onTap;
  final Color accentColor;
  final Color textColor;
  final Color mutedColor;

  @override
  Widget build(BuildContext context) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(18),
        onTap: onTap,
        child: Ink(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 11),
          decoration: BoxDecoration(
            gradient: selected
                ? LinearGradient(
                    colors: [
                      accentColor.withValues(alpha: 0.22),
                      accentColor.withValues(alpha: 0.10),
                    ],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  )
                : LinearGradient(
                    colors: [
                      Colors.white.withValues(alpha: 0.05),
                      Colors.white.withValues(alpha: 0.015),
                    ],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  ),
            borderRadius: BorderRadius.circular(18),
            border: Border.all(
              color: selected
                  ? accentColor.withValues(alpha: 0.28)
                  : Colors.white.withValues(alpha: 0.06),
            ),
          ),
          child: Row(
            children: [
              Container(
                width: 36,
                height: 36,
                decoration: BoxDecoration(
                  color: selected
                      ? Colors.white.withValues(alpha: 0.12)
                      : Colors.white.withValues(alpha: 0.06),
                  borderRadius: BorderRadius.circular(12),
                ),
                alignment: Alignment.center,
                child: Icon(
                  item.icon,
                  color: selected ? accentColor : mutedColor,
                  size: 18,
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  item.label,
                  style: Theme.of(context).textTheme.titleSmall?.copyWith(
                    fontWeight: FontWeight.w700,
                    fontSize: 13,
                    color: selected
                        ? textColor
                        : textColor.withValues(alpha: 0.88),
                  ),
                ),
              ),
              Icon(
                Icons.chevron_right_rounded,
                color: selected ? accentColor : mutedColor,
                size: 18,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _MenuActionTile extends StatelessWidget {
  const _MenuActionTile({
    required this.icon,
    required this.label,
    required this.onTap,
    required this.textColor,
    required this.mutedColor,
    this.destructive = false,
  });

  final IconData icon;
  final String label;
  final VoidCallback onTap;
  final Color textColor;
  final Color mutedColor;
  final bool destructive;

  @override
  Widget build(BuildContext context) {
    final color = destructive ? const Color(0xFFFF7B7B) : textColor;

    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(16),
        onTap: onTap,
        child: Ink(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 11),
          decoration: BoxDecoration(
            color: destructive
                ? const Color(0xFFFF7B7B).withValues(alpha: 0.10)
                : Colors.white.withValues(alpha: 0.04),
            borderRadius: BorderRadius.circular(16),
            border: Border.all(
              color: destructive
                  ? const Color(0xFFFF7B7B).withValues(alpha: 0.18)
                  : Colors.white.withValues(alpha: 0.06),
            ),
          ),
          child: Row(
            children: [
              Icon(icon, color: color, size: 18),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  label,
                  style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: color,
                    fontWeight: FontWeight.w700,
                    fontSize: 13,
                  ),
                ),
              ),
              Icon(
                Icons.chevron_right_rounded,
                color: destructive ? color.withValues(alpha: 0.8) : mutedColor,
                size: 18,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _AppBarActionIcon extends StatelessWidget {
  const _AppBarActionIcon({
    super.key,
    required this.icon,
    required this.active,
  });

  final IconData icon;
  final bool active;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Stack(
      clipBehavior: Clip.none,
      children: [
        Container(
          width: 38,
          height: 38,
          decoration: BoxDecoration(
            gradient: LinearGradient(
              colors: active
                  ? [
                      theme.colorScheme.primary.withValues(alpha: 0.18),
                      theme.colorScheme.primary.withValues(alpha: 0.07),
                    ]
                  : [
                      theme.colorScheme.surfaceContainerLowest,
                      theme.colorScheme.surface.withValues(alpha: 0.92),
                    ],
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
            ),
            borderRadius: BorderRadius.circular(13),
            border: Border.all(
              color: active
                  ? theme.colorScheme.primary.withValues(alpha: 0.22)
                  : theme.colorScheme.outlineVariant.withValues(alpha: 0.55),
            ),
            boxShadow: [
              BoxShadow(
                color: active
                    ? theme.colorScheme.primary.withValues(alpha: 0.10)
                    : theme.colorScheme.shadow.withValues(alpha: 0.04),
                blurRadius: 12,
                offset: const Offset(0, 4),
              ),
            ],
          ),
          alignment: Alignment.center,
          child: Icon(
            icon,
            size: 19,
            color: active ? theme.colorScheme.primary : const Color(0xFF5C677B),
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

class _InlineCatalogSearchField extends StatelessWidget {
  const _InlineCatalogSearchField({
    super.key,
    required this.controller,
    required this.focusNode,
    required this.onChanged,
    required this.onSubmitted,
    required this.onClear,
  });

  final TextEditingController controller;
  final FocusNode focusNode;
  final ValueChanged<String> onChanged;
  final ValueChanged<String> onSubmitted;
  final VoidCallback onClear;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return ValueListenableBuilder<TextEditingValue>(
      valueListenable: controller,
      builder: (context, value, child) {
        return Container(
          height: 44,
          decoration: BoxDecoration(
            color: theme.colorScheme.surfaceContainerLowest,
            borderRadius: BorderRadius.circular(14),
            border: Border.all(
              color: theme.colorScheme.outlineVariant.withValues(alpha: 0.7),
            ),
          ),
          child: Row(
            children: [
              const SizedBox(width: 12),
              Icon(
                Icons.search_rounded,
                size: 18,
                color: theme.colorScheme.primary,
              ),
              const SizedBox(width: 10),
              Expanded(
                child: TextField(
                  controller: controller,
                  focusNode: focusNode,
                  autofocus: true,
                  onChanged: onChanged,
                  onSubmitted: onSubmitted,
                  textInputAction: TextInputAction.search,
                  textAlignVertical: TextAlignVertical.center,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: const Color(0xFF182033),
                    fontWeight: FontWeight.w700,
                  ),
                  decoration: InputDecoration(
                    hintText: 'Buscar en catalogo',
                    hintStyle: theme.textTheme.bodyMedium?.copyWith(
                      color: const Color(0xFF8A94A6),
                      fontWeight: FontWeight.w500,
                    ),
                    border: InputBorder.none,
                    isDense: true,
                    contentPadding: const EdgeInsets.symmetric(vertical: 10),
                  ),
                ),
              ),
              if (value.text.isNotEmpty)
                IconButton(
                  tooltip: 'Limpiar busqueda',
                  onPressed: onClear,
                  icon: Icon(
                    Icons.close_rounded,
                    size: 18,
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                )
              else
                const SizedBox(width: 8),
            ],
          ),
        );
      },
    );
  }
}

class _ProfileSheet extends StatelessWidget {
  const _ProfileSheet({required this.authState});

  final AuthState authState;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final identity = _resolveUserIdentity(authState);
    final details = <({String label, String value})>[
      (
        label: 'Usuario',
        value: authState.username?.trim().isNotEmpty == true
            ? authState.username!.trim()
            : identity.displayName,
      ),
      (
        label: 'Correo',
        value: authState.email?.trim().isNotEmpty == true
            ? authState.email!.trim()
            : 'No disponible',
      ),
      (
        label: 'Empresa',
        value: authState.companyName?.trim().isNotEmpty == true
            ? authState.companyName!.trim()
            : 'FULLPOS',
      ),
      (
        label: 'Contexto',
        value:
            [
              if (authState.companyId != null) 'ID ${authState.companyId}',
              if (authState.companyRnc?.trim().isNotEmpty == true)
                'RNC ${authState.companyRnc!.trim()}',
            ].join(' · ').isEmpty
            ? 'Sin datos adicionales'
            : [
                if (authState.companyId != null) 'ID ${authState.companyId}',
                if (authState.companyRnc?.trim().isNotEmpty == true)
                  'RNC ${authState.companyRnc!.trim()}',
              ].join(' · '),
      ),
    ];

    return Material(
      color: theme.colorScheme.surface,
      borderRadius: BorderRadius.circular(28),
      child: Container(
        padding: const EdgeInsets.fromLTRB(18, 18, 18, 18),
        decoration: BoxDecoration(
          color: theme.colorScheme.surface,
          borderRadius: BorderRadius.circular(28),
          border: Border.all(
            color: theme.colorScheme.outlineVariant.withValues(alpha: 0.82),
          ),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.12),
              blurRadius: 24,
              offset: const Offset(0, 10),
            ),
          ],
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Container(
                  width: 52,
                  height: 52,
                  decoration: BoxDecoration(
                    gradient: LinearGradient(
                      colors: [
                        theme.colorScheme.primary,
                        theme.colorScheme.secondary,
                      ],
                    ),
                    borderRadius: BorderRadius.circular(18),
                  ),
                  alignment: Alignment.center,
                  child: Text(
                    identity.initials,
                    style: theme.textTheme.titleMedium?.copyWith(
                      color: theme.colorScheme.onPrimary,
                      fontWeight: FontWeight.w900,
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        identity.displayName,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: theme.textTheme.titleMedium?.copyWith(
                          fontWeight: FontWeight.w900,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'Perfil del administrador',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 18),
            for (var i = 0; i < details.length; i++) ...[
              _ProfileInfoRow(label: details[i].label, value: details[i].value),
              if (i != details.length - 1) const Divider(height: 18),
            ],
          ],
        ),
      ),
    );
  }
}

class _ProfileInfoRow extends StatelessWidget {
  const _ProfileInfoRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 72,
          child: Text(
            label,
            style: theme.textTheme.labelMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
              fontWeight: FontWeight.w800,
            ),
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Text(
            value,
            style: theme.textTheme.bodyMedium?.copyWith(
              fontWeight: FontWeight.w700,
            ),
          ),
        ),
      ],
    );
  }
}

class _UserIdentity {
  const _UserIdentity({required this.displayName, required this.initials});

  final String displayName;
  final String initials;
}

_UserIdentity _resolveUserIdentity(AuthState authState) {
  final displayName = authState.displayName?.trim().isNotEmpty == true
      ? authState.displayName!.trim()
      : authState.username?.trim().isNotEmpty == true
      ? authState.username!.trim()
      : 'Administrador';

  final parts = displayName
      .split(RegExp(r'\s+'))
      .where((part) => part.trim().isNotEmpty)
      .toList();
  final initials = parts.isEmpty
      ? 'AD'
      : parts.take(2).map((part) => part.characters.first.toUpperCase()).join();

  return _UserIdentity(displayName: displayName, initials: initials);
}

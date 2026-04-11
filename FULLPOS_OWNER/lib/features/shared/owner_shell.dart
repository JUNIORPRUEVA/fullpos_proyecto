import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
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
  final ProductsPageController _productsController = ProductsPageController();

  late final List<Widget> _pages = [
    const DashboardPage(key: PageStorageKey('tab_reportes')),
    ProductsPage(
      key: const PageStorageKey('tab_catalog'),
      controller: _productsController,
      showEmbeddedToolbar: false,
    ),
    const InventoryPage(key: PageStorageKey('tab_inventory')),
  ];

  Future<void> _syncRealtimeConnections() async {
    final authState = ref.read(authRepositoryProvider);
    final productRealtime = ref.read(productRealtimeServiceProvider);
    final saleRealtime = ref.read(saleRealtimeServiceProvider);

    final hasSession =
        (authState.accessToken?.trim().isNotEmpty ?? false) ||
        (authState.refreshToken?.trim().isNotEmpty ?? false);

    if (!hasSession) {
      productRealtime.disconnect();
      saleRealtime.disconnect();
      return;
    }

    await Future.wait<void>([
      productRealtime.connect(authState),
      saleRealtime.connect(authState),
    ]);
  }

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      unawaited(_syncRealtimeConnections());
    });
  }

  @override
  void dispose() {
    _productsController.dispose();
    super.dispose();
  }

  String _titleForRoute(String route, {required int routeIndex}) {
    if (routeIndex == 0) return 'Reporte';
    if (routeIndex == 1) return 'Catálogo';
    if (routeIndex == 2) return 'Inventario';

    if (route.startsWith('/sales/by-day')) return 'Ventas diarias';
    if (route.startsWith('/sales/list')) return 'Registro de ventas';
    if (route.startsWith('/inventory')) return 'Inventario';

    return '';
  }

  List<Widget> _buildAppBarActions(BuildContext context, AuthState authState) {
    return [
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

    if (routeIndex == 0) {
      return AppBar(
        toolbarHeight: 58,
        elevation: 0,
        scrolledUnderElevation: 1,
        surfaceTintColor: Colors.transparent,
        backgroundColor: theme.colorScheme.surface,
        centerTitle: false,
        titleSpacing: 12,
        actions: _buildAppBarActions(context, authState),
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
        titleSpacing: 6,
        title: SizedBox(
          height: 36,
          child: TextField(
            controller: _productsController.searchController,
            textInputAction: TextInputAction.search,
            onChanged: (value) => _productsController.onChanged?.call(value),
            onSubmitted: (_) => _productsController.onSearch?.call(),
            decoration: InputDecoration(
              hintText: 'Buscar productos',
              isDense: true,
              filled: true,
              fillColor: theme.colorScheme.surfaceContainerLow,
              prefixIcon: const Icon(Icons.search),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(14),
                borderSide: BorderSide.none,
              ),
              contentPadding: const EdgeInsets.symmetric(
                horizontal: 12,
                vertical: 8,
              ),
            ),
          ),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.tune_outlined),
            tooltip: 'Filtrar',
            onPressed: () => _productsController.onFilter?.call(context),
          ),
          ..._buildAppBarActions(context, authState),
        ],
      );
    }

    return AppBar(
      toolbarHeight: 52,
      elevation: 0,
      scrolledUnderElevation: 1,
      surfaceTintColor: Colors.transparent,
      backgroundColor: theme.colorScheme.surface,
      title: Text(title, style: const TextStyle(fontWeight: FontWeight.w700)),
      centerTitle: false,
      actions: _buildAppBarActions(context, authState),
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
      companySubtitle: null,
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
}

class _SessionInfoRow extends StatelessWidget {
  const _SessionInfoRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerLow,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: theme.textTheme.labelMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            value,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: theme.textTheme.titleSmall?.copyWith(
              fontWeight: FontWeight.w700,
            ),
          ),
        ],
      ),
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

    return parts
        .map((part) => part.characters.first.toUpperCase())
        .join();
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
          Row(
            children: [
              Container(
                width: 46,
                height: 46,
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
                    color: theme.colorScheme.primary.withAlpha((0.16 * 255).round()),
                  ),
                ),
                alignment: Alignment.center,
                child: Text(
                  _initials,
                  style: theme.textTheme.titleMedium?.copyWith(
                    color: theme.colorScheme.primary,
                    fontWeight: FontWeight.w900,
                    letterSpacing: 0.2,
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
                      _displayName,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: theme.textTheme.titleMedium?.copyWith(
                        fontWeight: FontWeight.w800,
                        letterSpacing: -0.2,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      'Sesión activa',
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 0,
            children: [
              const SizedBox(
                width: 136,
                child: _SessionInfoRow(label: 'Rol', value: 'Admin'),
              ),
              if (companyId != null && companyId.isNotEmpty)
                SizedBox(
                  width: 136,
                  child: _SessionInfoRow(label: 'ID empresa', value: companyId),
                ),
              if (username != null && username.isNotEmpty)
                SizedBox(
                  width: 136,
                  child: _SessionInfoRow(label: 'Usuario', value: username),
                ),
              if (version != null && version.isNotEmpty)
                SizedBox(
                  width: 136,
                  child: _SessionInfoRow(label: 'Versión', value: version),
                ),
              if (email != null && email.isNotEmpty)
                SizedBox(
                  width: 280,
                  child: _SessionInfoRow(label: 'Correo', value: email),
                ),
              if (companyName != null && companyName.isNotEmpty)
                SizedBox(
                  width: 280,
                  child: _SessionInfoRow(label: 'Empresa', value: companyName),
                ),
              if (companyRnc != null && companyRnc.isNotEmpty)
                SizedBox(
                  width: 280,
                  child: _SessionInfoRow(label: 'RNC', value: companyRnc),
                ),
            ],
          ),
        ],
      ),
    );
  }
}

enum _SessionMenuAction { logout }

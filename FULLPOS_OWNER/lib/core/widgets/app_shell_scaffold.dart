import 'package:flutter/material.dart';

import '../theme/app_colors.dart';
import 'app_background.dart';

class AppShellScaffold extends StatelessWidget {
  const AppShellScaffold({
    super.key,
    this.appBar,
    required this.title,
    required this.companyName,
    this.companySubtitle,
    this.username,
    this.version,
    required this.body,
    required this.currentRoute,
    required this.onDrawerNavigate,
    this.onLogout,
  });

  final PreferredSizeWidget? appBar;
  final String title;
  final String companyName;
  final String? companySubtitle;
  final String? username;
  final String? version;
  final Widget body;
  final String currentRoute;
  final ValueChanged<String> onDrawerNavigate;
  final Future<void> Function()? onLogout;

  static const _mainDrawerRoutes = [
    _NavItem(
      icon: Icons.stacked_line_chart_rounded,
      label: 'Reportes',
      route: '/dashboard',
    ),
    _NavItem(
      icon: Icons.widgets_outlined,
      label: 'Catalogo',
      route: '/products',
    ),
    _NavItem(
      icon: Icons.inventory_rounded,
      label: 'Inventario',
      route: '/inventory',
    ),
  ];

  static const _reportDrawerRoutes = [
    _NavItem(
      icon: Icons.timeline_rounded,
      label: 'Ventas diarias',
      route: '/sales/by-day',
    ),
  ];

  static const _settingsRoute = _NavItem(
    icon: Icons.handyman_rounded,
    label: 'Configuración',
    route: '/settings',
  );

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;

    return LayoutBuilder(
      builder: (context, constraints) {
        final useDesktopSidebar = constraints.maxWidth >= 1180;

        return Scaffold(
          backgroundColor: theme.scaffoldBackgroundColor,
          appBar: appBar ?? _buildAppBar(theme, scheme, useDesktopSidebar),
          drawer: useDesktopSidebar ? null : _buildSidebarDrawer(context),
          body: AppBackground(
            child: SafeArea(
              bottom: false,
              child: Padding(
                padding: EdgeInsets.fromLTRB(
                  useDesktopSidebar ? 18 : 16,
                  useDesktopSidebar ? 18 : 16,
                  16,
                  18,
                ),
                child: useDesktopSidebar
                    ? Row(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          SizedBox(
                            width: 290,
                            child: _buildDesktopSidebar(context),
                          ),
                          const SizedBox(width: 18),
                          Expanded(child: body),
                        ],
                      )
                    : body,
              ),
            ),
          ),
        );
      },
    );
  }

  PreferredSizeWidget _buildAppBar(
    ThemeData theme,
    ColorScheme scheme,
    bool useDesktopSidebar,
  ) {
    return AppBar(
      toolbarHeight: 56,
      elevation: 0,
      scrolledUnderElevation: 1,
      surfaceTintColor: Colors.transparent,
      backgroundColor: scheme.surface.withAlpha((0.94 * 255).round()),
      foregroundColor: AppColors.ink,
      shadowColor: Colors.black.withAlpha((0.04 * 255).round()),
      titleSpacing: useDesktopSidebar ? 18 : 14,
      automaticallyImplyLeading: !useDesktopSidebar,
      bottom: PreferredSize(
        preferredSize: const Size.fromHeight(1),
        child: Container(
          height: 1,
          color: AppColors.border.withAlpha((0.7 * 255).round()),
        ),
      ),
      title: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Text(
            title,
            style: theme.textTheme.titleMedium?.copyWith(
              color: AppColors.ink,
              fontWeight: FontWeight.w800,
              letterSpacing: -0.2,
              height: 1.0,
            ),
          ),
          if (companySubtitle != null && companySubtitle!.trim().isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(top: 3),
              child: Text(
                companySubtitle!,
                style: theme.textTheme.bodySmall?.copyWith(
                  color: AppColors.textSecondary,
                  fontWeight: FontWeight.w600,
                  height: 1.0,
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildSidebarDrawer(BuildContext context) {
    return Drawer(
      width: 312,
      backgroundColor: Theme.of(context).colorScheme.surface,
      surfaceTintColor: Colors.transparent,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.only(
          topRight: Radius.circular(24),
          bottomRight: Radius.circular(24),
        ),
      ),
      child: SafeArea(child: _buildSidebarContent(context, isDesktop: false)),
    );
  }

  Widget _buildDesktopSidebar(BuildContext context) {
    return DecoratedBox(
      decoration: BoxDecoration(
        color: AppColors.white.withAlpha((0.68 * 255).round()),
        borderRadius: BorderRadius.circular(28),
        border: Border.all(
          color: AppColors.border.withAlpha((0.8 * 255).round()),
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withAlpha((0.035 * 255).round()),
            blurRadius: 24,
            offset: const Offset(0, 10),
          ),
        ],
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(28),
        child: _buildSidebarContent(context, isDesktop: true),
      ),
    );
  }

  Widget _buildSidebarContent(BuildContext context, {required bool isDesktop}) {
    final theme = Theme.of(context);

    return DecoratedBox(
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          colors: [AppColors.surfaceMuted, Color(0xFFF7FAFF), AppColors.white],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          stops: [0.0, 0.52, 1.0],
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Padding(
            padding: EdgeInsets.fromLTRB(22, isDesktop ? 24 : 20, 22, 12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  width: 42,
                  height: 2,
                  decoration: BoxDecoration(
                    color: AppColors.textSecondary.withAlpha(
                      (0.16 * 255).round(),
                    ),
                    borderRadius: BorderRadius.circular(999),
                  ),
                ),
                const SizedBox(height: 14),
                Text(
                  'OWNER PANEL',
                  style: theme.textTheme.labelSmall?.copyWith(
                    color: AppColors.textSecondary,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 1.3,
                  ),
                ),
                const SizedBox(height: 16),
                Text(
                  companyName.toUpperCase(),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.titleMedium?.copyWith(
                    color: AppColors.textPrimary,
                    fontWeight: FontWeight.w800,
                    letterSpacing: -0.2,
                    height: 1.0,
                  ),
                ),
                if (companySubtitle != null &&
                    companySubtitle!.trim().isNotEmpty) ...[
                  const SizedBox(height: 6),
                  Text(
                    companySubtitle!,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: AppColors.textSecondary,
                      fontWeight: FontWeight.w500,
                      height: 1.25,
                    ),
                  ),
                ],
                if (username != null && username!.trim().isNotEmpty) ...[
                  const SizedBox(height: 10),
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 10,
                      vertical: 7,
                    ),
                    decoration: BoxDecoration(
                      color: AppColors.white.withAlpha((0.72 * 255).round()),
                      borderRadius: BorderRadius.circular(999),
                      border: Border.all(
                        color: AppColors.border.withAlpha((0.7 * 255).round()),
                      ),
                    ),
                    child: Text(
                      username!,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: AppColors.textSecondary,
                        fontWeight: FontWeight.w600,
                        height: 1.0,
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ),
          Expanded(
            child: ListView(
              padding: const EdgeInsets.fromLTRB(12, 6, 12, 10),
              children: [
                ..._mainDrawerRoutes.map(
                  (item) => _DrawerNavTile(
                    item: item,
                    isSelected: _isRouteSelected(currentRoute, item.route),
                    onTap: () => _navigateFromDrawer(context, item.route),
                    emphasize: true,
                  ),
                ),
                const SizedBox(height: 12),
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 10),
                  child: Container(
                    height: 1,
                    color: AppColors.border.withAlpha((0.85 * 255).round()),
                  ),
                ),
                const SizedBox(height: 8),
                ..._reportDrawerRoutes.map(
                  (item) => _DrawerNavTile(
                    item: item,
                    isSelected: _isRouteSelected(currentRoute, item.route),
                    onTap: () => _navigateFromDrawer(context, item.route),
                  ),
                ),
              ],
            ),
          ),
          Padding(
            padding: EdgeInsets.fromLTRB(18, 8, 18, isDesktop ? 20 : 18),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 10),
                  child: Container(
                    height: 1,
                    color: AppColors.border.withAlpha((0.85 * 255).round()),
                  ),
                ),
                const SizedBox(height: 10),
                _DrawerActionTile(
                  icon: Icons.handyman_rounded,
                  label: 'Configuración',
                  isSelected: _isRouteSelected(
                    currentRoute,
                    _settingsRoute.route,
                  ),
                  onTap: () =>
                      _navigateFromDrawer(context, _settingsRoute.route),
                ),
                const SizedBox(height: 4),
                _DrawerActionTile(
                  icon: Icons.power_settings_new_rounded,
                  label: 'Cerrar sesión',
                  color: theme.colorScheme.error,
                  onTap: onLogout,
                ),
                const SizedBox(height: 8),
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 10),
                  child: Text(
                    version != null ? 'Version $version' : 'Version 1.0.0',
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: AppColors.textSecondary,
                      fontWeight: FontWeight.w600,
                      letterSpacing: 0.1,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  bool _isRouteSelected(String activeRoute, String itemRoute) {
    if (itemRoute == '/dashboard') {
      return activeRoute == '/dashboard' || activeRoute.startsWith('/sales/');
    }

    return activeRoute == itemRoute || activeRoute.startsWith('$itemRoute/');
  }

  void _navigateFromDrawer(BuildContext context, String route) {
    final scaffold = Scaffold.maybeOf(context);
    if (scaffold?.isDrawerOpen ?? false) {
      Navigator.of(context).pop();
    }
    onDrawerNavigate(route);
  }
}

class _DrawerNavTile extends StatelessWidget {
  const _DrawerNavTile({
    required this.item,
    required this.isSelected,
    required this.onTap,
    this.emphasize = false,
  });

  final _NavItem item;
  final bool isSelected;
  final VoidCallback onTap;
  final bool emphasize;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final selectedColor = AppColors.primaryBlue;
    final textColor = isSelected ? AppColors.primaryBlue : AppColors.ink;

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 1),
      child: InkWell(
        borderRadius: BorderRadius.circular(14),
        onTap: onTap,
        child: Container(
          padding: EdgeInsets.symmetric(
            horizontal: 10,
            vertical: emphasize ? 11 : 9,
          ),
          decoration: BoxDecoration(
            color: isSelected
                ? AppColors.primaryBlueSoft.withAlpha((0.78 * 255).round())
                : Colors.transparent,
            borderRadius: BorderRadius.circular(14),
          ),
          child: Row(
            children: [
              Container(
                width: emphasize ? 34 : 30,
                height: emphasize ? 34 : 30,
                decoration: BoxDecoration(
                  color: isSelected
                      ? AppColors.primaryBlueSoft
                      : AppColors.white.withAlpha((0.7 * 255).round()),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(
                    color: isSelected
                        ? AppColors.border.withAlpha((0.75 * 255).round())
                        : AppColors.border.withAlpha((0.52 * 255).round()),
                  ),
                ),
                child: Icon(
                  item.icon,
                  color: textColor,
                  size: emphasize ? 20 : 18,
                ),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Text(
                  item.label,
                  style:
                      (emphasize
                              ? theme.textTheme.titleMedium
                              : theme.textTheme.titleSmall)
                          ?.copyWith(
                            color: textColor,
                            fontWeight: isSelected
                                ? FontWeight.w800
                                : FontWeight.w600,
                            letterSpacing: -0.1,
                            height: 1.0,
                          ),
                ),
              ),
              if (isSelected)
                Container(
                  width: 8,
                  height: 8,
                  decoration: BoxDecoration(
                    color: selectedColor,
                    shape: BoxShape.circle,
                  ),
                )
              else
                Icon(
                  Icons.chevron_right_rounded,
                  size: 16,
                  color: AppColors.textSecondary.withAlpha((0.8 * 255).round()),
                ),
            ],
          ),
        ),
      ),
    );
  }
}

class _DrawerActionTile extends StatelessWidget {
  const _DrawerActionTile({
    required this.icon,
    required this.label,
    this.onTap,
    this.color,
    this.isSelected = false,
  });

  final IconData icon;
  final String label;
  final VoidCallback? onTap;
  final Color? color;
  final bool isSelected;

  @override
  Widget build(BuildContext context) {
    final resolvedColor = color ?? AppColors.primaryBlue;

    return InkWell(
      borderRadius: BorderRadius.circular(14),
      onTap: onTap,
      child: Container(
        height: 44,
        padding: const EdgeInsets.symmetric(horizontal: 10),
        decoration: BoxDecoration(
          color: isSelected
              ? resolvedColor.withAlpha((0.10 * 255).round())
              : Colors.transparent,
          borderRadius: BorderRadius.circular(14),
        ),
        child: Row(
          children: [
            SizedBox(
              width: 24,
              child: Icon(icon, color: resolvedColor, size: 18),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                label,
                style: Theme.of(context).textTheme.titleSmall?.copyWith(
                  color: resolvedColor,
                  fontWeight: isSelected ? FontWeight.w700 : FontWeight.w600,
                  letterSpacing: -0.1,
                  height: 1.0,
                ),
              ),
            ),
            Icon(
              Icons.chevron_right_rounded,
              size: 16,
              color: resolvedColor.withAlpha((0.58 * 255).round()),
            ),
          ],
        ),
      ),
    );
  }
}

class _NavItem {
  const _NavItem({
    required this.icon,
    required this.label,
    required this.route,
  });

  final IconData icon;
  final String label;
  final String route;
}

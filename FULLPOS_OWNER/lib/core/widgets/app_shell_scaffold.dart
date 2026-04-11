import 'package:flutter/material.dart';

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
    label: 'Configuraciones',
    route: '/settings',
  );

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      backgroundColor: theme.scaffoldBackgroundColor,
      appBar:
          appBar ??
          AppBar(
            toolbarHeight: 52,
            elevation: 0,
            scrolledUnderElevation: 1,
            surfaceTintColor: Colors.transparent,
            backgroundColor: theme.colorScheme.surface,
            title: Text(
              title,
              style: const TextStyle(fontWeight: FontWeight.w700),
            ),
            centerTitle: false,
          ),
      drawer: Drawer(
        backgroundColor: theme.colorScheme.surface,
        surfaceTintColor: Colors.transparent,
        child: SafeArea(
          child: DecoratedBox(
            decoration: const BoxDecoration(
              gradient: LinearGradient(
                colors: [Color(0xFFE5E7EB), Color(0xFFF8FAFC), Color(0xFFFFFFFF)],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
                stops: [0.0, 0.45, 1.0],
              ),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(22, 20, 22, 12),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Container(
                        width: 48,
                        height: 3,
                        decoration: BoxDecoration(
                          color: theme.colorScheme.onSurface.withAlpha((0.16 * 255).round()),
                          borderRadius: BorderRadius.circular(999),
                        ),
                      ),
                      const SizedBox(height: 18),
                      Text(
                        companyName.toUpperCase(),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: theme.textTheme.titleMedium?.copyWith(
                          color: const Color(0xFF111827),
                          fontWeight: FontWeight.w700,
                          letterSpacing: -0.1,
                          height: 1.0,
                        ),
                      ),
                      if (username != null && username!.trim().isNotEmpty) ...[
                        const SizedBox(height: 6),
                        Text(
                          username!,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: const Color(0xFF6B7280),
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
                Expanded(
                  child: ListView(
                    padding: const EdgeInsets.fromLTRB(14, 4, 14, 12),
                    children: [
                      ..._mainDrawerRoutes.map(
                        (item) => _DrawerNavTile(
                          item: item,
                          isSelected: _isRouteSelected(currentRoute, item.route),
                          onTap: () => _navigateFromDrawer(context, item.route),
                          emphasize: true,
                        ),
                      ),
                      const SizedBox(height: 14),
                      Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 10),
                        child: Container(
                          height: 1,
                          color: Colors.black.withAlpha((0.08 * 255).round()),
                        ),
                      ),
                      const SizedBox(height: 10),
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
                  padding: const EdgeInsets.fromLTRB(18, 8, 18, 18),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 10,
                          vertical: 8,
                        ),
                        decoration: BoxDecoration(
                          gradient: const LinearGradient(
                            colors: [
                              Color(0xFFFFFFFF),
                              Color(0xFFF1F5F9),
                            ],
                            begin: Alignment.topLeft,
                            end: Alignment.bottomRight,
                          ),
                          borderRadius: BorderRadius.circular(22),
                          border: Border.all(
                            color: theme.colorScheme.outlineVariant,
                          ),
                          boxShadow: [
                            BoxShadow(
                              color: Colors.black.withAlpha((0.05 * 255).round()),
                              blurRadius: 18,
                              offset: const Offset(0, 6),
                            ),
                          ],
                        ),
                        child: Row(
                          children: [
                            Expanded(
                              child: _DrawerIconButton(
                                icon: Icons.handyman_rounded,
                                tooltip: 'Configuraciones',
                                isSelected: _isRouteSelected(
                                  currentRoute,
                                  _settingsRoute.route,
                                ),
                                onTap: () => _navigateFromDrawer(
                                  context,
                                  _settingsRoute.route,
                                ),
                              ),
                            ),
                            const SizedBox(width: 10),
                            Expanded(
                              child: _DrawerIconButton(
                                icon: Icons.power_settings_new_rounded,
                                tooltip: 'Cerrar sesión',
                                color: theme.colorScheme.error,
                                onTap: onLogout,
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 10),
                      Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 10),
                        child: Text(
                          version != null ? 'Version $version' : 'Version 1.0.0',
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: const Color(0xFF6B7280),
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
      body: AppBackground(
        child: SafeArea(
          bottom: false,
          child: Padding(
            padding: const EdgeInsets.fromLTRB(14, 14, 14, 18),
            child: body,
          ),
        ),
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
    final selectedColor = theme.colorScheme.primary;
    final textColor = isSelected ? const Color(0xFF0F5BD3) : const Color(0xFF111827);

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: InkWell(
        borderRadius: BorderRadius.circular(18),
        onTap: onTap,
        child: Container(
          padding: EdgeInsets.symmetric(
            horizontal: 12,
            vertical: emphasize ? 12 : 10,
          ),
          decoration: BoxDecoration(
            color: isSelected
                ? const Color(0xFFE9F1FF)
                : Colors.transparent,
            borderRadius: BorderRadius.circular(18),
          ),
          child: Row(
            children: [
              Container(
                width: emphasize ? 36 : 32,
                height: emphasize ? 36 : 32,
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: isSelected
                        ? const [Color(0xFFDCE9FF), Color(0xFFCFE0FF)]
                        : [
                            Colors.white.withAlpha((0.82 * 255).round()),
                            const Color(0xFFF3F6FA),
                          ],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  ),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(
                    color: isSelected
                        ? const Color(0xFFBDD3FF)
                        : Colors.white.withAlpha((0.65 * 255).round()),
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: isSelected
                          ? const Color(0xFF0F5BD3).withAlpha((0.10 * 255).round())
                          : Colors.black.withAlpha((0.03 * 255).round()),
                      blurRadius: 10,
                      offset: const Offset(0, 4),
                    ),
                  ],
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
                  style: (emphasize
                          ? theme.textTheme.titleMedium
                          : theme.textTheme.titleSmall)
                      ?.copyWith(
                        color: textColor,
                        fontWeight: isSelected ? FontWeight.w800 : FontWeight.w600,
                        letterSpacing: -0.1,
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
                  size: 18,
                  color: Colors.black.withAlpha((0.34 * 255).round()),
                ),
            ],
          ),
        ),
      ),
    );
  }
}

class _DrawerIconButton extends StatelessWidget {
  const _DrawerIconButton({
    required this.icon,
    required this.tooltip,
    this.onTap,
    this.color,
    this.isSelected = false,
  });

  final IconData icon;
  final String tooltip;
  final VoidCallback? onTap;
  final Color? color;
  final bool isSelected;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final resolvedColor = color ?? theme.colorScheme.primary;
    return Tooltip(
      message: tooltip,
      child: InkWell(
        borderRadius: BorderRadius.circular(18),
        onTap: onTap,
        child: Container(
          height: 52,
          decoration: BoxDecoration(
            gradient: LinearGradient(
              colors: isSelected
                  ? [
                      resolvedColor.withAlpha((0.16 * 255).round()),
                      resolvedColor.withAlpha((0.08 * 255).round()),
                    ]
                  : [
                      Colors.white.withAlpha((0.78 * 255).round()),
                      const Color(0xFFF3F6FA),
                    ],
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
            ),
            borderRadius: BorderRadius.circular(18),
            border: Border.all(
              color: isSelected
                  ? resolvedColor.withAlpha((0.26 * 255).round())
                  : theme.colorScheme.outlineVariant,
            ),
            boxShadow: [
              BoxShadow(
                color: isSelected
                    ? resolvedColor.withAlpha((0.10 * 255).round())
                    : Colors.black.withAlpha((0.03 * 255).round()),
                blurRadius: 12,
                offset: const Offset(0, 4),
              ),
            ],
          ),
          child: Icon(
            icon,
            color: resolvedColor,
            size: 22,
          ),
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

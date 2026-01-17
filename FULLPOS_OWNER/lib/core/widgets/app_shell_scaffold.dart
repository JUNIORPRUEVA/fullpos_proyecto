import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

class AppShellScaffold extends StatelessWidget {
  const AppShellScaffold({
    super.key,
    required this.child,
    required this.title,
    required this.companyName,
    required this.onLogout,
    required this.currentRoute,
    this.version,
  });

  final Widget child;
  final String title;
  final String companyName;
  final VoidCallback onLogout;
  final String currentRoute;
  final String? version;

  @override
  Widget build(BuildContext context) {
    final isTablet = MediaQuery.of(context).size.width > 900;

    final navItems = [
      _NavItem(icon: Icons.dashboard_outlined, label: 'Dashboard', route: '/dashboard'),
      _NavItem(icon: Icons.inventory_2_outlined, label: 'Productos', route: '/products'),
      _NavItem(icon: Icons.list_alt_outlined, label: 'Ventas', route: '/sales/list'),
      _NavItem(icon: Icons.calendar_today_outlined, label: 'Ventas por día', route: '/sales/by-day'),
      _NavItem(icon: Icons.attach_money_outlined, label: 'Cierres', route: '/cash/closings'),
    ];

    Widget navBuilder() {
      return isTablet
          ? NavigationRail(
              destinations: navItems
                  .map(
                    (item) => NavigationRailDestination(
                      icon: Icon(item.icon),
                      label: Text(item.label),
                    ),
                  )
                  .toList(),
              selectedIndex: navItems.indexWhere((i) => i.route == currentRoute).clamp(0, navItems.length - 1),
              onDestinationSelected: (index) {
                final route = navItems[index].route;
                if (route != currentRoute) context.go(route);
              },
            )
          : Drawer(
              child: SafeArea(
                child: Column(
                  children: [
                    ListTile(
                      title: Text(companyName, style: const TextStyle(fontWeight: FontWeight.w700)),
                      subtitle: Text('FULLPOS Owner', style: TextStyle(color: Colors.grey[600])),
                      trailing: IconButton(
                        icon: const Icon(Icons.logout),
                        onPressed: onLogout,
                      ),
                    ),
                    const Divider(),
                    ...navItems.map(
                      (item) => ListTile(
                        leading: Icon(item.icon),
                        title: Text(item.label),
                        selected: currentRoute == item.route,
                        onTap: () {
                          if (item.route != currentRoute) context.go(item.route);
                          Navigator.of(context).pop();
                        },
                      ),
                    ),
                    const Spacer(),
                    if (version != null)
                      Padding(
                        padding: const EdgeInsets.all(8.0),
                        child: Text('v$version', style: TextStyle(color: Colors.grey[600])),
                      ),
                  ],
                ),
              ),
            );
    }

    return Scaffold(
      appBar: AppBar(
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: const TextStyle(fontWeight: FontWeight.w700)),
            Text(
              companyName,
              style: TextStyle(
                color: Colors.white.withOpacity(0.8),
                fontSize: 12,
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.logout),
            tooltip: 'Cerrar sesión',
            onPressed: onLogout,
          ),
        ],
      ),
      drawer: isTablet ? null : navBuilder(),
      body: Row(
        children: [
          if (isTablet) SizedBox(width: 240, child: navBuilder()),
          Expanded(
            child: Column(
              children: [
                Expanded(child: child),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                  alignment: Alignment.centerRight,
                  child: Text(
                    version != null ? 'FULLPOS Owner ${version!}' : 'FULLPOS Owner',
                    style: TextStyle(color: Colors.white.withOpacity(0.7), fontSize: 12),
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

class _NavItem {
  _NavItem({required this.icon, required this.label, required this.route});
  final IconData icon;
  final String label;
  final String route;
}

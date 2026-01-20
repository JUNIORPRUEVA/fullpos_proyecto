import 'package:flutter/material.dart';

class AppShellScaffold extends StatelessWidget {
  const AppShellScaffold({
    super.key,
    required this.title,
    required this.companyName,
    this.companySubtitle,
    this.username,
    this.version,
    required this.body,
    required this.currentIndex,
    required this.onTabSelected,
    required this.onDrawerNavigate,
    required this.onLogout,
  });

  final String title;
  final String companyName;
  final String? companySubtitle;
  final String? username;
  final String? version;
  final Widget body;
  final int currentIndex;
  final ValueChanged<int> onTabSelected;
  final ValueChanged<String> onDrawerNavigate;
  final VoidCallback onLogout;

  static const _tabItems = [
    _NavItem(
      icon: Icons.inventory_2_outlined,
      label: 'Catalogo',
      route: '/products',
    ),
    _NavItem(
      icon: Icons.payments_outlined,
      label: 'Cortes',
      route: '/cash/closings',
    ),
    _NavItem(
      icon: Icons.query_stats_outlined,
      label: 'Reportes',
      route: '/dashboard',
    ),
  ];

  static const _drawerRoutes = [
    _NavItem(
      icon: Icons.verified_user_outlined,
      label: 'Autorizaciones',
      route: '/overrides',
    ),
    _NavItem(
      icon: Icons.password_outlined,
      label: 'Token virtual',
      route: '/virtual-token',
    ),
    _NavItem(
      icon: Icons.history,
      label: 'Historial de tokens',
      route: '/overrides/audit',
    ),
    _NavItem(
      icon: Icons.list_alt_outlined,
      label: 'Ventas detalladas',
      route: '/sales/list',
    ),
    _NavItem(
      icon: Icons.inventory_2,
      label: 'Inventario',
      route: '/inventory',
    ),
    _NavItem(
      icon: Icons.request_quote_outlined,
      label: 'Cotizaciones',
      route: '/quotes',
    ),
    _NavItem(
      icon: Icons.vpn_key_outlined,
      label: 'Tokens remotos',
      route: '/settings',
    ),
  ];

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      backgroundColor: theme.colorScheme.surface,
      appBar: AppBar(
        title: Text(title, style: const TextStyle(fontWeight: FontWeight.w700)),
        centerTitle: false,
        actions: [
          IconButton(
            icon: const Icon(Icons.more_vert),
            onPressed: () {},
            tooltip: 'Mas opciones',
          ),
        ],
      ),
      drawer: Drawer(
        child: SafeArea(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Container(
                padding: const EdgeInsets.fromLTRB(16, 14, 16, 14),
                decoration: const BoxDecoration(
                  gradient: LinearGradient(
                    colors: [Color(0xFF0F1A2C), Color(0xFF08102D)],
                    begin: Alignment.topCenter,
                    end: Alignment.bottomCenter,
                  ),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Text(
                      companyName.toUpperCase(),
                      style: theme.textTheme.titleMedium?.copyWith(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    if (companySubtitle != null)
                      Padding(
                        padding: const EdgeInsets.only(top: 2),
                        child: Text(
                          companySubtitle!,
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: Colors.white70,
                          ),
                        ),
                      ),
                  ],
                ),
              ),
              const Divider(),
              ..._drawerRoutes.map(
                (item) => ListTile(
                  leading: Icon(item.icon),
                  title: Text(item.label),
                  onTap: () {
                    Navigator.of(context).pop();
                    onDrawerNavigate(item.route);
                  },
                ),
              ),
              const Spacer(),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
                child: Text(
                  version != null ? 'v$version' : 'v1.0.0',
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: Colors.grey[600],
                  ),
                ),
              ),
              ListTile(
                leading: const Icon(Icons.logout),
                title: const Text('Cerrar sesion'),
                onTap: () {
                  Navigator.of(context).pop();
                  onLogout();
                },
              ),
            ],
          ),
        ),
      ),
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            colors: [Color(0xFF0F1A2C), Color(0xFF08102D)],
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
          ),
        ),
        child: SafeArea(
          bottom: false,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 16),
            child: body,
          ),
        ),
      ),
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: currentIndex,
        onTap: onTabSelected,
        type: BottomNavigationBarType.fixed,
        items: _tabItems
            .map(
              (item) => BottomNavigationBarItem(
                icon: Icon(item.icon),
                label: item.label,
              ),
            )
            .toList(),
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

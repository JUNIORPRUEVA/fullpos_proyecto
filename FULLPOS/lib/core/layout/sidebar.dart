import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import '../constants/app_colors.dart';
import '../constants/app_sizes.dart';
import '../session/session_manager.dart';
import '../session/ui_preferences.dart';
import '../window/window_service.dart';
import '../../features/auth/data/auth_repository.dart';
import '../../features/cash/data/cash_repository.dart';
import '../../features/settings/data/user_model.dart';
import '../../features/settings/providers/theme_provider.dart';
import '../../features/settings/providers/business_settings_provider.dart';
import '../../features/products/utils/catalog_pdf_launcher.dart';

/// Sidebar del layout principal con navegación (colapsable)
class Sidebar extends ConsumerStatefulWidget {
  final bool? forcedCollapsed;
  final double? customWidth;

  const Sidebar({
    super.key,
    this.forcedCollapsed,
    this.customWidth,
  });

  @override
  ConsumerState<Sidebar> createState() => _SidebarState();
}

class _SidebarState extends ConsumerState<Sidebar> {
  bool _isCollapsed = false;
  UserPermissions _permissions = UserPermissions.cashier();
  bool _isAdmin = false;

  Future<void> _logout(BuildContext context) async {
    await SessionManager.logout();
    if (context.mounted) {
      context.go('/login');
    }
  }

  Future<void> _handleExitApp(BuildContext context) async {
    final hasOpenCash = await CashRepository.hasOpenSession();
    final shouldExit = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Cerrar aplicación'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('¿Desea cerrar la aplicación?'),
            if (hasOpenCash) ...[
              const SizedBox(height: 8),
              const Text(
                'Tienes una caja abierta. ¿Cerrar la app y dejar la caja abierta o ir a cerrarla?',
                style: TextStyle(fontSize: 13),
              ),
            ],
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancelar'),
          ),
          if (hasOpenCash)
            TextButton(
              onPressed: () {
                Navigator.pop(ctx, false);
                context.go('/cash');
              },
              child: const Text('Ir a cerrar caja'),
            ),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.red.shade600,
            ),
            child: Text(hasOpenCash ? 'Salir (dejar caja abierta)' : 'Salir'),
          ),
        ],
      ),
    );

    if (shouldExit == true) {
      await WindowService.close();
    }
  }

  @override
  void initState() {
    super.initState();
    _isCollapsed = widget.forcedCollapsed ?? _isCollapsed;
    _loadState();
  }

  Future<void> _loadState() async {
    final permissions = await AuthRepository.getCurrentPermissions();
    final isAdmin = await AuthRepository.isAdmin();
    final collapsed =
        widget.forcedCollapsed ?? await UiPreferences.isSidebarCollapsed();
    if (mounted) {
      setState(() {
        _isCollapsed = collapsed;
        _permissions = permissions;
        _isAdmin = isAdmin;
      });
    }
  }

  Future<void> _toggleSidebar() async {
    if (widget.forcedCollapsed != null) {
      if (mounted) setState(() => _isCollapsed = !_isCollapsed);
      return;
    }

    final newState = await UiPreferences.toggleSidebar();
    if (mounted) setState(() => _isCollapsed = newState);
  }

  @override
  Widget build(BuildContext context) {
    final themeSettings = ref.watch(themeProvider);
    final businessSettings = ref.watch(businessSettingsProvider);
    final canCloseApp =
        Platform.isWindows || Platform.isLinux || Platform.isMacOS;
    final logoFile = businessSettings.logoPath != null
        ? File(businessSettings.logoPath!)
        : null;
    final sidebarColor = themeSettings.sidebarColor;
    final sidebarTextColor = themeSettings.sidebarTextColor;
    final sidebarActiveColor = themeSettings.sidebarActiveColor;
    final sidebarGradientEnd =
        Color.lerp(sidebarColor, sidebarActiveColor, 0.28) ?? sidebarColor;
    // Border color: ligeramente más claro que el sidebar
    final borderColor = Color.lerp(sidebarColor, Colors.white, 0.15)!;
    // final dividerColor = borderColor.withValues(alpha: 0.55);

    final targetWidth = widget.customWidth ?? AppSizes.sidebarWidth;

    return AnimatedContainer(
      duration: const Duration(milliseconds: 250),
      curve: Curves.easeInOut,
      width: _isCollapsed ? 72 : targetWidth,
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [sidebarColor, sidebarGradientEnd],
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
        ),
        border: Border(right: BorderSide(color: borderColor, width: 2)),
        boxShadow: const [
          BoxShadow(
            color: Colors.black54,
            blurRadius: 20,
            offset: Offset(6, 8),
          ),
          BoxShadow(
            color: Colors.white24,
            blurRadius: 12,
            offset: Offset(-2, -2),
            spreadRadius: -3,
          ),
        ],
      ),
      child: LayoutBuilder(
        builder: (context, constraints) {
          // Importante: al expandir, el child se construye desde un ancho pequeño
          // (animación de 72 → sidebarWidth). Si renderizamos el layout “expandido”
          // demasiado pronto, puede aparecer un RenderFlex overflow por 1 frame.
          final effectiveCollapsed = _isCollapsed || constraints.maxWidth < 160;

          final toggleTooltip = _isCollapsed
              ? 'Expandir menú'
              : 'Colapsar menú';

          Widget logoImage({required double size}) {
            if (logoFile == null) {
              return Icon(
                Icons.storefront,
                color: sidebarActiveColor,
                size: size * 0.55,
              );
            }

            return Image.file(
              logoFile,
              width: size,
              height: size,
              fit: BoxFit.cover,
              errorBuilder: (context, error, stackTrace) => Icon(
                Icons.storefront,
                color: sidebarActiveColor,
                size: size * 0.55,
              ),
            );
          }

          return Column(
            children: [
              // Logo/Título + botón colapsar
              Container(
                height: AppSizes.topbarHeight,
                padding: const EdgeInsets.symmetric(
                  horizontal: AppSizes.paddingM,
                  vertical: AppSizes.paddingS,
                ),
                decoration: BoxDecoration(
                  border: Border(
                    bottom: BorderSide(color: borderColor, width: 2),
                  ),
                ),
                child: effectiveCollapsed
                    ? Center(
                        child: Tooltip(
                          message: toggleTooltip,
                          child: Material(
                            color: Colors.transparent,
                            shape: CircleBorder(
                              side: BorderSide(
                                color: Colors.white.withValues(alpha: 0.16),
                              ),
                            ),
                            clipBehavior: Clip.antiAlias,
                            child: InkWell(
                              onTap: _toggleSidebar,
                              customBorder: const CircleBorder(),
                              child: SizedBox(
                                width: 40,
                                height: 40,
                                child: Center(
                                  child: logoFile != null
                                      ? Container(
                                          width: 34,
                                          height: 34,
                                          decoration: BoxDecoration(
                                            shape: BoxShape.circle,
                                            border: Border.all(
                                              color: Colors.white.withValues(
                                                alpha: 0.14,
                                              ),
                                            ),
                                          ),
                                          child: ClipOval(
                                            child: logoImage(size: 34),
                                          ),
                                        )
                                      : Icon(
                                          _isCollapsed
                                              ? Icons.menu
                                              : Icons.menu_open,
                                          color: sidebarActiveColor,
                                          size: 18,
                                        ),
                                ),
                              ),
                            ),
                          ),
                        ),
                      )
                    : Row(
                        children: [
                          Container(
                            width: 38,
                            height: 38,
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              border: Border.all(
                                color: Colors.white.withValues(alpha: 0.14),
                              ),
                              color: Colors.white.withValues(alpha: 0.06),
                            ),
                            child: ClipOval(child: logoImage(size: 38)),
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Column(
                              mainAxisAlignment: MainAxisAlignment.center,
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  businessSettings.businessName.isNotEmpty
                                      ? businessSettings.businessName
                                      : 'FULLPOS',
                                  style: TextStyle(
                                    color: sidebarActiveColor,
                                    fontSize: 14,
                                    fontWeight: FontWeight.bold,
                                    letterSpacing: 0.6,
                                  ),
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                  softWrap: false,
                                ),
                                const SizedBox(height: 2),
                                Text(
                                  'Sistema POS',
                                  style: TextStyle(
                                    color: sidebarTextColor.withValues(
                                      alpha: 0.72,
                                    ),
                                    fontSize: 11.5,
                                    fontWeight: FontWeight.w500,
                                    letterSpacing: 0.3,
                                  ),
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                  softWrap: false,
                                ),
                              ],
                            ),
                          ),
                          SizedBox(
                            width: 36,
                            height: 36,
                            child: IconButton(
                              icon: Icon(
                                Icons.chevron_left,
                                color: sidebarTextColor.withValues(alpha: 0.9),
                                size: 18,
                              ),
                              padding: EdgeInsets.zero,
                              onPressed: _toggleSidebar,
                              tooltip: 'Colapsar menú',
                            ),
                          ),
                        ],
                      ),
              ),

              // Menú de navegación con verificación de permisos
              Expanded(
                child: Column(
                  children: [
                    Expanded(
                      child: ListView(
                        padding: const EdgeInsets.symmetric(
                          vertical: AppSizes.paddingM,
                        ),
                        children: [
                          // Ventas - siempre visible si puede vender
                          if (_isAdmin || _permissions.canSell)
                            PremiumNavItem(
                              icon: Icons.shopping_cart,
                              title: 'Ventas',
                              route: '/sales',
                              isCollapsed: effectiveCollapsed,
                              textColor: sidebarTextColor,
                              activeColor: sidebarActiveColor,
                            ),
                          // Catálogo - visible si puede ver productos
                          if (_isAdmin || _permissions.canViewProducts)
                            PremiumNavItem(
                              icon: Icons.inventory_2,
                              title: 'Catálogo',
                              route: '/products',
                              isCollapsed: effectiveCollapsed,
                              textColor: sidebarTextColor,
                              activeColor: sidebarActiveColor,
                            ),
                          // Clientes - visible si puede ver clientes
                          if (_isAdmin || _permissions.canViewClients)
                            PremiumNavItem(
                              icon: Icons.people,
                              title: 'Clientes',
                              route: '/clients',
                              isCollapsed: effectiveCollapsed,
                              textColor: sidebarTextColor,
                              activeColor: sidebarActiveColor,
                            ),
                          // Préstamos - visible si puede ver préstamos
                          if (_isAdmin || _permissions.canViewLoans)
                            PremiumNavItem(
                              icon: Icons.handshake,
                              title: 'Préstamos',
                              route: '/loans',
                              isCollapsed: effectiveCollapsed,
                              textColor: sidebarTextColor,
                              activeColor: sidebarActiveColor,
                            ),
                          // Reportes - visible si puede ver reportes
                          if (_isAdmin || _permissions.canViewReports)
                            PremiumNavItem(
                              icon: Icons.bar_chart,
                              title: 'Reportes',
                              route: '/reports',
                              isCollapsed: effectiveCollapsed,
                              textColor: sidebarTextColor,
                              activeColor: sidebarActiveColor,
                            ),

                          // Compras / Órdenes de compra - visible si puede ajustar stock
                          if (_isAdmin || _permissions.canAdjustStock)
                            PremiumNavItem(
                              icon: Icons.shopping_bag_outlined,
                              title: 'Compras',
                              route: '/purchases',
                              isCollapsed: effectiveCollapsed,
                              textColor: sidebarTextColor,
                              activeColor: sidebarActiveColor,
                            ),
                        ],
                      ),
                    ),
                    if (_isAdmin || _permissions.canViewProducts)
                      Padding(
                        padding: const EdgeInsets.symmetric(
                          horizontal: AppSizes.paddingS,
                          vertical: AppSizes.paddingS,
                        ),
                        child: Container(
                          height: 1,
                          decoration: BoxDecoration(
                            gradient: LinearGradient(
                              colors: [
                                Colors.white.withValues(alpha: 0.0),
                                Colors.white.withValues(alpha: 0.25),
                                Colors.white.withValues(alpha: 0.0),
                              ],
                            ),
                          ),
                        ),
                      ),
                    if (_isAdmin || _permissions.canViewProducts)
                      Padding(
                        padding: const EdgeInsets.symmetric(
                          horizontal: AppSizes.paddingS,
                          vertical: AppSizes.paddingXS,
                        ),
                        child: PremiumNavItem(
                          icon: Icons.picture_as_pdf,
                          title: 'Catálogo PDF',
                          route: null,
                          onTap: () =>
                              CatalogPdfLauncher.openFromSidebar(context),
                          isCollapsed: effectiveCollapsed,
                          textColor: sidebarTextColor,
                          activeColor: sidebarActiveColor,
                        ),
                      ),
                    if (_isAdmin || _permissions.canAccessTools)
                      Padding(
                        padding: const EdgeInsets.symmetric(
                          horizontal: AppSizes.paddingS,
                          vertical: AppSizes.paddingXS,
                        ),
                        child: PremiumNavItem(
                          icon: Icons.construction,
                          title: 'Herramientas',
                          route: '/tools',
                          isCollapsed: effectiveCollapsed,
                          textColor: sidebarTextColor,
                          activeColor: sidebarActiveColor,
                        ),
                      ),
                    const SizedBox(height: AppSizes.spaceXL * 2),
                  ],
                ),
              ),

              // Botones de salida
              Padding(
                padding: EdgeInsets.all(
                  effectiveCollapsed ? AppSizes.paddingS : AppSizes.paddingM,
                ),
                child: Builder(
                  builder: (context) {
                    Widget actionSquare({
                      required String tooltip,
                      required IconData icon,
                      required VoidCallback onTap,
                      required Color fg,
                      required Color bg,
                      BorderSide? border,
                      double? sizeOverride,
                    }) {
                      final size =
                          sizeOverride ?? (effectiveCollapsed ? 40.0 : 44.0);
                      return Tooltip(
                        message: tooltip,
                        child: SizedBox(
                          width: size,
                          height: size,
                          child: Material(
                            color: bg,
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(12),
                              side: border ?? BorderSide.none,
                            ),
                            child: InkWell(
                              onTap: onTap,
                              borderRadius: BorderRadius.circular(12),
                              child: Icon(icon, color: fg, size: 20),
                            ),
                          ),
                        ),
                      );
                    }

                    final homeBtn = actionSquare(
                      tooltip: 'Minimizar a la barra de tareas',
                      icon: Icons.home_outlined,
                      onTap: () => WindowService.minimize(),
                      fg: AppColors.textLight,
                      bg: const Color(0xFF0E3A57),
                      border: BorderSide(
                        color: Colors.white.withValues(alpha: 0.18),
                      ),
                      sizeOverride: effectiveCollapsed ? 40.0 : 44.0,
                    );

                    final closeBtn = actionSquare(
                      tooltip: 'Cerrar aplicación',
                      icon: Icons.power_settings_new,
                      onTap: () => _handleExitApp(context),
                      fg: AppColors.textLight,
                      bg: const Color(0xFF0B523A),
                      border: BorderSide(
                        color: Colors.white.withValues(alpha: 0.18),
                      ),
                      sizeOverride: effectiveCollapsed ? 40.0 : 44.0,
                    );

                    final logoutBtn = actionSquare(
                      tooltip: 'Cerrar sesión',
                      icon: Icons.logout,
                      onTap: () => _logout(context),
                      fg: AppColors.textLight,
                      bg: const Color(0xFFB1202C),
                      border: BorderSide(
                        color: Colors.white.withValues(alpha: 0.14),
                      ),
                      sizeOverride: effectiveCollapsed ? 40.0 : 44.0,
                    );

                    if (effectiveCollapsed) {
                      return Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          homeBtn,
                          const SizedBox(height: AppSizes.spaceS),
                          if (canCloseApp) closeBtn,
                          if (canCloseApp)
                            const SizedBox(height: AppSizes.spaceS),
                          logoutBtn,
                        ],
                      );
                    }

                    return Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        homeBtn,
                        const SizedBox(width: AppSizes.spaceS),
                        if (canCloseApp) closeBtn,
                        if (canCloseApp) const SizedBox(width: AppSizes.spaceS),
                        logoutBtn,
                      ],
                    );
                  },
                ),
              ),
            ],
          );
        },
      ),
    );
  }
}

/// Item de navegación del sidebar (premium + hover/selected)
class PremiumNavItem extends StatefulWidget {
  final IconData icon;
  final String title;
  final String? route;
  final VoidCallback? onTap;
  final bool isCollapsed;
  final Color textColor;
  final Color activeColor;

  const PremiumNavItem({
    super.key,
    required this.icon,
    required this.title,
    required this.route,
    this.onTap,
    required this.isCollapsed,
    required this.textColor,
    required this.activeColor,
  });

  @override
  State<PremiumNavItem> createState() => _PremiumNavItemState();
}

class _PremiumNavItemState extends State<PremiumNavItem> {
  bool _isHover = false;

  String _safeCurrentPath(BuildContext context) {
    // En algunas pantallas (p.ej. previews PDF abiertas con Navigator/Dialogs),
    // no existe GoRouterState en el árbol y GoRouterState.of(context) lanza.
    try {
      return GoRouterState.of(context).uri.path;
    } catch (_) {
      // ignore
    }

    try {
      final router = GoRouter.of(context);
      // go_router 14 + Flutter reciente expone RouteInformation.uri.
      final routeInfo = router.routeInformationProvider.value;
      return routeInfo.uri.path;
    } catch (_) {
      // ignore
    }

    return '';
  }

  @override
  Widget build(BuildContext context) {
    final currentRoute = _safeCurrentPath(context);
    final isActive = widget.route != null && currentRoute == widget.route;
    final isEnabled = widget.onTap != null || widget.route != null;

    const duration = Duration(milliseconds: 180);
    final pillRadius = BorderRadius.circular(16);

    final fgColor = isActive
        ? Colors.white.withValues(alpha: 0.96)
        : widget.textColor;
    final iconColor = isActive ? widget.activeColor : widget.textColor;

    final item = Padding(
      padding: EdgeInsets.symmetric(
        horizontal: widget.isCollapsed ? 6 : 12,
        vertical: 4,
      ),
      child: Material(
        color: Colors.transparent,
        shape: RoundedRectangleBorder(borderRadius: pillRadius),
        clipBehavior: Clip.antiAlias,
        child: MouseRegion(
          cursor: isEnabled
              ? SystemMouseCursors.click
              : SystemMouseCursors.basic,
          onEnter: (_) => setState(() => _isHover = true),
          onExit: (_) => setState(() => _isHover = false),
          child: InkWell(
            onTap:
                widget.onTap ??
                (widget.route == null ? null : () => context.go(widget.route!)),
            borderRadius: pillRadius,
            child: AnimatedContainer(
              duration: duration,
              curve: Curves.easeOut,
              padding: EdgeInsets.symmetric(
                horizontal: widget.isCollapsed ? 0 : 14,
                vertical: widget.isCollapsed ? 10 : 12,
              ),
              decoration: BoxDecoration(
                gradient: isActive
                    ? LinearGradient(
                        colors: [
                          widget.activeColor.withValues(alpha: 0.95),
                          widget.activeColor.withValues(alpha: 0.70),
                        ],
                        begin: Alignment.topLeft,
                        end: Alignment.bottomRight,
                      )
                    : (_isHover
                          ? const LinearGradient(
                              colors: [Color(0xFF123D5C), Color(0xFF0F2F48)],
                              begin: Alignment.topLeft,
                              end: Alignment.bottomRight,
                            )
                          : null),
                color: isActive || _isHover
                    ? null
                    : Colors.white.withValues(alpha: 0.04),
                borderRadius: pillRadius,
                border: Border.all(
                  color: isActive
                      ? Colors.white.withValues(alpha: 0.45)
                      : Colors.white.withValues(alpha: 0.08),
                  width: 1.2,
                ),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withOpacity(isActive ? 0.35 : 0.2),
                    blurRadius: isActive ? 14 : 10,
                    offset: const Offset(0, 6),
                  ),
                ],
              ),
              child: widget.isCollapsed
                  ? SizedBox(
                      height: 44,
                      child: Row(
                        children: [
                          Padding(
                            padding: const EdgeInsets.symmetric(vertical: 6),
                            child: AnimatedContainer(
                              duration: duration,
                              curve: Curves.easeOut,
                              width: 4,
                              decoration: BoxDecoration(
                                color: isActive
                                    ? Colors.white
                                    : Colors.transparent,
                                borderRadius: BorderRadius.circular(4),
                              ),
                            ),
                          ),
                          Expanded(
                            child: Center(
                              child: Icon(
                                widget.icon,
                                color: iconColor,
                                size: 22,
                              ),
                            ),
                          ),
                        ],
                      ),
                    )
                  : Row(
                      children: [
                        Icon(widget.icon, color: iconColor, size: 21),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Text(
                            widget.title,
                            style: TextStyle(
                              color: fgColor,
                              fontSize: 14.5,
                              fontWeight: isActive
                                  ? FontWeight.w800
                                  : FontWeight.w600,
                            ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            softWrap: false,
                          ),
                        ),
                        const Icon(
                          Icons.chevron_right,
                          size: 16,
                          color: Colors.white70,
                        ),
                      ],
                    ),
            ),
          ),
        ),
      ),
    );

    // Si está colapsado, envolver en Tooltip
    if (widget.isCollapsed) {
      return Tooltip(
        message: widget.title,
        preferBelow: false,
        verticalOffset: 8,
        child: item,
      );
    }

    return item;
  }
}

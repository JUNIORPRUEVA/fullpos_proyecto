import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import '../constants/app_sizes.dart';
import '../utils/date_time_formatter.dart';
import '../session/session_manager.dart';
import '../../features/auth/data/auth_repository.dart';
import '../../features/cash/data/cash_repository.dart';
import '../../features/cash/ui/cash_open_dialog.dart';
import '../../features/cash/ui/cash_panel_sheet.dart';
import '../../features/settings/providers/theme_provider.dart';

/// Topbar del layout principal con fecha/hora y usuario
class Topbar extends ConsumerStatefulWidget {
  final bool showMenuButton;
  final VoidCallback? onMenuPressed;

  const Topbar({super.key, this.showMenuButton = false, this.onMenuPressed});

  @override
  ConsumerState<Topbar> createState() => _TopbarState();
}

class _TopbarState extends ConsumerState<Topbar> {
  late Timer _timer;
  // ignore: unused_field
  late Timer _cashTimer;
  StreamSubscription<void>? _sessionSub;
  DateTime _currentTime = DateTime.now();
  String? _username;
  String? _displayName;

  bool _canAccessCash = false;
  // ignore: unused_field
  int? _openCashSessionId;

  @override
  void initState() {
    super.initState();
    _loadUserSummary();
    _sessionSub = SessionManager.changes.listen((_) {
      if (!mounted) return;
      _loadUserSummary();
    });
    _loadCashAccess();
    _loadOpenCashSessionId();
    // Actualizar cada segundo
    _timer = Timer.periodic(const Duration(seconds: 1), (timer) {
      if (mounted) {
        setState(() {
          _currentTime = DateTime.now();
        });
      }
    });

    // Refrescar estado de caja sin recargar la UI completa (cada 10s)
    _cashTimer = Timer.periodic(const Duration(seconds: 10), (_) {
      _loadOpenCashSessionId();
    });
  }

  @override
  void dispose() {
    _timer.cancel();
    _cashTimer.cancel();
    _sessionSub?.cancel();
    super.dispose();
  }

  Future<void> _loadUserSummary() async {
    final username = await SessionManager.username();
    final displayName = await SessionManager.displayName();
    final role = await SessionManager.role();

    if (!mounted) return;
    setState(() {
      _username = username ?? 'Usuario';
      _displayName = (displayName != null && displayName.trim().isNotEmpty)
          ? displayName.trim()
          : null;
    });
  }

  Future<void> _loadCashAccess() async {
    try {
      final perms = await AuthRepository.getCurrentPermissions();
      final isAdmin = await AuthRepository.isAdmin();
      final allowed = isAdmin || perms.canOpenCash || perms.canCloseCash;
      if (mounted) {
        setState(() => _canAccessCash = allowed);
      }
    } catch (_) {
      if (mounted) setState(() => _canAccessCash = false);
    }
  }

  Future<void> _loadOpenCashSessionId() async {
    try {
      final id = await CashRepository.getCurrentSessionId();
      if (mounted) setState(() => _openCashSessionId = id);
    } catch (_) {
      // Si falla, no bloquear la UI
    }
  }

  // ignore: unused_element
  Future<void> _onCashPressed() async {
    // Re-validar estado al momento del click
    final sessionId = await CashRepository.getCurrentSessionId();

    if (!mounted) return;

    if (sessionId != null) {
      await CashPanelSheet.show(context, sessionId: sessionId);
      await _loadOpenCashSessionId();
      return;
    }

    final opened = await CashOpenDialog.show(context);

    if (!mounted) return;
    if (opened == true) {
      final newSessionId = await CashRepository.getCurrentSessionId();

      if (!mounted) return;
      if (newSessionId != null) {
        await CashPanelSheet.show(context, sessionId: newSessionId);
      }
      await _loadOpenCashSessionId();
    }
  }

  Future<void> _logout(BuildContext context) async {
    await SessionManager.logout();
    if (context.mounted) {
      context.go('/login');
    }
  }

  @override
  Widget build(BuildContext context) {
    final settings = ref.watch(themeProvider);
    final scheme = Theme.of(context).colorScheme;
    final appBarBg = settings.appBarColor;
    final appBarFg = settings.appBarTextColor;

    return LayoutBuilder(
      builder: (context, constraints) {
        final isCompact = constraints.maxWidth < 900;

        Widget cashControl() {
          // Botón movido a la pantalla de ventas
          return const SizedBox.shrink();
        }

        Widget userControl() {
          final userLabel = (_displayName ?? _username ?? 'Usuario').trim();
          return Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              PopupMenuButton<String>(
                tooltip: 'Cuenta y configuración',
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(AppSizes.radiusM),
                ),
                onSelected: (value) {
                  if (value == 'account') {
                    context.go('/account');
                  } else if (value == 'settings') {
                    context.go('/settings');
                  }
                },
                itemBuilder: (_) => [
                  PopupMenuItem<String>(
                    value: 'account',
                    child: Row(
                      children: const [
                        Icon(Icons.person_outline),
                        SizedBox(width: 8),
                        Text('Usuario'),
                      ],
                    ),
                  ),
                  PopupMenuItem<String>(
                    value: 'settings',
                    child: Row(
                      children: const [
                        Icon(Icons.settings_outlined),
                        SizedBox(width: 8),
                        Text('Configuración'),
                      ],
                    ),
                  ),
                ],
                child: Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: AppSizes.paddingM,
                    vertical: AppSizes.paddingS,
                  ),
                  decoration: BoxDecoration(
                    color: scheme.secondary.withOpacity(0.15),
                    borderRadius: BorderRadius.circular(AppSizes.radiusM),
                    border: Border.all(color: scheme.secondary, width: 1),
                    boxShadow: [
                      BoxShadow(
                        color: Colors.black.withOpacity(0.1),
                        blurRadius: 10,
                        offset: const Offset(0, 4),
                      ),
                    ],
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Container(
                        width: 8,
                        height: 8,
                        decoration: BoxDecoration(
                          color: settings.successColor,
                          shape: BoxShape.circle,
                        ),
                      ),
                      const SizedBox(width: AppSizes.spaceS),
                      Icon(Icons.person, size: 18, color: scheme.secondary),
                      const SizedBox(width: AppSizes.spaceS),
                      Icon(
                        Icons.settings_outlined,
                        color: scheme.secondary.withOpacity(0.7),
                        size: 16,
                      ),
                      const SizedBox(width: AppSizes.spaceS),
                      if (!isCompact)
                        Text(
                          userLabel.isNotEmpty ? userLabel : 'Usuario',
                          style: TextStyle(
                            color: scheme.secondary,
                            fontSize: 13,
                            fontWeight: FontWeight.w700,
                            fontFamily: settings.fontFamily,
                            height: 1.1,
                          ),
                        ),
                      const SizedBox(width: AppSizes.spaceS),
                      Icon(
                        Icons.keyboard_arrow_down_rounded,
                        color: scheme.secondary,
                        size: 18,
                      ),
                    ],
                  ),
                ),
              ),
            ],
          );
        }

        Widget dateTimeChip() {
          if (isCompact) return const SizedBox.shrink();
          return Container(
            padding: const EdgeInsets.symmetric(
              horizontal: AppSizes.paddingM,
              vertical: AppSizes.paddingS,
            ),
            decoration: BoxDecoration(
              color: scheme.primary.withOpacity(0.25),
              borderRadius: BorderRadius.circular(AppSizes.radiusM),
              border: Border.all(
                color: scheme.secondary.withOpacity(0.35),
                width: 1,
              ),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.access_time, size: 18, color: scheme.secondary),
                const SizedBox(width: AppSizes.spaceS),
                Text(
                  DateTimeFormatter.formatFullDateTime(_currentTime),
                  style: TextStyle(
                    color: appBarFg,
                    fontSize: 13,
                    fontWeight: FontWeight.w500,
                    fontFamily: settings.fontFamily,
                  ),
                ),
              ],
            ),
          );
        }

        return Container(
          height: AppSizes.topbarHeight,
          decoration: BoxDecoration(
            color: appBarBg,
            border: Border(
              bottom: BorderSide(
                color: scheme.primary.withOpacity(0.35),
                width: 2,
              ),
            ),
            boxShadow: const [
              BoxShadow(
                color: Colors.black26,
                blurRadius: 12,
                offset: Offset(0, 4),
              ),
              BoxShadow(
                color: Colors.white24,
                blurRadius: 8,
                offset: Offset(0, -2),
                spreadRadius: -1,
              ),
            ],
          ),
          padding: EdgeInsets.symmetric(
            horizontal: isCompact ? AppSizes.paddingM : AppSizes.paddingL,
          ),
          child: Row(
            children: [
              if (widget.showMenuButton) ...[
                IconButton(
                  onPressed: widget.onMenuPressed,
                  tooltip: 'Menú',
                  icon: Icon(Icons.menu, color: appBarFg),
                ),
                const SizedBox(width: AppSizes.spaceS),
              ],
              Expanded(
                child: Text(
                  'CENTRO DE OPERACIONES',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: appBarFg,
                    fontSize: isCompact ? 18 : 20,
                    fontWeight: FontWeight.bold,
                    fontFamily: settings.fontFamily,
                  ),
                ),
              ),
              if (_canAccessCash) ...[
                const SizedBox(width: AppSizes.spaceS),
                cashControl(),
                const SizedBox(width: AppSizes.spaceM),
              ],
              if (!isCompact) ...[
                dateTimeChip(),
                const SizedBox(width: AppSizes.spaceM),
              ],
              userControl(),
            ],
          ),
        );
      },
    );
  }
}


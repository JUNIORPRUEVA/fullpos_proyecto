import 'dart:async';
import 'dart:io' show Platform;
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../constants/app_sizes.dart';
import '../utils/date_time_formatter.dart';
import '../window/window_service.dart';
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
  late Timer _cashTimer;
  StreamSubscription<void>? _sessionSub;
  DateTime _currentTime = DateTime.now();
  String? _username;
  String? _displayName;
  String? _roleLabel;

  bool _canAccessCash = false;
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

    String? roleLabel;
    if (role == 'admin') {
      roleLabel = 'Administrador';
    } else if (role == 'cashier') {
      roleLabel = 'Cajero';
    } else if (role != null && role.trim().isNotEmpty) {
      roleLabel = role;
    }

    if (!mounted) return;
    setState(() {
      _username = username ?? 'Usuario';
      _displayName = (displayName != null && displayName.trim().isNotEmpty)
          ? displayName.trim()
          : null;
      _roleLabel = roleLabel;
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

  Widget _buildCashButton() {
    final isOpen = _openCashSessionId != null;
    final settings = ref.watch(themeProvider);
    final scheme = Theme.of(context).colorScheme;
    final success = settings.successColor;
    final error = settings.errorColor;
    final statusColor = isOpen ? success : error;
    final statusTextColor = Colors.black;
    final statusBgColor = Colors.white;

    return SizedBox(
      height: 36,
      child: ElevatedButton.icon(
        onPressed: _onCashPressed,
        style: ElevatedButton.styleFrom(
          backgroundColor: scheme.secondary,
          foregroundColor: Theme.of(context).colorScheme.onSecondary,
          elevation: 4,
          padding: const EdgeInsets.symmetric(horizontal: 14),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
        ),
        icon: const Icon(Icons.point_of_sale, size: 18),
        label: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('Caja', style: TextStyle(fontWeight: FontWeight.bold)),
            const SizedBox(width: 10),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(
                color: statusBgColor,
                borderRadius: BorderRadius.circular(999),
                border: Border.all(
                  color: statusColor.withOpacity(0.95),
                  width: 1.2,
                ),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    isOpen ? Icons.lock_open : Icons.lock,
                    size: 14,
                    color: statusColor,
                  ),
                  const SizedBox(width: 6),
                  Text(
                    isOpen ? 'Abierta' : 'Cerrada',
                    style: TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w900,
                      color: statusTextColor,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
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
          if (!isCompact) {
            return Container(
              padding: const EdgeInsets.symmetric(
                horizontal: AppSizes.paddingM,
                vertical: AppSizes.paddingS,
              ),
              decoration: BoxDecoration(
                color: scheme.secondary.withOpacity(0.15),
                borderRadius: BorderRadius.circular(AppSizes.radiusM),
                border: Border.all(color: scheme.secondary, width: 1),
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
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        _displayName ?? _username ?? 'Cargando...',
                        style: TextStyle(
                          color: scheme.secondary,
                          fontSize: 13,
                          fontWeight: FontWeight.w700,
                          fontFamily: settings.fontFamily,
                          height: 1.1,
                        ),
                      ),
                      if (_roleLabel != null) ...[
                        const SizedBox(height: 2),
                        Text(
                          _roleLabel!,
                          style: TextStyle(
                            color: scheme.secondary.withOpacity(0.90),
                            fontSize: 11,
                            fontWeight: FontWeight.w700,
                            fontFamily: settings.fontFamily,
                            height: 1.1,
                          ),
                        ),
                      ],
                    ],
                  ),
                ],
              ),
            );
          }

          final userLabel = (_displayName ?? _username ?? 'Usuario').trim();
          return Tooltip(
            message: userLabel.isNotEmpty ? userLabel : 'Usuario',
            child: Icon(Icons.person, color: scheme.secondary),
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

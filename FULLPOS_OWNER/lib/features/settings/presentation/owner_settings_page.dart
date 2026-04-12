import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../core/realtime/company_realtime_service.dart';
import '../../../core/providers/sync_request_provider.dart';
import '../../../core/providers/theme_provider.dart';
import '../../auth/data/auth_repository.dart';
import '../../products/data/product_realtime_service.dart';
import '../../reports/data/sale_realtime_service.dart';

class OwnerSettingsPage extends ConsumerStatefulWidget {
  const OwnerSettingsPage({super.key});

  @override
  ConsumerState<OwnerSettingsPage> createState() => _OwnerSettingsPageState();
}

class _OwnerSettingsPageState extends ConsumerState<OwnerSettingsPage> {
  bool _refreshingData = false;
  bool _refreshingSession = false;

  Future<void> _setThemeMode(ThemeMode mode) async {
    await ref.read(themeModeProvider.notifier).setThemeMode(mode);
  }

  Future<void> _refreshAllData() async {
    if (_refreshingData) return;
    setState(() => _refreshingData = true);

    try {
      ref.read(syncRequestProvider.notifier).syncFullApp();
      final authState = ref.read(authRepositoryProvider);
      await Future.wait<void>([
        ref.read(companyRealtimeServiceProvider).connect(authState),
        ref.read(productRealtimeServiceProvider).connect(authState),
        ref.read(saleRealtimeServiceProvider).connect(authState),
      ]);
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Datos actualizados y conexiones reanudadas.'),
        ),
      );
    } finally {
      if (mounted) {
        setState(() => _refreshingData = false);
      }
    }
  }

  Future<void> _refreshSession() async {
    if (_refreshingSession) return;
    setState(() => _refreshingSession = true);

    try {
      await ref.read(authRepositoryProvider.notifier).me();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Sesión verificada correctamente.')),
      );
    } finally {
      if (mounted) {
        setState(() => _refreshingSession = false);
      }
    }
  }

  Future<void> _logout() async {
    await ref.read(authRepositoryProvider.notifier).logout();
    if (!mounted) return;
    context.go('/login');
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final authState = ref.watch(authRepositoryProvider);
    final themeMode = ref.watch(themeModeProvider);
    final companyRealtime = ref.read(companyRealtimeServiceProvider);
    final productRealtime = ref.read(productRealtimeServiceProvider);
    final saleRealtime = ref.read(saleRealtimeServiceProvider);

    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 28),
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 920),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              _SettingsHeroCard(
                companyName: authState.companyName ?? 'FULLPOS Owner',
                username:
                    authState.displayName ?? authState.username ?? 'Usuario',
                version: authState.ownerVersion ?? '1.0.0',
              ),
              const SizedBox(height: 16),
              _SettingsSection(
                title: 'Apariencia',
                child: Column(
                  children: [
                    _ThemeModeTile(
                      title: 'Modo claro',
                      icon: Icons.light_mode_rounded,
                      selected: themeMode == ThemeMode.light,
                      onTap: () => _setThemeMode(ThemeMode.light),
                    ),
                    const SizedBox(height: 10),
                    _ThemeModeTile(
                      title: 'Modo oscuro',
                      icon: Icons.dark_mode_rounded,
                      selected: themeMode == ThemeMode.dark,
                      onTap: () => _setThemeMode(ThemeMode.dark),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              _SettingsSection(
                title: 'Datos y sincronización',
                child: Column(
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: _InfoStatCard(
                            label: 'Global realtime',
                            value: companyRealtime.connectionState,
                            emphasized:
                                companyRealtime.connectionState == 'connected',
                          ),
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: _InfoStatCard(
                            label: 'Productos realtime',
                            value: productRealtime.connectionState,
                            emphasized:
                                productRealtime.connectionState == 'connected',
                          ),
                        ),
                        Expanded(
                          child: _InfoStatCard(
                            label: 'Ventas realtime',
                            value: saleRealtime.connectionState,
                            emphasized:
                                saleRealtime.connectionState == 'connected',
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 14),
                    Row(
                      children: [
                        Expanded(
                          child: FilledButton.icon(
                            onPressed: _refreshingData ? null : _refreshAllData,
                            icon: const Icon(Icons.sync_rounded),
                            label: Text(
                              _refreshingData
                                  ? 'Actualizando...'
                                  : 'Actualizar datos',
                            ),
                          ),
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: OutlinedButton.icon(
                            onPressed: _refreshingSession
                                ? null
                                : _refreshSession,
                            icon: const Icon(Icons.verified_user_outlined),
                            label: Text(
                              _refreshingSession
                                  ? 'Verificando...'
                                  : 'Verificar sesión',
                            ),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              _SettingsSection(
                title: 'Cuenta y empresa',
                child: Column(
                  children: [
                    _InfoRow(
                      label: 'Empresa',
                      value: authState.companyName ?? 'No disponible',
                    ),
                    _InfoRow(
                      label: 'Usuario',
                      value: authState.username ?? 'No disponible',
                    ),
                    _InfoRow(
                      label: 'Nombre',
                      value: authState.displayName ?? 'No disponible',
                    ),
                    _InfoRow(
                      label: 'Correo',
                      value: authState.email ?? 'No disponible',
                    ),
                    _InfoRow(
                      label: 'RNC',
                      value: authState.companyRnc ?? 'No disponible',
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              _SettingsSection(
                title: 'Seguridad',
                child: Column(
                  children: [
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(14),
                      decoration: BoxDecoration(
                        color: scheme.errorContainer.withAlpha(
                          (0.45 * 255).round(),
                        ),
                        borderRadius: BorderRadius.circular(18),
                        border: Border.all(
                          color: scheme.error.withAlpha((0.20 * 255).round()),
                        ),
                      ),
                      child: Row(
                        children: [
                          Icon(Icons.lock_outline_rounded, color: scheme.error),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Text(
                              'Cierra la sesión al terminar de usar este dispositivo.',
                              style: theme.textTheme.bodyMedium?.copyWith(
                                color: scheme.onSurface,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 14),
                    SizedBox(
                      width: double.infinity,
                      child: OutlinedButton.icon(
                        onPressed: _logout,
                        icon: const Icon(Icons.logout_rounded),
                        label: const Text('Cerrar sesión'),
                        style: OutlinedButton.styleFrom(
                          foregroundColor: scheme.error,
                          side: BorderSide(
                            color: scheme.error.withAlpha((0.35 * 255).round()),
                          ),
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
    );
  }
}

class _SettingsHeroCard extends StatelessWidget {
  const _SettingsHeroCard({
    required this.companyName,
    required this.username,
    required this.version,
  });

  final String companyName;
  final String username;
  final String version;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [
            scheme.primary.withAlpha((0.18 * 255).round()),
            scheme.secondary.withAlpha((0.10 * 255).round()),
            scheme.surface,
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(28),
        border: Border.all(color: scheme.outlineVariant),
      ),
      child: Row(
        children: [
          Container(
            width: 52,
            height: 52,
            decoration: BoxDecoration(
              color: scheme.primary,
              borderRadius: BorderRadius.circular(18),
            ),
            child: Icon(
              Icons.settings_rounded,
              color: scheme.onPrimary,
              size: 28,
            ),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Configuración de FULLPOS Owner',
                  style: theme.textTheme.titleLarge?.copyWith(
                    fontWeight: FontWeight.w900,
                    letterSpacing: -0.3,
                  ),
                ),
                const SizedBox(height: 6),
                Text(
                  '$companyName · $username',
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: scheme.onSurfaceVariant,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ],
            ),
          ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            decoration: BoxDecoration(
              color: scheme.surface,
              borderRadius: BorderRadius.circular(999),
              border: Border.all(color: scheme.outlineVariant),
            ),
            child: Text(
              'v$version',
              style: theme.textTheme.labelLarge?.copyWith(
                fontWeight: FontWeight.w800,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _SettingsSection extends StatelessWidget {
  const _SettingsSection({required this.title, required this.child});

  final String title;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(24),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: theme.textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.w900,
            ),
          ),
          const SizedBox(height: 14),
          child,
        ],
      ),
    );
  }
}

class _ThemeModeTile extends StatelessWidget {
  const _ThemeModeTile({
    required this.title,
    required this.icon,
    required this.selected,
    required this.onTap,
  });

  final String title;
  final IconData icon;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;

    return InkWell(
      borderRadius: BorderRadius.circular(18),
      onTap: onTap,
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: selected
              ? scheme.primaryContainer.withAlpha((0.45 * 255).round())
              : scheme.surfaceContainerLowest,
          borderRadius: BorderRadius.circular(18),
          border: Border.all(
            color: selected ? scheme.primary : scheme.outlineVariant,
          ),
        ),
        child: Row(
          children: [
            Container(
              width: 44,
              height: 44,
              decoration: BoxDecoration(
                color: selected
                    ? scheme.primary.withAlpha((0.16 * 255).round())
                    : scheme.surface,
                borderRadius: BorderRadius.circular(14),
              ),
              child: Icon(
                icon,
                color: selected ? scheme.primary : scheme.onSurface,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: theme.textTheme.titleSmall?.copyWith(
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                ],
              ),
            ),
            Radio<bool>(
              value: true,
              groupValue: selected,
              onChanged: (_) => onTap(),
            ),
          ],
        ),
      ),
    );
  }
}

class _InfoStatCard extends StatelessWidget {
  const _InfoStatCard({
    required this.label,
    required this.value,
    this.emphasized = false,
  });

  final String label;
  final String value;
  final bool emphasized;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;

    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: emphasized
            ? scheme.primaryContainer.withAlpha((0.50 * 255).round())
            : scheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: scheme.outlineVariant),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: theme.textTheme.bodySmall?.copyWith(
              color: scheme.onSurfaceVariant,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 6),
          Text(
            value,
            style: theme.textTheme.titleSmall?.copyWith(
              fontWeight: FontWeight.w900,
              color: emphasized ? scheme.primary : scheme.onSurface,
            ),
          ),
        ],
      ),
    );
  }
}

class _InfoRow extends StatelessWidget {
  const _InfoRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 120,
            child: Text(
              label,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              value,
              style: theme.textTheme.bodyMedium?.copyWith(
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

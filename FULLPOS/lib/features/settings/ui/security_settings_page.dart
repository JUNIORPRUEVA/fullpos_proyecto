import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/security/app_actions.dart';
import '../../../core/security/security_config.dart';
import '../../../core/session/session_manager.dart';
import '../providers/business_settings_provider.dart';

class SecuritySettingsPage extends ConsumerStatefulWidget {
  const SecuritySettingsPage({super.key});

  @override
  ConsumerState<SecuritySettingsPage> createState() =>
      _SecuritySettingsPageState();
}

class _SecuritySettingsPageState extends ConsumerState<SecuritySettingsPage> {
  SecurityConfig? _config;
  bool _loading = true;
  int _companyId = 1;
  String _terminalId = '';

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final companyId = await SessionManager.companyId() ?? 1;
    final terminalId =
        await SessionManager.terminalId() ??
        await SessionManager.ensureTerminalId();
    final config = await SecurityConfigRepository.load(
      companyId: companyId,
      terminalId: terminalId,
    );

    if (!mounted) return;
    setState(() {
      _config = config;
      _companyId = companyId;
      _terminalId = terminalId;
      _loading = false;
    });
  }

  Future<void> _save(SecurityConfig newConfig) async {
    setState(() {
      _config = newConfig;
    });
    await SecurityConfigRepository.save(
      config: newConfig,
      companyId: _companyId,
      terminalId: _terminalId,
    );
  }

  Future<void> _copy(String label, String value) async {
    await Clipboard.setData(ClipboardData(text: value));
    if (!mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text('$label copiado')));
  }

  @override
  Widget build(BuildContext context) {
    if (_loading || _config == null) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }

    final businessSettings = ref.watch(businessSettingsProvider);
    final cloudEnabled = businessSettings.cloudEnabled;
    final config = _config!;
    final theme = Theme.of(context);
    final titleStyle =
        theme.textTheme.titleMedium?.copyWith(
          color: theme.colorScheme.onSurface,
          fontWeight: FontWeight.bold,
        ) ??
        const TextStyle(fontWeight: FontWeight.bold);
    final switchTitleStyle =
        theme.textTheme.bodyLarge?.copyWith(
          color: theme.colorScheme.onSurface,
          fontWeight: FontWeight.w600,
        ) ??
        const TextStyle(fontWeight: FontWeight.w600);
    final switchSubtitleStyle =
        theme.textTheme.bodySmall?.copyWith(
          color: theme.colorScheme.onSurface.withOpacity(0.7),
        ) ??
        const TextStyle();
    final tileColor = theme.colorScheme.surface;

    return Scaffold(
      appBar: AppBar(title: const Text('Seguridad y permisos')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text('Permisos rápidos', style: titleStyle),
          const SizedBox(height: 6),
          Text(
            'Si no estás seguro, déjalo todo apagado y actívalo cuando lo necesites.',
            style: switchSubtitleStyle,
          ),
          const SizedBox(height: 8),
          SwitchListTile(
            title: Text('PIN del jefe (sin internet)', style: switchTitleStyle),
            subtitle: Text(
              'El jefe pone su PIN y aprueba esa sola acción.',
              style: switchSubtitleStyle,
            ),
            value: config.offlinePinEnabled,
            onChanged: (v) => _save(config.copyWith(offlinePinEnabled: v)),
            tileColor: tileColor,
            activeColor: theme.colorScheme.primary,
            contentPadding: const EdgeInsets.symmetric(horizontal: 12),
          ),
          SwitchListTile(
            title: Text('Código rápido en la PC', style: switchTitleStyle),
            subtitle: Text(
              'Saca un código aquí mismo para aprobar al momento.',
              style: switchSubtitleStyle,
            ),
            value: config.offlineBarcodeEnabled,
            onChanged: (v) => _save(config.copyWith(offlineBarcodeEnabled: v)),
            tileColor: tileColor,
            activeColor: theme.colorScheme.primary,
            contentPadding: const EdgeInsets.symmetric(horizontal: 12),
          ),
          if (cloudEnabled) ...[
            const SizedBox(height: 4),
            Text('Funciones de nube', style: titleStyle),
            const SizedBox(height: 8),
            SwitchListTile(
              title: Text(
                'Aprobación por internet (Owner)',
                style: switchTitleStyle,
              ),
              subtitle: Text(
                'Le llega la solicitud al Owner para aprobar desde el celular.',
                style: switchSubtitleStyle,
              ),
              value: config.remoteEnabled,
              onChanged: (v) => _save(config.copyWith(remoteEnabled: v)),
              tileColor: tileColor,
              activeColor: theme.colorScheme.primary,
              contentPadding: const EdgeInsets.symmetric(horizontal: 12),
            ),
            SwitchListTile(
              title: Text('Código del Owner (token)', style: switchTitleStyle),
              subtitle: Text(
                'El Owner genera un código que se usa una sola vez.',
                style: switchSubtitleStyle,
              ),
              value: config.virtualTokenEnabled,
              onChanged: (v) => _save(config.copyWith(virtualTokenEnabled: v)),
              tileColor: tileColor,
              activeColor: theme.colorScheme.primary,
              contentPadding: const EdgeInsets.symmetric(horizontal: 12),
            ),
            Card(
              margin: const EdgeInsets.only(top: 8, bottom: 12),
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'ID de la caja (para activar en Owner)',
                      style: TextStyle(fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(height: 6),
                    SelectableText(_terminalId),
                    const SizedBox(height: 8),
                    Row(
                      children: [
                        ElevatedButton.icon(
                          onPressed: _terminalId.isEmpty
                              ? null
                              : () => _copy('Terminal ID', _terminalId),
                          icon: const Icon(Icons.copy),
                          label: const Text('Copiar'),
                        ),
                        const SizedBox(width: 12),
                        Flexible(
                          child: Text(
                            'Dáselo al dueño para activar el token en el Owner.',
                            style: switchSubtitleStyle,
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
          ],
          const Divider(),
          Text('Acciones que piden permiso', style: titleStyle),
          const SizedBox(height: 8),
          ...AppActionCategory.values.map(
            (cat) => _buildCategory(cat, config, switchSubtitleStyle),
          ),
        ],
      ),
    );
  }

  Widget _buildCategory(
    AppActionCategory category,
    SecurityConfig config,
    TextStyle? subtitleStyle,
  ) {
    final actions = AppActions.byCategory(category);
    if (actions.isEmpty) return const SizedBox.shrink();

    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              category.name.toUpperCase(),
              style: const TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            ...actions.map(
              (a) => SwitchListTile(
                title: Text(
                  a.name,
                  style:
                      subtitleStyle?.copyWith(fontWeight: FontWeight.w600) ??
                      const TextStyle(),
                ),
                subtitle: Text(
                  '${a.description} • Riesgo: ${a.risk.name}',
                  style: subtitleStyle,
                ),
                value:
                    config.overrideByAction[a.code] ??
                    a.requiresOverrideByDefault,
                onChanged: (v) {
                  final updated = Map<String, bool>.from(
                    config.overrideByAction,
                  )..[a.code] = v;
                  _save(config.copyWith(overrideByAction: updated));
                },
              ),
            ),
          ],
        ),
      ),
    );
  }
}

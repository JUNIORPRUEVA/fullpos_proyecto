import 'package:flutter/material.dart';

import '../../../core/security/app_actions.dart';
import '../../../core/security/security_config.dart';
import '../../../core/session/session_manager.dart';

class SecuritySettingsPage extends StatefulWidget {
  const SecuritySettingsPage({super.key});

  @override
  State<SecuritySettingsPage> createState() => _SecuritySettingsPageState();
}

class _SecuritySettingsPageState extends State<SecuritySettingsPage> {
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

  @override
  Widget build(BuildContext context) {
    if (_loading || _config == null) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }

    final config = _config!;

    return Scaffold(
      appBar: AppBar(title: const Text('Seguridad y Overrides')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          const Text(
            'Métodos de autorización',
            style: TextStyle(fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          SwitchListTile(
            title: const Text('PIN offline (OTP de un solo uso)'),
            value: config.offlinePinEnabled,
            onChanged: (v) => _save(config.copyWith(offlinePinEnabled: v)),
          ),
          SwitchListTile(
            title: const Text('Código local (QR/Barcode)'),
            value: config.offlineBarcodeEnabled,
            onChanged: (v) => _save(config.copyWith(offlineBarcodeEnabled: v)),
          ),
          SwitchListTile(
            title: const Text('Remoto (requiere internet)'),
            value: config.remoteEnabled,
            onChanged: (v) => _save(config.copyWith(remoteEnabled: v)),
          ),
          const Divider(),
          const Text(
            'Acciones que requieren override',
            style: TextStyle(fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          ...AppActionCategory.values.map((cat) => _buildCategory(cat, config)),
        ],
      ),
    );
  }

  Widget _buildCategory(AppActionCategory category, SecurityConfig config) {
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
                title: Text(a.name),
                subtitle: Text('${a.description} • Riesgo: ${a.risk.name}'),
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

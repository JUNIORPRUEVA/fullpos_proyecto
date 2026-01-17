import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:url_launcher/url_launcher_string.dart';

import '../data/business_settings_model.dart';
import '../providers/business_settings_provider.dart';

class CloudSettingsPage extends ConsumerStatefulWidget {
  const CloudSettingsPage({super.key});

  @override
  ConsumerState<CloudSettingsPage> createState() => _CloudSettingsPageState();
}

class _CloudSettingsPageState extends ConsumerState<CloudSettingsPage> {
  final _formKey = GlobalKey<FormState>();
  late BusinessSettings _settings;
  bool _loading = true;

  final _endpointCtrl = TextEditingController();
  final _bucketCtrl = TextEditingController();
  final _apiKeyCtrl = TextEditingController();
  final _androidUrlCtrl = TextEditingController();
  final _iosUrlCtrl = TextEditingController();

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final settings = ref.read(businessSettingsProvider);
      _settings = settings;
      _endpointCtrl.text = settings.cloudEndpoint ?? '';
      _bucketCtrl.text = settings.cloudBucket ?? '';
      _apiKeyCtrl.text = settings.cloudApiKey ?? '';
      _androidUrlCtrl.text = settings.cloudOwnerAppAndroidUrl ?? '';
      _iosUrlCtrl.text = settings.cloudOwnerAppIosUrl ?? '';
      setState(() => _loading = false);
    });
  }

  @override
  void dispose() {
    _endpointCtrl.dispose();
    _bucketCtrl.dispose();
    _apiKeyCtrl.dispose();
    _androidUrlCtrl.dispose();
    _iosUrlCtrl.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    if (!_formKey.currentState!.validate()) {
      return;
    }
    final notifier = ref.read(businessSettingsProvider.notifier);
    final updated = _settings.copyWith(
      cloudEndpoint: _endpointCtrl.text.trim().isEmpty
          ? null
          : _endpointCtrl.text.trim(),
      cloudBucket: _bucketCtrl.text.trim().isEmpty
          ? null
          : _bucketCtrl.text.trim(),
      cloudApiKey: _apiKeyCtrl.text.trim().isEmpty
          ? null
          : _apiKeyCtrl.text.trim(),
      cloudOwnerAppAndroidUrl: _androidUrlCtrl.text.trim().isEmpty
          ? null
          : _androidUrlCtrl.text.trim(),
      cloudOwnerAppIosUrl: _iosUrlCtrl.text.trim().isEmpty
          ? null
          : _iosUrlCtrl.text.trim(),
    );
    await notifier.saveSettings(updated);
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Configuración de nube guardada')),
      );
    }
  }

  Future<void> _copyToClipboard(String label, String value) async {
    await Clipboard.setData(ClipboardData(text: value));
    if (!mounted) {
      return;
    }
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text('Copiado: $label')));
  }

  Future<void> _openUrl(String url) async {
    final ok = await launchUrlString(url, mode: LaunchMode.externalApplication);
    if (!ok && mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('No se pudo abrir el enlace')),
      );
    }
  }

  void _toggleRole(String role, bool value) {
    final roles = List<String>.from(_settings.cloudAllowedRoles);
    if (value) {
      if (!roles.contains(role)) {
        roles.add(role);
      }
    } else {
      roles.remove(role);
    }
    _settings = _settings.copyWith(cloudAllowedRoles: roles);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }

    return Scaffold(
      appBar: AppBar(
        title: const Text('Nube y Accesos'),
        actions: [
          TextButton.icon(
            onPressed: _save,
            icon: const Icon(Icons.save, color: Colors.white),
            label: const Text('Guardar', style: TextStyle(color: Colors.white)),
          ),
        ],
      ),
      body: Form(
        key: _formKey,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            SwitchListTile(
              title: const Text('Sincronización en la nube'),
              subtitle: const Text(
                'Habilita el uso de un bucket/endpoints externos',
              ),
              value: _settings.cloudEnabled,
              onChanged: (v) {
                setState(() => _settings = _settings.copyWith(cloudEnabled: v));
              },
            ),
            const SizedBox(height: 8),
            DropdownButtonFormField<String>(
              value: _settings.cloudProvider,
              decoration: const InputDecoration(
                labelText: 'Proveedor',
                border: OutlineInputBorder(),
              ),
              items: const [
                DropdownMenuItem(value: 'aws', child: Text('AWS S3')),
                DropdownMenuItem(value: 'gcp', child: Text('GCP Storage')),
                DropdownMenuItem(value: 'azure', child: Text('Azure Blob')),
                DropdownMenuItem(value: 'custom', child: Text('Personalizado')),
              ],
              onChanged: (v) {
                setState(
                  () => _settings = _settings.copyWith(
                    cloudProvider: v ?? 'custom',
                  ),
                );
              },
            ),
            const SizedBox(height: 12),
            TextFormField(
              controller: _endpointCtrl,
              decoration: InputDecoration(
                labelText: 'Endpoint/Base URL',
                border: OutlineInputBorder(),
                suffixIcon: (_endpointCtrl.text.trim().isEmpty)
                    ? null
                    : IconButton(
                        tooltip: 'Copiar',
                        icon: const Icon(Icons.copy),
                        onPressed: () => _copyToClipboard(
                          'Endpoint/Base URL',
                          _endpointCtrl.text.trim(),
                        ),
                      ),
              ),
              onChanged: (_) => setState(() {}),
              validator: (v) {
                if (!_settings.cloudEnabled) {
                  return null;
                }
                final value = v?.trim() ?? '';
                if (value.isEmpty) {
                  return 'Requerido cuando la nube está activa';
                }
                if (!value.startsWith('http')) {
                  return 'Debe ser una URL válida';
                }
                return null;
              },
            ),
            const SizedBox(height: 12),
            TextFormField(
              controller: _bucketCtrl,
              decoration: InputDecoration(
                labelText: 'Bucket/Container',
                border: OutlineInputBorder(),
                suffixIcon: (_bucketCtrl.text.trim().isEmpty)
                    ? null
                    : IconButton(
                        tooltip: 'Copiar',
                        icon: const Icon(Icons.copy),
                        onPressed: () => _copyToClipboard(
                          'Bucket/Container',
                          _bucketCtrl.text.trim(),
                        ),
                      ),
              ),
              onChanged: (_) => setState(() {}),
              validator: (v) {
                if (!_settings.cloudEnabled) {
                  return null;
                }
                if ((v?.trim() ?? '').isEmpty) {
                  return 'Requerido cuando la nube está activa';
                }
                return null;
              },
            ),
            const SizedBox(height: 12),
            TextFormField(
              controller: _apiKeyCtrl,
              decoration: InputDecoration(
                labelText: 'API Key / Token',
                border: OutlineInputBorder(),
                suffixIcon: (_apiKeyCtrl.text.trim().isEmpty)
                    ? null
                    : IconButton(
                        tooltip: 'Copiar',
                        icon: const Icon(Icons.copy),
                        onPressed: () => _copyToClipboard(
                          'API Key / Token',
                          _apiKeyCtrl.text,
                        ),
                      ),
              ),
              obscureText: true,
              enableSuggestions: false,
              autocorrect: false,
              onChanged: (_) => setState(() {}),
              validator: (v) {
                if (!_settings.cloudEnabled) {
                  return null;
                }
                if ((v?.trim() ?? '').isEmpty) {
                  return 'Requerido cuando la nube está activa';
                }
                return null;
              },
            ),
            const SizedBox(height: 12),
            Card(
              margin: EdgeInsets.zero,
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Roles con acceso a nube',
                      style: TextStyle(fontWeight: FontWeight.w700),
                    ),
                    CheckboxListTile(
                      title: const Text('Admin'),
                      value: _settings.cloudAllowedRoles.contains('admin'),
                      onChanged: (v) =>
                          setState(() => _toggleRole('admin', v ?? false)),
                    ),
                    CheckboxListTile(
                      title: const Text('Supervisor'),
                      value: _settings.cloudAllowedRoles.contains('supervisor'),
                      onChanged: (v) =>
                          setState(() => _toggleRole('supervisor', v ?? false)),
                    ),
                    CheckboxListTile(
                      title: const Text('Cajero'),
                      value: _settings.cloudAllowedRoles.contains('cashier'),
                      onChanged: (v) =>
                          setState(() => _toggleRole('cashier', v ?? false)),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 12),
            Card(
              margin: EdgeInsets.zero,
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Descarga FULLPOS Owner',
                      style: TextStyle(fontWeight: FontWeight.w700),
                    ),
                    const SizedBox(height: 8),
                    TextFormField(
                      controller: _androidUrlCtrl,
                      decoration: InputDecoration(
                        labelText: 'URL Android (APK/TestFlight)',
                        border: OutlineInputBorder(),
                        suffixIcon: (_androidUrlCtrl.text.trim().isEmpty)
                            ? null
                            : Wrap(
                                spacing: 0,
                                children: [
                                  IconButton(
                                    tooltip: 'Abrir',
                                    icon: const Icon(Icons.open_in_new),
                                    onPressed: () =>
                                        _openUrl(_androidUrlCtrl.text.trim()),
                                  ),
                                  IconButton(
                                    tooltip: 'Copiar',
                                    icon: const Icon(Icons.copy),
                                    onPressed: () => _copyToClipboard(
                                      'URL Android',
                                      _androidUrlCtrl.text.trim(),
                                    ),
                                  ),
                                ],
                              ),
                      ),
                      validator: (v) =>
                          (v != null && v.isNotEmpty && !v.startsWith('http'))
                          ? 'Debe ser una URL válida'
                          : null,
                      onChanged: (_) => setState(() {}),
                    ),
                    const SizedBox(height: 8),
                    TextFormField(
                      controller: _iosUrlCtrl,
                      decoration: InputDecoration(
                        labelText: 'URL iOS (IPA/AppStore)',
                        border: OutlineInputBorder(),
                        suffixIcon: (_iosUrlCtrl.text.trim().isEmpty)
                            ? null
                            : Wrap(
                                spacing: 0,
                                children: [
                                  IconButton(
                                    tooltip: 'Abrir',
                                    icon: const Icon(Icons.open_in_new),
                                    onPressed: () =>
                                        _openUrl(_iosUrlCtrl.text.trim()),
                                  ),
                                  IconButton(
                                    tooltip: 'Copiar',
                                    icon: const Icon(Icons.copy),
                                    onPressed: () => _copyToClipboard(
                                      'URL iOS',
                                      _iosUrlCtrl.text.trim(),
                                    ),
                                  ),
                                ],
                              ),
                      ),
                      validator: (v) =>
                          (v != null && v.isNotEmpty && !v.startsWith('http'))
                          ? 'Debe ser una URL válida'
                          : null,
                      onChanged: (_) => setState(() {}),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Estos enlaces también se usan en el módulo Herramientas (POS) y en /api/downloads/owner-app.',
                      style: TextStyle(
                        color: Colors.grey.shade700,
                        fontSize: 12,
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 20),
            ElevatedButton.icon(
              onPressed: _save,
              icon: const Icon(Icons.save),
              label: const Text('Guardar'),
            ),
          ],
        ),
      ),
    );
  }
}

import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:http/http.dart' as http;
import 'package:url_launcher/url_launcher_string.dart';

import '../../../core/config/backend_config.dart';
import '../../../core/providers/theme_provider.dart';
import '../../../core/theme/app_themes.dart';
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
  final _ownerUserCtrl = TextEditingController();
  final _passCtrl = TextEditingController();
  final _pass2Ctrl = TextEditingController();

  bool _savingAccess = false;
  bool _obscurePass = true;

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
      _ownerUserCtrl.text = settings.cloudOwnerUsername ?? '';
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
    _ownerUserCtrl.dispose();
    _passCtrl.dispose();
    _pass2Ctrl.dispose();
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
    if (updated.cloudEnabled) {
      await _syncCompanyConfigToCloud(showSuccess: false);
    }
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

  void _showMessage(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(message)));
  }

  String _resolveBaseUrl() {
    final endpoint = _settings.cloudEndpoint?.trim();
    if (endpoint != null && endpoint.isNotEmpty) return endpoint;
    return backendBaseUrl;
  }

  String? _normalizeText(String? value) {
    final v = value?.trim();
    if (v == null || v.isEmpty) return null;
    return v;
  }

  String? _normalizeUrl(String? value) {
    final v = value?.trim();
    if (v == null || v.isEmpty) return null;
    if (!v.startsWith('http')) return null;
    return v;
  }

  String? _normalizeEmail(String? value) {
    final v = value?.trim();
    if (v == null || v.isEmpty) return null;
    final isValid = RegExp(r'^[^@\s]+@[^@\s]+\.[^@\s]+$').hasMatch(v);
    return isValid ? v : null;
  }

  Future<void> _syncCompanyConfigToCloud({bool showSuccess = true}) async {
    final rnc = _settings.rnc?.trim() ?? '';
    if (rnc.isEmpty) return;

    try {
      final baseUrl = _resolveBaseUrl();
      final uri = Uri.parse(
        baseUrl,
      ).replace(path: '/api/companies/config/by-rnc');
      final headers = <String, String>{'Content-Type': 'application/json'};
      final cloudKey = _settings.cloudApiKey?.trim();
      if (cloudKey != null && cloudKey.isNotEmpty) {
        headers['x-cloud-key'] = cloudKey;
      }

      final themeKey = ref.read(appThemeProvider).key;
      final logoUrl = _normalizeUrl(_settings.logoPath);

      final payload = <String, dynamic>{
        'companyRnc': rnc,
        'companyName': _normalizeText(_settings.businessName) ?? 'Empresa',
        if (logoUrl != null) 'logoUrl': logoUrl,
        'phone': _normalizeText(_settings.phone),
        'phone2': _normalizeText(_settings.phone2),
        'email': _normalizeEmail(_settings.email),
        'address': _normalizeText(_settings.address),
        'city': _normalizeText(_settings.city),
        'slogan': _normalizeText(_settings.slogan),
        'website': _normalizeUrl(_settings.website),
        'instagramUrl': _normalizeUrl(_settings.instagramUrl),
        'facebookUrl': _normalizeUrl(_settings.facebookUrl),
        'themeKey': themeKey,
      };

      final response = await http
          .put(uri, headers: headers, body: jsonEncode(payload))
          .timeout(const Duration(seconds: 8));

      if (response.statusCode < 200 || response.statusCode >= 300) {
        if (showSuccess) {
          _showMessage('No se pudo sincronizar la configuración.');
        }
        return;
      }

      if (showSuccess) {
        _showMessage('Configuración sincronizada con la nube.');
      }
    } catch (_) {
      if (showSuccess) {
        _showMessage('No se pudo conectar con la nube.');
      }
    }
  }

  Future<void> _saveCloudAccess() async {
    if (_savingAccess) return;

    final rnc = _settings.rnc?.trim() ?? '';
    if (rnc.isEmpty) {
      _showMessage('Configura el RNC de la empresa antes de continuar.');
      return;
    }

    final username = _ownerUserCtrl.text.trim();
    final pass = _passCtrl.text.trim();
    final pass2 = _pass2Ctrl.text.trim();

    if (username.length < 3) {
      _showMessage('El usuario debe tener al menos 3 caracteres.');
      return;
    }
    if (pass.length < 6) {
      _showMessage('La contraseña debe tener mínimo 6 caracteres.');
      return;
    }
    if (pass != pass2) {
      _showMessage('Las contraseñas no coinciden.');
      return;
    }

    setState(() => _savingAccess = true);
    try {
      final baseUrl = _resolveBaseUrl();
      final uri = Uri.parse(baseUrl).replace(path: provisionOwnerPath);
      final headers = <String, String>{'Content-Type': 'application/json'};
      final cloudKey = _settings.cloudApiKey?.trim();
      if (cloudKey != null && cloudKey.isNotEmpty) {
        headers['x-cloud-key'] = cloudKey;
      }

      final payload = {
        'companyRnc': rnc,
        'username': username,
        'password': pass,
      };

      final response = await http
          .post(uri, headers: headers, body: jsonEncode(payload))
          .timeout(const Duration(seconds: 8));

      if (response.statusCode < 200 || response.statusCode >= 300) {
        _showMessage('No se pudo crear el acceso en la nube.');
        return;
      }

      final notifier = ref.read(businessSettingsProvider.notifier);
      final updated = _settings.copyWith(
        cloudEnabled: true,
        cloudOwnerUsername: username,
      );
      await notifier.saveSettings(updated);
      if (!mounted) return;
      setState(() {
        _settings = updated;
        _passCtrl.clear();
        _pass2Ctrl.clear();
      });

      _showMessage('Acceso creado. Entra con FULLPOS Owner.');
      await _syncCompanyConfigToCloud(showSuccess: true);
    } catch (_) {
      _showMessage('No se pudo conectar con el servidor de nube.');
    } finally {
      if (mounted) setState(() => _savingAccess = false);
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
                final value = v?.trim() ?? '';
                if (value.isEmpty) return null;
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
              validator: (v) => null,
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
              validator: (v) => null,
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
                      'Acceso FULLPOS Owner',
                      style: TextStyle(fontWeight: FontWeight.w700),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Crea/actualiza el usuario del dueño para que pueda entrar en la app Owner.',
                      style: TextStyle(
                        color: Colors.grey.shade700,
                        fontSize: 12,
                      ),
                    ),
                    const SizedBox(height: 12),
                    TextField(
                      controller: _ownerUserCtrl,
                      decoration: const InputDecoration(
                        labelText: 'Usuario Owner',
                        border: OutlineInputBorder(),
                        prefixIcon: Icon(Icons.person_outline),
                      ),
                    ),
                    const SizedBox(height: 12),
                    TextField(
                      controller: _passCtrl,
                      obscureText: _obscurePass,
                      decoration: InputDecoration(
                        labelText: 'Contraseña',
                        border: const OutlineInputBorder(),
                        prefixIcon: const Icon(Icons.lock_outline),
                        suffixIcon: IconButton(
                          tooltip: _obscurePass ? 'Mostrar' : 'Ocultar',
                          icon: Icon(
                            _obscurePass
                                ? Icons.visibility_outlined
                                : Icons.visibility_off_outlined,
                          ),
                          onPressed: () =>
                              setState(() => _obscurePass = !_obscurePass),
                        ),
                      ),
                    ),
                    const SizedBox(height: 12),
                    TextField(
                      controller: _pass2Ctrl,
                      obscureText: _obscurePass,
                      decoration: const InputDecoration(
                        labelText: 'Confirmar contraseña',
                        border: OutlineInputBorder(),
                        prefixIcon: Icon(Icons.lock_outline),
                      ),
                    ),
                    const SizedBox(height: 12),
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        onPressed: _savingAccess ? null : _saveCloudAccess,
                        icon: _savingAccess
                            ? const SizedBox(
                                width: 18,
                                height: 18,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                ),
                              )
                            : const Icon(Icons.save_outlined),
                        label: const Text('Guardar acceso Owner'),
                      ),
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

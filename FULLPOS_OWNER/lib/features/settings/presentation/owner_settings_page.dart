import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../core/config/app_config.dart';

class OwnerSettingsPage extends ConsumerStatefulWidget {
  const OwnerSettingsPage({super.key});

  @override
  ConsumerState<OwnerSettingsPage> createState() => _OwnerSettingsPageState();
}

class _OwnerSettingsPageState extends ConsumerState<OwnerSettingsPage> {
  final _formKey = GlobalKey<FormState>();
  final _baseUrlCtrl = TextEditingController();

  @override
  void initState() {
    super.initState();
    final config = ref.read(appConfigProvider);
    _baseUrlCtrl.text = config.baseUrl;
    ref.listen<AppConfigState>(appConfigProvider, (prev, next) {
      if (!mounted) return;
      if (_baseUrlCtrl.text != next.baseUrl) {
        _baseUrlCtrl.text = next.baseUrl;
      }
    });
  }

  @override
  void dispose() {
    _baseUrlCtrl.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    if (!_formKey.currentState!.validate()) return;
    await ref.read(appConfigProvider.notifier).setBaseUrl(_baseUrlCtrl.text);
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Configuración guardada')),
    );
  }

  Future<void> _reset() async {
    await ref.read(appConfigProvider.notifier).resetBaseUrl();
    final config = ref.read(appConfigProvider);
    _baseUrlCtrl.text = config.baseUrl;
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Se restableció la URL por defecto')),
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Configuración de la nube'),
        actions: [
          TextButton.icon(
            onPressed: _save,
            icon: const Icon(Icons.save),
            label: const Text('Guardar'),
          ),
        ],
      ),
      body: Form(
        key: _formKey,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            Text(
              'Endpoint/Base URL',
              style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 6),
            Text(
              'Usa la misma URL configurada en FULLPOS > Configuración > Nube y Accesos.',
              style: theme.textTheme.bodySmall?.copyWith(color: Colors.white70),
            ),
            const SizedBox(height: 12),
            TextFormField(
              controller: _baseUrlCtrl,
              decoration: const InputDecoration(
                labelText: 'Base URL (ej. https://api.fullpos.com)',
                prefixIcon: Icon(Icons.cloud_outlined),
              ),
              validator: (value) {
                final text = value?.trim() ?? '';
                if (text.isEmpty) {
                  return 'Ingresa la URL de tu nube';
                }
                if (!text.startsWith('http')) {
                  return 'Debe ser una URL válida';
                }
                return null;
              },
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: _save,
                    icon: const Icon(Icons.save),
                    label: const Text('Guardar'),
                  ),
                ),
                const SizedBox(width: 12),
                OutlinedButton.icon(
                  onPressed: _reset,
                  icon: const Icon(Icons.refresh),
                  label: const Text('Restablecer'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

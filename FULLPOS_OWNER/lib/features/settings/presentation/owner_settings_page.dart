import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:url_launcher/url_launcher.dart';
import '../data/company_config.dart';
import '../providers/company_config_provider.dart';

class OwnerSettingsPage extends ConsumerStatefulWidget {
  const OwnerSettingsPage({super.key});

  @override
  ConsumerState<OwnerSettingsPage> createState() => _OwnerSettingsPageState();
}

class _OwnerSettingsPageState extends ConsumerState<OwnerSettingsPage> {
  @override
  void initState() {
    super.initState();
  }

  @override
  void dispose() {
    super.dispose();
  }

  Widget _buildLogo(String? logoUrl) {
    const placeholder = CircleAvatar(
      radius: 30,
      backgroundColor: Colors.white12,
      child: Icon(Icons.business, size: 32, color: Colors.white70),
    );
    if (logoUrl == null || logoUrl.isEmpty) return placeholder;
    return CircleAvatar(
      radius: 30,
      backgroundColor: Colors.transparent,
      backgroundImage: NetworkImage(logoUrl),
      child: Container(
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          border: Border.all(color: Colors.white24, width: 1),
        ),
      ),
    );
  }

  Future<void> _openUrl(String? value) async {
    if (value == null || value.isEmpty) return;
    final uri = Uri.tryParse(value);
    if (uri == null) return;
    if (await canLaunchUrl(uri)) {
      await launchUrl(uri, mode: LaunchMode.externalApplication);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final configState = ref.watch(companyConfigProvider);
    final config = configState.valueOrNull;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Configuración premium'),
        actions: [
          IconButton(
            tooltip: 'Actualizar configuración',
            icon: const Icon(Icons.refresh_rounded),
            onPressed: () => ref.read(companyConfigProvider.notifier).refresh(),
          ),
        ],
      ),
      body: GestureDetector(
        onTap: () => FocusScope.of(context).unfocus(),
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (configState.isLoading) const LinearProgressIndicator(),
              const SizedBox(height: 12),
              configState.when(
                data: (config) {
                  if (config == null) {
                    return Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Icon(Icons.cloud_off, color: Colors.amber),
                        const SizedBox(height: 6),
                        Text(
                          'La nube no tiene la configuraci\u00f3n de empresa disponible.',
                          style: theme.textTheme.bodyMedium?.copyWith(
                            color: Colors.amber,
                          ),
                        ),
                        const SizedBox(height: 16),
                      ],
                    );
                  }

                  return Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _buildBrandCard(theme, config),
                      const SizedBox(height: 16),
                      _buildCompanyDetails(theme, config),
                      const SizedBox(height: 16),
                    ],
                  );
                },
                loading: () => const SizedBox.shrink(),
                error: (error, stack) => Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Icon(Icons.warning, color: Colors.amber),
                    const SizedBox(height: 6),
                    Text(
                      'No se pudo cargar la configuración del negocio.',
                      style: theme.textTheme.bodyMedium?.copyWith(
                        color: Colors.amber,
                      ),
                    ),
                    const SizedBox(height: 16),
                  ],
                ),
              ),
              const SizedBox.shrink(),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildBrandCard(ThemeData theme, CompanyConfig config) {
    return Card(
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            _buildLogo(config.logoUrl),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    config.companyName,
                    style: theme.textTheme.titleLarge?.copyWith(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  if (config.rnc != null && config.rnc!.isNotEmpty)
                    Text(
                      'RNC ${config.rnc}',
                      style: theme.textTheme.bodyMedium,
                    ),
                  if (config.version != null && config.version!.isNotEmpty)
                    Text(
                      'Versión ${config.version}',
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: Colors.white70,
                      ),
                    ),
                  if (config.slogan != null && config.slogan!.isNotEmpty)
                    Padding(
                      padding: const EdgeInsets.only(top: 6),
                      child: Text(
                        config.slogan!,
                        style: theme.textTheme.bodySmall,
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

  Widget _buildCompanyDetails(ThemeData theme, CompanyConfig config) {
    Widget infoTile(
      IconData icon,
      String title,
      String? value, {
      VoidCallback? onTap,
    }) {
      return ListTile(
        contentPadding: EdgeInsets.zero,
        leading: Icon(icon, color: theme.colorScheme.secondary),
        title: Text(title),
        subtitle: Text(value ?? 'Pendiente', style: theme.textTheme.bodySmall),
        trailing: onTap != null
            ? const Icon(Icons.open_in_new, size: 18)
            : null,
        onTap: onTap,
      );
    }

    return Card(
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 8),
        child: Column(
          children: [
            infoTile(Icons.phone, 'Teléfonos', config.phone ?? config.phone2),
            infoTile(Icons.email_outlined, 'Correo electrónico', config.email),
            infoTile(Icons.location_on_outlined, 'Ubicación', config.address),
            infoTile(
              Icons.language,
              'Sitio web',
              config.website,
              onTap: () => _openUrl(config.website),
            ),
            infoTile(
              Icons.facebook,
              'Facebook',
              config.facebookUrl,
              onTap: () => _openUrl(config.facebookUrl),
            ),
            infoTile(
              Icons.camera_alt_outlined,
              'Instagram',
              config.instagramUrl,
              onTap: () => _openUrl(config.instagramUrl),
            ),
          ],
        ),
      ),
    );
  }

  // Se removió la configuración de URL para el cliente.
}

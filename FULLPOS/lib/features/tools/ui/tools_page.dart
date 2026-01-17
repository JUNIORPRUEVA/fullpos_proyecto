import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:url_launcher/url_launcher_string.dart';
import '../../../core/constants/app_colors.dart';
import '../../../core/constants/app_sizes.dart';
import '../data/owner_app_links.dart';
import '../../settings/providers/business_settings_provider.dart';

/// Página de Herramientas
class ToolsPage extends ConsumerWidget {
  const ToolsPage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final settings = ref.watch(businessSettingsProvider);

    final localLinks = OwnerAppLinks(
      androidUrl: (settings.cloudOwnerAppAndroidUrl?.trim().isEmpty ?? true)
          ? null
          : settings.cloudOwnerAppAndroidUrl!.trim(),
      iosUrl: (settings.cloudOwnerAppIosUrl?.trim().isEmpty ?? true)
          ? null
          : settings.cloudOwnerAppIosUrl!.trim(),
    );

    final hasLocalLinks =
        localLinks.androidUrl != null || localLinks.iosUrl != null;

    final ownerLinks = hasLocalLinks
        ? _OwnerAppLinksCard(data: localLinks, sourceLabel: 'Configuración')
        : FutureBuilder<OwnerAppLinks>(
            future: OwnerAppLinks.fetch(),
            builder: (context, snapshot) {
              if (snapshot.connectionState == ConnectionState.waiting) {
                return const Padding(
                  padding: EdgeInsets.all(12),
                  child: LinearProgressIndicator(minHeight: 2),
                );
              }
              if (snapshot.hasError) {
                return Padding(
                  padding: const EdgeInsets.all(12),
                  child: Text(
                    'No se pudieron cargar los enlaces de la app del Due\u00f1o',
                    style: TextStyle(color: Colors.red[400]),
                  ),
                );
              }
              return _OwnerAppLinksCard(
                data: snapshot.data,
                sourceLabel: 'Servidor',
              );
            },
          );

    final tools = [
      _ToolItem(
        icon: Icons.description_outlined,
        title: 'NCF',
        subtitle: 'Comprobantes',
        color: AppColors.teal,
        onTap: () => context.go('/ncf'),
      ),
      _ToolItem(
        icon: Icons.receipt_long_outlined,
        title: 'Ventas',
        subtitle: 'Historial',
        color: AppColors.gold,
        onTap: () => context.go('/sales-list'),
      ),
      _ToolItem(
        icon: Icons.request_quote_outlined,
        title: 'Cotizaciones',
        subtitle: 'Pendientes',
        color: AppColors.teal600,
        onTap: () => context.go('/quotes-list'),
      ),
      _ToolItem(
        icon: Icons.keyboard_return_rounded,
        title: 'Devoluciones',
        subtitle: 'Gestión',
        color: Colors.orange,
        onTap: () => context.go('/returns-list'),
      ),
      _ToolItem(
        icon: Icons.credit_card_outlined,
        title: 'Créditos',
        subtitle: 'Ventas a crédito',
        color: Colors.blue,
        onTap: () => context.go('/credits-list'),
      ),
      _ToolItem(
        icon: Icons.inventory_2_outlined,
        title: 'Inventario',
        subtitle: 'Conteo rápido',
        color: AppColors.success,
        onTap: () {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Módulo en desarrollo'),
              backgroundColor: AppColors.info,
            ),
          );
        },
      ),
      _ToolItem(
        icon: Icons.qr_code_scanner_rounded,
        title: 'Escáner',
        subtitle: 'Códigos',
        color: AppColors.info,
        onTap: () {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Módulo en desarrollo'),
              backgroundColor: AppColors.info,
            ),
          );
        },
      ),
    ];

    return Scaffold(
      backgroundColor: AppColors.bgLight,
      appBar: AppBar(
        title: const Text(
          'Herramientas',
          style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600),
        ),
        toolbarHeight: 48,
      ),
      body: Padding(
        padding: const EdgeInsets.all(AppSizes.paddingL),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            ownerLinks,
            const SizedBox(height: AppSizes.paddingM),
            // Header
            Container(
              padding: const EdgeInsets.symmetric(
                horizontal: AppSizes.paddingM,
                vertical: AppSizes.paddingS,
              ),
              child: Row(
                children: [
                  Icon(
                    Icons.apps_rounded,
                    size: 20,
                    color: AppColors.textDarkSecondary,
                  ),
                  const SizedBox(width: 8),
                  Text(
                    'Accesos Rápidos',
                    style: TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                      color: AppColors.textDarkSecondary,
                      letterSpacing: 0.5,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: AppSizes.paddingM),
            // Grid de herramientas
            Expanded(
              child: GridView.builder(
                gridDelegate: const SliverGridDelegateWithMaxCrossAxisExtent(
                  maxCrossAxisExtent: 160,
                  mainAxisSpacing: 12,
                  crossAxisSpacing: 12,
                  childAspectRatio: 1.1,
                ),
                itemCount: tools.length,
                itemBuilder: (context, index) => _ToolCard(tool: tools[index]),
              ),
            ),
          ],
        ),
      ),
    );
  }

  static void _openUrl(BuildContext context, String url) async {
    final ok = await launchUrlString(url, mode: LaunchMode.externalApplication);
    if (!ok && context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('No se pudo abrir el enlace')),
      );
    }
  }
}

class _OwnerAppLinksCard extends StatelessWidget {
  final OwnerAppLinks? data;
  final String sourceLabel;

  const _OwnerAppLinksCard({required this.data, required this.sourceLabel});

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: AppSizes.paddingS),
      child: Padding(
        padding: const EdgeInsets.all(AppSizes.paddingM),
        child: Row(
          children: [
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Expanded(
                        child: Text(
                          'App del Due\u00f1o (FULLPOS Owner)',
                          style: TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Chip(
                        label: Text(sourceLabel),
                        backgroundColor: AppColors.teal.withOpacity(0.08),
                        labelStyle: const TextStyle(color: AppColors.teal),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Wrap(
                    spacing: 12,
                    runSpacing: 8,
                    children: [
                      ElevatedButton.icon(
                        icon: const Icon(Icons.android),
                        label: const Text('Descargar Android'),
                        onPressed: data?.androidUrl != null
                            ? () =>
                                  ToolsPage._openUrl(context, data!.androidUrl!)
                            : null,
                      ),
                      ElevatedButton.icon(
                        icon: const Icon(Icons.phone_iphone),
                        label: const Text('Descargar iPhone'),
                        onPressed: data?.iosUrl != null
                            ? () => ToolsPage._openUrl(context, data!.iosUrl!)
                            : null,
                      ),
                      if (data?.version != null)
                        Chip(
                          label: Text('Versi\u00f3n ${data!.version}'),
                          backgroundColor: AppColors.teal.withOpacity(0.1),
                          labelStyle: const TextStyle(color: AppColors.teal),
                        ),
                    ],
                  ),
                ],
              ),
            ),
            if (data?.androidUrl != null)
              QrImageView(
                data: data!.androidUrl!,
                size: 120,
                backgroundColor: Colors.white,
              ),
          ],
        ),
      ),
    );
  }
}

class _ToolItem {
  final IconData icon;
  final String title;
  final String subtitle;
  final Color color;
  final VoidCallback onTap;

  const _ToolItem({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.color,
    required this.onTap,
  });
}

class _ToolCard extends StatefulWidget {
  final _ToolItem tool;

  const _ToolCard({required this.tool});

  @override
  State<_ToolCard> createState() => _ToolCardState();
}

class _ToolCardState extends State<_ToolCard> {
  bool _isHovered = false;

  @override
  Widget build(BuildContext context) {
    return MouseRegion(
      onEnter: (_) => setState(() => _isHovered = true),
      onExit: (_) => setState(() => _isHovered = false),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 150),
        transform: Matrix4.identity()..scale(_isHovered ? 1.02 : 1.0),
        transformAlignment: Alignment.center,
        child: Card(
          elevation: _isHovered ? 4 : 1,
          shadowColor: widget.tool.color.withOpacity(0.3),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
            side: BorderSide(
              color: _isHovered
                  ? widget.tool.color.withOpacity(0.3)
                  : Colors.transparent,
              width: 1.5,
            ),
          ),
          child: InkWell(
            onTap: widget.tool.onTap,
            borderRadius: BorderRadius.circular(12),
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  // Icono
                  Container(
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: widget.tool.color.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: Icon(
                      widget.tool.icon,
                      size: 24,
                      color: widget.tool.color,
                    ),
                  ),
                  const SizedBox(height: 10),
                  // Título
                  Text(
                    widget.tool.title,
                    style: const TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                      color: AppColors.textDark,
                    ),
                    textAlign: TextAlign.center,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 2),
                  // Subtítulo
                  Text(
                    widget.tool.subtitle,
                    style: TextStyle(
                      fontSize: 11,
                      color: AppColors.textDarkSecondary.withOpacity(0.8),
                    ),
                    textAlign: TextAlign.center,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

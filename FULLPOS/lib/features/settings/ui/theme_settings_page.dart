import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../providers/theme_provider.dart';
import '../../../core/constants/app_sizes.dart';
import 'theme_selector_widget.dart';

/// Página de configuración completa del tema (paleta + tipografía + presets)
class ThemeSettingsPage extends ConsumerWidget {
  const ThemeSettingsPage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final settings = ref.watch(themeProvider);
    final notifier = ref.read(themeProvider.notifier);
    final scheme = Theme.of(context).colorScheme;

    return Scaffold(
      appBar: AppBar(title: const Text('TEMA DE LA APLICACIÓN'), elevation: 0),
      body: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Encabezado informativo
            Container(
              color: Theme.of(context).colorScheme.primary.withAlpha(15),
              padding: const EdgeInsets.all(20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    '🎨 Personaliza tu POS (completo)',
                    style: Theme.of(context).textTheme.headlineSmall,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Configura la paleta completa: AppBar, Sidebar, Footer, botones y tipografía.',
                    style: Theme.of(context).textTheme.bodyMedium,
                  ),
                  const SizedBox(height: 12),
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: scheme.secondary.withAlpha(25),
                      borderRadius: BorderRadius.circular(AppSizes.radiusM),
                      border: Border.all(
                        color: scheme.secondary.withAlpha(120),
                        width: 1,
                      ),
                    ),
                    child: Row(
                      children: [
                        Icon(
                          Icons.info_outline,
                          color: scheme.secondary,
                          size: 20,
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Text(
                            'Tu selección se guarda automáticamente.',
                            style: Theme.of(context).textTheme.bodySmall,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),

            // Selector de temas
            const ThemeSelector(padding: EdgeInsets.all(20)),

            // Tipografía
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              child: _SectionCard(
                title: 'Tipografía',
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: DropdownButtonFormField<String>(
                            value: settings.fontFamily,
                            decoration: const InputDecoration(
                              labelText: 'Tipo de letra',
                            ),
                            items: const [
                              DropdownMenuItem(
                                value: 'Poppins',
                                child: Text('Poppins'),
                              ),
                              DropdownMenuItem(
                                value: 'Roboto',
                                child: Text('Roboto'),
                              ),
                              DropdownMenuItem(
                                value: 'Arial',
                                child: Text('Arial'),
                              ),
                            ],
                            onChanged: (v) {
                              if (v == null) return;
                              notifier.updateFontFamily(v);
                            },
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 14),
                    Text(
                      'Tamaño base: ${settings.fontSize.toStringAsFixed(0)}',
                      style: Theme.of(context).textTheme.labelLarge,
                    ),
                    Slider(
                      value: settings.fontSize.clamp(10.0, 22.0),
                      min: 10,
                      max: 22,
                      divisions: 12,
                      label: settings.fontSize.toStringAsFixed(0),
                      onChanged: (v) => notifier.updateFontSize(v),
                    ),
                  ],
                ),
              ),
            ),

            const SizedBox(height: 12),

            // Paleta completa
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              child: _SectionCard(
                title: 'Paleta de Colores',
                child: Column(
                  children: [
                    _ColorRow(
                      label: 'Color primario',
                      color: settings.primaryColor,
                      onPick: (c) => notifier.updatePrimaryColor(c),
                    ),
                    _ColorRow(
                      label: 'Color acento',
                      color: settings.accentColor,
                      onPick: (c) => notifier.updateAccentColor(c),
                    ),
                    _ColorRow(
                      label: 'Fondo (background)',
                      color: settings.backgroundColor,
                      onPick: (c) => notifier.updateBackgroundColor(c),
                    ),
                    _ColorRow(
                      label: 'Surface',
                      color: settings.surfaceColor,
                      onPick: (c) => notifier.updateSurfaceColor(c),
                    ),
                    _ColorRow(
                      label: 'Color de texto',
                      color: settings.textColor,
                      onPick: (c) => notifier.updateTextColor(c),
                    ),
                    const Divider(height: 24),
                    _ColorRow(
                      label: 'AppBar principal',
                      color: settings.appBarColor,
                      onPick: (c) => notifier.updateAppBarColor(c),
                    ),
                    _ColorRow(
                      label: 'Texto AppBar',
                      color: settings.appBarTextColor,
                      onPick: (c) => notifier.updateAppBarTextColor(c),
                    ),
                    const Divider(height: 24),
                    _ColorRow(
                      label: 'Sidebar principal',
                      color: settings.sidebarColor,
                      onPick: (c) => notifier.updateSidebarColor(c),
                    ),
                    _ColorRow(
                      label: 'Texto Sidebar',
                      color: settings.sidebarTextColor,
                      onPick: (c) => notifier.updateSidebarTextColor(c),
                    ),
                    _ColorRow(
                      label: 'Activo Sidebar',
                      color: settings.sidebarActiveColor,
                      onPick: (c) => notifier.updateSidebarActiveColor(c),
                    ),
                    const Divider(height: 24),
                    _ColorRow(
                      label: 'Footer principal',
                      color: settings.footerColor,
                      onPick: (c) => notifier.updateFooterColor(c),
                    ),
                    _ColorRow(
                      label: 'Texto Footer',
                      color: settings.footerTextColor,
                      onPick: (c) => notifier.updateFooterTextColor(c),
                    ),
                    const Divider(height: 24),
                    _ColorRow(
                      label: 'Botones (principal)',
                      color: settings.buttonColor,
                      onPick: (c) => notifier.updateButtonColor(c),
                    ),
                    _ColorRow(
                      label: 'Cards',
                      color: settings.cardColor,
                      onPick: (c) => notifier.updateCardColor(c),
                    ),
                    const Divider(height: 24),
                    _ColorRow(
                      label: 'Éxito',
                      color: settings.successColor,
                      onPick: (c) => notifier.updateSuccessColor(c),
                    ),
                    _ColorRow(
                      label: 'Error',
                      color: settings.errorColor,
                      onPick: (c) => notifier.updateErrorColor(c),
                    ),
                    _ColorRow(
                      label: 'Advertencia',
                      color: settings.warningColor,
                      onPick: (c) => notifier.updateWarningColor(c),
                    ),
                  ],
                ),
              ),
            ),

            const SizedBox(height: 12),

            // Acciones
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              child: Row(
                children: [
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: () => notifier.resetToDefault(),
                      icon: const Icon(Icons.restart_alt),
                      label: const Text('Restablecer'),
                    ),
                  ),
                ],
              ),
            ),

            // Pie de página
            Container(
              margin: const EdgeInsets.all(20),
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surface,
                borderRadius: BorderRadius.circular(AppSizes.radiusM),
                border: Border.all(color: Colors.grey.withAlpha(100), width: 1),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(
                        Icons.check_circle,
                        color: settings.successColor,
                        size: 20,
                      ),
                      const SizedBox(width: 8),
                      Text(
                        'Tema aplicado y guardado',
                        style: Theme.of(context).textTheme.labelLarge?.copyWith(
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Text(
                    'Los cambios se aplicarán inmediatamente en toda la aplicación.',
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                ],
              ),
            ),

            const SizedBox(height: 20),
          ],
        ),
      ),
    );
  }
}

class _SectionCard extends StatelessWidget {
  final String title;
  final Widget child;

  const _SectionCard({required this.title, required this.child});

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(AppSizes.radiusM),
        border: Border.all(color: Colors.grey.withAlpha(90)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 12),
          child,
        ],
      ),
    );
  }
}

class _ColorRow extends StatelessWidget {
  final String label;
  final Color color;
  final ValueChanged<Color> onPick;

  const _ColorRow({
    required this.label,
    required this.color,
    required this.onPick,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Row(
        children: [
          Expanded(
            child: Text(label, style: Theme.of(context).textTheme.bodyMedium),
          ),
          const SizedBox(width: 12),
          InkWell(
            onTap: () async {
              final picked = await _pickColor(context, initial: color);
              if (picked != null) onPick(picked);
            },
            borderRadius: BorderRadius.circular(10),
            child: Container(
              width: 44,
              height: 34,
              decoration: BoxDecoration(
                color: color,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: Colors.grey.withAlpha(120)),
              ),
            ),
          ),
          const SizedBox(width: 12),
          Text(
            '#${color.value.toRadixString(16).toUpperCase().padLeft(8, '0')}',
            style: Theme.of(
              context,
            ).textTheme.labelSmall?.copyWith(fontFamily: 'monospace'),
          ),
        ],
      ),
    );
  }

  Future<Color?> _pickColor(
    BuildContext context, {
    required Color initial,
  }) async {
    Color current = initial;
    int a = initial.alpha;
    int r = initial.red;
    int g = initial.green;
    int b = initial.blue;

    String toHex(Color c) =>
        c.value.toRadixString(16).toUpperCase().padLeft(8, '0');
    Color fromArgb(int aa, int rr, int gg, int bb) =>
        Color.fromARGB(aa, rr, gg, bb);

    final controller = TextEditingController(text: toHex(initial));

    final result = await showDialog<Color>(
      context: context,
      builder: (ctx) {
        return AlertDialog(
          title: const Text('Seleccionar color'),
          content: StatefulBuilder(
            builder: (ctx, setState) {
              final theme = Theme.of(ctx);
              final scheme = theme.colorScheme;
              final swatches = <Color>[
                const Color(0xFF000000),
                const Color(0xFFFFFFFF),
                const Color(0xFF1F2937),
                const Color(0xFF00796B),
                const Color(0xFFD4AF37),
                const Color(0xFF1976D2),
                const Color(0xFF7B1FA2),
                const Color(0xFFE65100),
                const Color(0xFF2E7D32),
                const Color(0xFFEF4444),
                const Color(0xFFF59E0B),
              ];

              void syncFromCurrent() {
                a = current.alpha;
                r = current.red;
                g = current.green;
                b = current.blue;
              }

              void setCurrent(Color c) {
                setState(() {
                  current = c;
                  syncFromCurrent();
                  controller.text = toHex(current);
                });
              }

              void setFromSliders() {
                setCurrent(fromArgb(a, r, g, b));
              }

              return SizedBox(
                width: 420,
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Container(
                          width: 44,
                          height: 34,
                          decoration: BoxDecoration(
                            color: current,
                            borderRadius: BorderRadius.circular(10),
                            border: Border.all(
                              color: Colors.grey.withAlpha(140),
                            ),
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: TextField(
                            controller: controller,
                            decoration: const InputDecoration(
                              labelText: 'ARGB Hex (8 chars) ej: FF00796B',
                            ),
                            onChanged: (v) {
                              final parsed = _tryParseHexColor(v);
                              if (parsed != null) {
                                setState(() {
                                  current = parsed;
                                  syncFromCurrent();
                                });
                              }
                            },
                          ),
                        ),
                      ],
                    ),

                    const SizedBox(height: 14),
                    Text(
                      'Selector (A/R/G/B)',
                      style: theme.textTheme.labelLarge,
                    ),
                    const SizedBox(height: 8),

                    _SliderRow(
                      label: 'A',
                      value: a.toDouble(),
                      activeColor: scheme.primary,
                      onChanged: (v) {
                        a = v.round().clamp(0, 255);
                        setFromSliders();
                      },
                    ),
                    _SliderRow(
                      label: 'R',
                      value: r.toDouble(),
                      activeColor: Colors.red,
                      onChanged: (v) {
                        r = v.round().clamp(0, 255);
                        setFromSliders();
                      },
                    ),
                    _SliderRow(
                      label: 'G',
                      value: g.toDouble(),
                      activeColor: Colors.green,
                      onChanged: (v) {
                        g = v.round().clamp(0, 255);
                        setFromSliders();
                      },
                    ),
                    _SliderRow(
                      label: 'B',
                      value: b.toDouble(),
                      activeColor: Colors.blue,
                      onChanged: (v) {
                        b = v.round().clamp(0, 255);
                        setFromSliders();
                      },
                    ),

                    const SizedBox(height: 14),
                    Wrap(
                      spacing: 10,
                      runSpacing: 10,
                      children: [
                        for (final c in swatches)
                          InkWell(
                            onTap: () {
                              setCurrent(c);
                            },
                            borderRadius: BorderRadius.circular(10),
                            child: Container(
                              width: 34,
                              height: 34,
                              decoration: BoxDecoration(
                                color: c,
                                borderRadius: BorderRadius.circular(10),
                                border: Border.all(
                                  color: Colors.grey.withAlpha(120),
                                ),
                              ),
                            ),
                          ),
                      ],
                    ),
                  ],
                ),
              );
            },
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text('Cancelar'),
            ),
            ElevatedButton(
              onPressed: () => Navigator.of(ctx).pop(current),
              child: const Text('Aplicar'),
            ),
          ],
        );
      },
    );

    return result;
  }

  Color? _tryParseHexColor(String input) {
    final v = input.trim().replaceAll('#', '').toUpperCase();
    final hex = v.length == 6 ? 'FF$v' : v;
    final ok = RegExp(r'^[0-9A-F]{8}$').hasMatch(hex);
    if (!ok) return null;
    return Color(int.parse(hex, radix: 16));
  }
}

class _SliderRow extends StatelessWidget {
  final String label;
  final double value;
  final ValueChanged<double> onChanged;
  final Color activeColor;

  const _SliderRow({
    required this.label,
    required this.value,
    required this.onChanged,
    required this.activeColor,
  });

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        SizedBox(
          width: 18,
          child: Text(label, style: Theme.of(context).textTheme.labelMedium),
        ),
        const SizedBox(width: 8),
        Expanded(
          child: Slider(
            min: 0,
            max: 255,
            divisions: 255,
            value: value.clamp(0, 255),
            activeColor: activeColor,
            label: value.round().toString(),
            onChanged: onChanged,
          ),
        ),
        SizedBox(
          width: 36,
          child: Text(
            value.round().toString(),
            textAlign: TextAlign.end,
            style: Theme.of(
              context,
            ).textTheme.labelSmall?.copyWith(fontFamily: 'monospace'),
          ),
        ),
      ],
    );
  }
}

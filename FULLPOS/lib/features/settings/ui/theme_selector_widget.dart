import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../providers/theme_provider.dart';
import '../data/theme_settings_model.dart';
import '../../../core/constants/app_sizes.dart';

/// Widget para selector de tema de la aplicación
class ThemeSelector extends ConsumerWidget {
  final EdgeInsets padding;

  const ThemeSelector({super.key, this.padding = const EdgeInsets.all(16)});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final settings = ref.watch(themeProvider);
    final themeNotifier = ref.read(themeProvider.notifier);

    return Padding(
      padding: padding,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Título
          Text(
            'Tema de la aplicación',
            style: Theme.of(context).textTheme.titleLarge,
          ),
          const SizedBox(height: 4),
          Text(
            'Elige un tema (Original + 3 más) y personalízalo completo',
            style: Theme.of(context).textTheme.bodySmall,
          ),
          const SizedBox(height: 24),

          // Modo oscuro
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(AppSizes.radiusM),
              border: Border.all(color: Colors.grey.withAlpha(80)),
            ),
            child: Row(
              children: [
                const Icon(Icons.dark_mode_outlined, size: 18),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    'Modo oscuro',
                    style: Theme.of(context).textTheme.titleSmall,
                  ),
                ),
                Switch(
                  value: settings.isDarkMode,
                  onChanged: (_) => themeNotifier.toggleDarkMode(),
                ),
              ],
            ),
          ),

          const SizedBox(height: 16),

          // Opción 1: Original
          _buildPresetOption(
            context,
            presetKey: 'default',
            title: 'Tema Original',
            description: 'Teal + Dorado (corporativo)',
            settings: PresetThemes.getPreset('default'),
            isSelected: _isSamePalette(
              ref.watch(themeProvider),
              PresetThemes.getPreset('default'),
            ),
            onTap: () => themeNotifier.applyPreset('default'),
          ),
          const SizedBox(height: 12),

          // Opción 2: Azul / Blanco / Negro
          _buildPresetOption(
            context,
            presetKey: 'ocean',
            title: 'Negro / Azul / Blanco',
            description: 'Corporativo (sobrio, elegante)',
            settings: PresetThemes.getPreset('ocean'),
            isSelected: _isSamePalette(
              ref.watch(themeProvider),
              PresetThemes.getPreset('ocean'),
            ),
            onTap: () => themeNotifier.applyPreset('ocean'),
          ),
          const SizedBox(height: 12),

          // Opción 3: Profesional POS
          _buildPresetOption(
            context,
            presetKey: 'forest',
            title: 'Naranja / Blanco / Azul',
            description: 'Corporativo (energético y claro)',
            settings: PresetThemes.getPreset('forest'),
            isSelected: _isSamePalette(
              ref.watch(themeProvider),
              PresetThemes.getPreset('forest'),
            ),
            onTap: () => themeNotifier.applyPreset('forest'),
          ),

          const SizedBox(height: 12),

          // Opción 4: Nuevo (Morado)
          _buildPresetOption(
            context,
            presetKey: 'purple',
            title: 'Grafito / Blanco / Teal',
            description: 'Corporativo (minimalista y premium)',
            settings: PresetThemes.getPreset('purple'),
            isSelected: _isSamePalette(
              ref.watch(themeProvider),
              PresetThemes.getPreset('purple'),
            ),
            onTap: () => themeNotifier.applyPreset('purple'),
          ),

          const SizedBox(height: 24),

          // Preview del tema actual
          _buildThemePreview(context),
        ],
      ),
    );
  }

  bool _isSamePalette(ThemeSettings current, ThemeSettings preset) {
    return current.primaryColor == preset.primaryColor &&
        current.accentColor == preset.accentColor &&
        current.sidebarColor == preset.sidebarColor &&
        current.footerColor == preset.footerColor &&
        current.isDarkMode == preset.isDarkMode;
  }

  Widget _buildPresetOption(
    BuildContext context, {
    required String presetKey,
    required String title,
    required String description,
    required ThemeSettings settings,
    required bool isSelected,
    required VoidCallback onTap,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(AppSizes.radiusM),
          border: Border.all(
            color: isSelected
                ? settings.primaryColor
                : Colors.grey.withAlpha(100),
            width: isSelected ? 2.5 : 1.5,
          ),
          color: isSelected
              ? settings.primaryColor.withAlpha(15)
              : Colors.transparent,
        ),
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            // Indicador selección
            Container(
              width: 18,
              height: 18,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                border: Border.all(
                  width: 2,
                  color: isSelected
                      ? settings.primaryColor
                      : Colors.grey.withAlpha(140),
                ),
              ),
              child: isSelected
                  ? Center(
                      child: Container(
                        width: 10,
                        height: 10,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          color: settings.primaryColor,
                        ),
                      ),
                    )
                  : null,
            ),
            const SizedBox(width: 14),

            // Información del tema
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: Theme.of(context).textTheme.titleMedium?.copyWith(
                      fontWeight: isSelected
                          ? FontWeight.w700
                          : FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    description,
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                ],
              ),
            ),

            // Mini preview de colores
            SizedBox(
              width: 100,
              child: Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  _buildColorPreview(settings.primaryColor, size: 24),
                  const SizedBox(width: 6),
                  _buildColorPreview(settings.accentColor, size: 24),
                  const SizedBox(width: 6),
                  _buildColorPreview(
                    settings.surfaceColor,
                    size: 24,
                    hasBorder: true,
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  /// Construir un círculo de color
  Widget _buildColorPreview(
    Color color, {
    double size = 24,
    bool hasBorder = false,
  }) {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: color,
        border: hasBorder
            ? Border.all(color: Colors.grey.withAlpha(150), width: 1)
            : null,
      ),
    );
  }

  /// Construir preview del tema completo
  Widget _buildThemePreview(BuildContext context) {
    final theme = Theme.of(context);

    return Container(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(AppSizes.radiusL),
        border: Border.all(color: Colors.grey.withAlpha(100), width: 1),
      ),
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Título
          Text(
            'Vista previa del tema actual',
            style: Theme.of(context).textTheme.labelLarge,
          ),
          const SizedBox(height: 12),

          // Vista previa tipo AppBar
          Container(
            height: 40,
            decoration: BoxDecoration(
              color: theme.colorScheme.primary,
              borderRadius: BorderRadius.circular(AppSizes.radiusM),
            ),
            child: Center(
              child: Text(
                'AppBar Preview',
                style: theme.textTheme.titleSmall?.copyWith(
                  color: theme.colorScheme.onPrimary,
                ),
              ),
            ),
          ),
          const SizedBox(height: 12),

          // Ejemplo de contenido
          Container(
            decoration: BoxDecoration(
              color: theme.scaffoldBackgroundColor,
              borderRadius: BorderRadius.circular(AppSizes.radiusM),
              border: Border.all(color: Colors.grey.withAlpha(100), width: 1),
            ),
            padding: const EdgeInsets.all(12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Título de contenido', style: theme.textTheme.titleMedium),
                const SizedBox(height: 8),
                Text(
                  'Este es un texto normal de demostración para mostrar cómo se vería el contenido con este tema.',
                  style: theme.textTheme.bodyMedium,
                ),
                const SizedBox(height: 12),
                Row(
                  children: [
                    ElevatedButton(
                      onPressed: () {},
                      child: const Text('Botón'),
                    ),
                    const SizedBox(width: 8),
                    OutlinedButton(
                      onPressed: () {},
                      child: const Text('Outlined'),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

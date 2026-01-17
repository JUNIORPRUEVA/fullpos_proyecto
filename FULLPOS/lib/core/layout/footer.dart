import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../constants/app_sizes.dart';
import '../../features/settings/providers/theme_provider.dart';
import '../../features/settings/providers/business_settings_provider.dart';

/// Footer del layout principal
class Footer extends ConsumerWidget {
  const Footer({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final themeSettings = ref.watch(themeProvider);
    final businessSettings = ref.watch(businessSettingsProvider);
    final footerColor = themeSettings.footerColor;
    final footerTextColor = themeSettings.footerTextColor;
    final activeColor = themeSettings
        .sidebarActiveColor; // Usar el color activo para la versión
    final borderColor = Color.lerp(footerColor, Colors.white, 0.15)!;
    final year = DateTime.now().year;

    return Container(
      height: AppSizes.footerHeight,
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [footerColor, footerColor.withOpacity(0.85)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        border: Border(top: BorderSide(color: borderColor, width: 2)),
        boxShadow: const [
          BoxShadow(
            color: Colors.black26,
            blurRadius: 10,
            offset: Offset(0, -3),
          ),
          BoxShadow(
            color: Colors.white24,
            blurRadius: 6,
            offset: Offset(0, 1),
            spreadRadius: -2,
          ),
        ],
      ),
      padding: const EdgeInsets.symmetric(horizontal: AppSizes.paddingL),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            '© $year ${businessSettings.businessName.isNotEmpty ? businessSettings.businessName : 'FULLTECH, SRL'} - Sistema POS',
            style: TextStyle(color: footerTextColor, fontSize: 12),
          ),
          Text(
            'v1.0.0 Local',
            style: TextStyle(
              color: activeColor,
              fontSize: 12,
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ),
    );
  }
}

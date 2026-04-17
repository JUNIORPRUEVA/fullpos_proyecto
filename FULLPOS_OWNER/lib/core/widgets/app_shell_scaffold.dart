import 'package:flutter/material.dart';

import '../theme/app_colors.dart';
import 'app_background.dart';

class AppShellScaffold extends StatelessWidget {
  const AppShellScaffold({
    super.key,
    this.appBar,
    required this.title,
    required this.companyName,
    this.companySubtitle,
    this.username,
    this.version,
    required this.body,
    required this.currentRoute,
    required this.onDrawerNavigate,
    this.onLogout,
  });

  final PreferredSizeWidget? appBar;
  final String title;
  final String companyName;
  final String? companySubtitle;
  final String? username;
  final String? version;
  final Widget body;
  final String currentRoute;
  final ValueChanged<String> onDrawerNavigate;
  final Future<void> Function()? onLogout;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      backgroundColor: theme.scaffoldBackgroundColor,
      appBar: appBar ?? _buildAppBar(theme),
      body: AppBackground(
        child: SafeArea(
          bottom: false,
          child: LayoutBuilder(
            builder: (context, constraints) {
              final horizontalPadding = constraints.maxWidth >= 1180
                  ? 20.0
                  : 16.0;

              return Padding(
                padding: EdgeInsets.fromLTRB(
                  horizontalPadding,
                  16,
                  horizontalPadding,
                  18,
                ),
                child: body,
              );
            },
          ),
        ),
      ),
    );
  }

  PreferredSizeWidget _buildAppBar(ThemeData theme) {
    final scheme = theme.colorScheme;

    return AppBar(
      toolbarHeight: 56,
      elevation: 0,
      scrolledUnderElevation: 1,
      surfaceTintColor: Colors.transparent,
      backgroundColor: scheme.surface.withAlpha((0.94 * 255).round()),
      foregroundColor: AppColors.ink,
      shadowColor: Colors.black.withAlpha((0.04 * 255).round()),
      titleSpacing: 14,
      bottom: PreferredSize(
        preferredSize: const Size.fromHeight(1),
        child: Container(
          height: 1,
          color: AppColors.border.withAlpha((0.7 * 255).round()),
        ),
      ),
      title: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Text(
            title,
            style: theme.textTheme.titleMedium?.copyWith(
              color: AppColors.ink,
              fontWeight: FontWeight.w800,
              letterSpacing: -0.2,
              height: 1.0,
            ),
          ),
          if (companySubtitle != null && companySubtitle!.trim().isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(top: 3),
              child: Text(
                companySubtitle!,
                style: theme.textTheme.bodySmall?.copyWith(
                  color: AppColors.textSecondary,
                  fontWeight: FontWeight.w600,
                  height: 1.0,
                ),
              ),
            ),
        ],
      ),
    );
  }
}

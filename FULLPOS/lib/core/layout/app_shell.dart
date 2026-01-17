import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import '../window/window_service.dart';
import 'desktop_frame.dart';
import 'sidebar.dart';
import 'topbar.dart';
import 'footer.dart';

/// Layout principal de la aplicación (Sidebar + Topbar + Content + Footer)
class AppShell extends StatefulWidget {
  final Widget child;

  const AppShell({super.key, required this.child});

  static const double _drawerBreakpointWidth = 900;
  static const double _shortHeightBreakpoint = 560;

  @override
  State<AppShell> createState() => _AppShellState();
}

class _AppShellState extends State<AppShell> {
  static const double _breakpointHysteresis = 40;
  bool _didInitResponsive = false;
  bool _isNarrow = false;
  bool _isShort = false;

  bool get _isDesktop =>
      Platform.isWindows || Platform.isLinux || Platform.isMacOS;

  void _updateResponsive(BoxConstraints constraints) {
    if (!_didInitResponsive) {
      _didInitResponsive = true;
      _isNarrow = constraints.maxWidth < AppShell._drawerBreakpointWidth;
      _isShort = constraints.maxHeight < AppShell._shortHeightBreakpoint;
      return;
    }

    final narrowLower = AppShell._drawerBreakpointWidth - _breakpointHysteresis;
    final narrowUpper = AppShell._drawerBreakpointWidth + _breakpointHysteresis;
    if (constraints.maxWidth < narrowLower) _isNarrow = true;
    if (constraints.maxWidth > narrowUpper) _isNarrow = false;

    final shortLower = AppShell._shortHeightBreakpoint - _breakpointHysteresis;
    final shortUpper = AppShell._shortHeightBreakpoint + _breakpointHysteresis;
    if (constraints.maxHeight < shortLower) _isShort = true;
    if (constraints.maxHeight > shortUpper) _isShort = false;
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return ValueListenableBuilder<bool>(
      valueListenable: WindowService.fullScreenListenable,
      builder: (context, isFullScreen, _) {
        return LayoutBuilder(
          builder: (context, constraints) {
            _updateResponsive(constraints);

            final isNarrow = _isNarrow;
            final isShort = _isShort;
            final showFooter = !isShort;

            Widget topbar() {
              if (!isNarrow) return const Topbar();
              return Builder(
                builder: (context) => Topbar(
                  showMenuButton: true,
                  onMenuPressed: () => Scaffold.of(context).openDrawer(),
                ),
              );
            }

            final contentColumn = Column(
              children: [
                topbar(),
                Expanded(child: widget.child),
                if (showFooter) const Footer(),
              ],
            );

            final baseBody = Container(
              decoration: const BoxDecoration(color: Colors.white),
              child: isNarrow
                  ? SafeArea(child: contentColumn)
                  : Row(
                      children: [
                        const Sidebar(),
                        Expanded(child: contentColumn),
                      ],
                    ),
            );

            return Scaffold(
              backgroundColor: Theme.of(context).scaffoldBackgroundColor,
              drawer: isNarrow
                  ? const Drawer(
                      child: SafeArea(child: Sidebar(forcedCollapsed: false)),
                    )
                  : null,
              body: baseBody,
            );
          },
        );
      },
    );
  }
}

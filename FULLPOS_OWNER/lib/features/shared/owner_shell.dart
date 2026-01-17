import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import '../../core/widgets/app_shell_scaffold.dart';
import '../auth/data/auth_repository.dart';

class OwnerShell extends ConsumerWidget {
  const OwnerShell({super.key, required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final authState = ref.watch(authRepositoryProvider);
    final repo = ref.read(authRepositoryProvider.notifier);
    final currentRoute = GoRouterState.of(context).matchedLocation;

    return AppShellScaffold(
      child: child,
      title: 'Panel Owner',
      companyName: authState.companyName ?? 'Empresa',
      version: authState.ownerVersion,
      currentRoute: currentRoute,
      onLogout: () async {
        await repo.logout();
        if (context.mounted) context.go('/login');
      },
    );
  }
}

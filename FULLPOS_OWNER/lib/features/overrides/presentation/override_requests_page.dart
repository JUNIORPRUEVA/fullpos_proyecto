import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import '../../auth/data/auth_repository.dart';
import '../data/override_repository.dart';
import '../data/override_models.dart';

class OverrideRequestsPage extends ConsumerStatefulWidget {
  const OverrideRequestsPage({super.key});

  @override
  ConsumerState<OverrideRequestsPage> createState() =>
      _OverrideRequestsPageState();
}

class _OverrideRequestsPageState extends ConsumerState<OverrideRequestsPage> {
  bool _loading = true;
  String? _error;
  List<OverrideRequestItem> _requests = const [];

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final repo = ref.read(overrideRepositoryProvider);
      final result = await repo.fetchRequests();
      if (result.statusCode == 401) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Sesión vencida. Entra de nuevo.')),
          );
        }
        await ref.read(authRepositoryProvider.notifier).logout();
        if (mounted) context.go('/login');
        return;
      }
      if (result.statusCode >= 400) {
        if (!mounted) return;
        setState(() {
          _loading = false;
          _error = result.message ?? 'No se pudieron cargar las solicitudes.';
        });
        return;
      }
      if (!mounted) return;
      setState(() {
        _requests = result.items;
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _error = 'No se pudieron cargar las solicitudes.';
      });
    }
  }

  Future<void> _approveRequest(OverrideRequestItem item) async {
    try {
      final repo = ref.read(overrideRepositoryProvider);
      final result = await repo.approveRequest(item.id);
      if (result.statusCode == 401) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Sesión vencida. Entra de nuevo.')),
          );
        }
        await ref.read(authRepositoryProvider.notifier).logout();
        if (mounted) context.go('/login');
        return;
      }
      if (result.statusCode >= 400 || result.token == null) {
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(result.message ?? 'No se pudo aprobar la solicitud.'),
          ),
        );
        return;
      }
      if (!mounted) return;
      await showDialog<void>(
        context: context,
        builder: (_) => AlertDialog(
          title: const Text('Token generado'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('Solicitud: #${result.token!.requestId}'),
              const SizedBox(height: 6),
              SelectableText(
                result.token!.token,
                style: const TextStyle(fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 6),
              Text('Vence: ${result.token!.expiresAt}'),
            ],
          ),
          actions: [
            TextButton.icon(
              onPressed: () async {
                await Clipboard.setData(
                  ClipboardData(text: result.token!.token),
                );
                if (!mounted) return;
                ScaffoldMessenger.of(
                  context,
                ).showSnackBar(const SnackBar(content: Text('Token copiado.')));
              },
              icon: const Icon(Icons.copy),
              label: const Text('Copiar'),
            ),
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Cerrar'),
            ),
          ],
        ),
      );
      await _load();
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('No se pudo aprobar la solicitud.')),
      );
    }
  }

  Widget _buildRequestCard(OverrideRequestItem item) {
    final meta = item.meta ?? const <String, dynamic>{};
    final actionName = meta['action_name']?.toString();
    final actionDesc = meta['action_desc']?.toString();

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    actionName?.isNotEmpty == true
                        ? actionName!
                        : 'Accion: ${item.actionCode}',
                    style: const TextStyle(fontWeight: FontWeight.w700),
                  ),
                ),
                Text(
                  item.status,
                  style: const TextStyle(color: Colors.orangeAccent),
                ),
              ],
            ),
            if (actionDesc != null && actionDesc.trim().isNotEmpty) ...[
              const SizedBox(height: 6),
              Text(actionDesc),
            ],
            const SizedBox(height: 6),
            Text('Solicitado por: ${item.requestedByName ?? '-'}'),
            if (item.terminalId != null) Text('Terminal: ${item.terminalId}'),
            if (item.resourceType != null || item.resourceId != null)
              Text(
                'Recurso: ${item.resourceType ?? '-'} ${item.resourceId ?? ''}',
              ),
            const SizedBox(height: 6),
            Text('Fecha: ${item.createdAt}'),
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: _loading ? null : () => _approveRequest(item),
                    icon: const Icon(Icons.verified),
                    label: const Text('Aprobar y generar token'),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Autorizaciones'),
        actions: [
          IconButton(
            tooltip: 'Actualizar',
            onPressed: _loading ? null : _load,
            icon: const Icon(Icons.refresh),
          ),
          IconButton(
            tooltip: 'Historial de tokens',
            onPressed: () => context.go('/overrides/audit'),
            icon: const Icon(Icons.history),
          ),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : _error != null
          ? Center(child: Text(_error!))
          : _requests.isEmpty
          ? const Center(child: Text('No hay solicitudes pendientes.'))
          : ListView.separated(
              padding: const EdgeInsets.all(16),
              itemCount: _requests.length,
              separatorBuilder: (context, separatorIndex) =>
                  const SizedBox(height: 10),
              itemBuilder: (_, index) => _buildRequestCard(_requests[index]),
            ),
    );
  }
}

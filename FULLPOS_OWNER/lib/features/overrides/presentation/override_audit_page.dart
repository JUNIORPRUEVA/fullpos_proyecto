import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../../core/config/app_config.dart';
import '../../auth/data/auth_repository.dart';
import '../data/override_audit_models.dart';
import '../data/override_audit_repository.dart';

class OverrideAuditPage extends ConsumerStatefulWidget {
  const OverrideAuditPage({super.key});

  @override
  ConsumerState<OverrideAuditPage> createState() => _OverrideAuditPageState();
}

class _OverrideAuditPageState extends ConsumerState<OverrideAuditPage> {
  static final _dateFormat = DateFormat('dd/MM/yyyy HH:mm');

  bool _loading = true;
  String? _error;
  List<OverrideAuditEntry> _entries = const [];

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _load());
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final repo = ref.read(overrideAuditRepositoryProvider);
      final result = await repo.fetchAudit(limit: 200);
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
          _error =
              result.message ?? 'No se pudo cargar el historial de tokens.';
        });
        return;
      }
      if (!mounted) return;
      setState(() {
        _entries = result.items;
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _error = 'No se pudo cargar el historial de tokens.';
      });
    }
  }

  Future<void> _copyBaseUrl(String value) async {
    await Clipboard.setData(ClipboardData(text: value));
    if (!mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(const SnackBar(content: Text('URL de nube copiada')));
  }

  Color _resultColor(String value) {
    switch (value.toLowerCase()) {
      case 'approved':
        return Colors.greenAccent;
      case 'requested':
        return Colors.orangeAccent;
      case 'rejected':
        return Colors.redAccent;
      case 'expired':
      case 'invalid':
        return Colors.grey;
      default:
        return Colors.white;
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return Scaffold(
        appBar: AppBar(title: const Text('Historial de tokens')),
        body: const Center(child: CircularProgressIndicator()),
      );
    }

    final content = RefreshIndicator(
      onRefresh: _load,
      child: ListView.separated(
        physics: const AlwaysScrollableScrollPhysics(),
        padding: const EdgeInsets.all(16),
        itemCount:
            1 + (_error != null || _entries.isEmpty ? 1 : _entries.length),
        separatorBuilder: (context, separatorIndex) =>
            const SizedBox(height: 12),
        itemBuilder: (context, index) {
          if (index == 0) return _buildSetupCard();
          if (_error != null) return _buildErrorCard();
          if (_entries.isEmpty) return _buildEmptyState();
          final entry = _entries[index - 1];
          return _buildAuditCard(entry);
        },
      ),
    );

    return Scaffold(
      appBar: AppBar(title: const Text('Historial de tokens')),
      body: content,
    );
  }

  Widget _buildSetupCard() {
    final baseUrl = ref.watch(appConfigProvider).baseUrl;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Token en la nube',
              style: TextStyle(fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 6),
            const Text(
              'Este historial muestra todas las acciones autorizadas con tokens remotos. '
              'Comparte la URL de nube con el POS y activa la sincronización antes de enviar un token.',
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: SelectableText(
                    baseUrl,
                    style: const TextStyle(fontWeight: FontWeight.w600),
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.copy),
                  tooltip: 'Copiar URL',
                  onPressed: () => _copyBaseUrl(baseUrl),
                ),
              ],
            ),
            const SizedBox(height: 6),
            const Text(
              'Asegúrate de que el POS use esta URL en Configuración > Nube y que la API Key sea la misma '
              'que la variable OVERRIDE_API_KEY en el backend para que el cajero pueda ingresar tokens.',
              style: TextStyle(fontSize: 12),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildAuditCard(OverrideAuditEntry entry) {
    final methodLabel = entry.method.isNotEmpty ? entry.method : 'remote';
    final resultColor = _resultColor(entry.result);
    final requestedBy =
        entry.requestedByName ?? entry.requestedById?.toString() ?? '-';
    final approvedBy =
        entry.approvedByName ?? entry.approvedById?.toString() ?? '-';
    final hasResource =
        (entry.resourceType?.isNotEmpty == true) ||
        (entry.resourceId?.isNotEmpty == true);
    final resourceDesc = hasResource
        ? '${entry.resourceType ?? '-'} ${entry.resourceId ?? ''}'.trim()
        : null;
    final metaText = entry.meta?.entries
        .map((e) => '${e.key}: ${e.value}')
        .join(' · ');

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Chip(
                  label: Text(methodLabel.toUpperCase()),
                  visualDensity: VisualDensity.compact,
                ),
                const SizedBox(width: 8),
                Chip(
                  backgroundColor: resultColor.withAlpha((0.15 * 255).round()),
                  labelStyle: TextStyle(color: resultColor),
                  label: Text(entry.result.toUpperCase()),
                  visualDensity: VisualDensity.compact,
                ),
              ],
            ),
            const SizedBox(height: 10),
            Text(
              'Acción: ${entry.actionCode}',
              style: const TextStyle(fontWeight: FontWeight.w600),
            ),
            if (resourceDesc != null)
              Text(
                'Recurso: $resourceDesc',
                style: const TextStyle(fontSize: 12),
              ),
            const SizedBox(height: 8),
            Text('Solicitado por: $requestedBy'),
            Text('Aprobado por: $approvedBy'),
            if (entry.terminalId != null && entry.terminalId!.isNotEmpty)
              Text('Terminal: ${entry.terminalId}'),
            if (metaText != null && metaText.isNotEmpty)
              Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Text(
                  'Meta: $metaText',
                  style: const TextStyle(fontSize: 12, color: Colors.grey),
                ),
              ),
            Align(
              alignment: Alignment.topRight,
              child: Text(
                _dateFormat.format(entry.createdAt.toLocal()),
                style: TextStyle(color: Colors.grey[400], fontSize: 12),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildEmptyState() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Todavía no hay acciones con tokens',
              style: TextStyle(fontWeight: FontWeight.w600),
            ),
            const SizedBox(height: 6),
            const Text(
              'Cuando el dueño apruebe una solicitud remota, aparecerá aquí el registro del token y la acción.',
            ),
            const SizedBox(height: 10),
            ElevatedButton(onPressed: _load, child: const Text('Refrescar')),
          ],
        ),
      ),
    );
  }

  Widget _buildErrorCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'No pudimos cargar el historial',
              style: TextStyle(fontWeight: FontWeight.w600),
            ),
            const SizedBox(height: 6),
            Text(_error ?? 'Error inesperado'),
            const SizedBox(height: 10),
            ElevatedButton(
              onPressed: _load,
              child: const Text('Intentar de nuevo'),
            ),
          ],
        ),
      ),
    );
  }
}

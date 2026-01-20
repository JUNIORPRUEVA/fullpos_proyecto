import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/storage/secure_storage.dart';
import '../data/totp.dart';
import '../data/virtual_token_repository.dart';

class VirtualTokenPage extends ConsumerStatefulWidget {
  const VirtualTokenPage({super.key});

  @override
  ConsumerState<VirtualTokenPage> createState() => _VirtualTokenPageState();
}

class _VirtualTokenPageState extends ConsumerState<VirtualTokenPage> {
  final _terminalCtrl = TextEditingController();
  bool _loading = false;
  String? _error;

  String? _terminalId;
  String? _secret;
  int _digits = 6;
  int _periodSeconds = 30;

  DateTime _now = DateTime.now();
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _startTicker();
    WidgetsBinding.instance.addPostFrameCallback((_) => _loadSaved());
  }

  @override
  void dispose() {
    _timer?.cancel();
    _terminalCtrl.dispose();
    super.dispose();
  }

  void _startTicker() {
    _timer?.cancel();
    _timer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (!mounted) return;
      setState(() => _now = DateTime.now());
    });
  }

  Future<void> _loadSaved() async {
    final storage = ref.read(secureStorageProvider);
    final active = await storage.readActiveVirtualTerminal();
    if (!mounted) return;
    if (active != null) {
      final secret = await storage.readVirtualSecret(active);
      if (!mounted) return;
      setState(() {
        _terminalId = active;
        _terminalCtrl.text = active;
        _secret = secret;
      });
    }
  }

  Future<void> _activate() async {
    final terminalId = _terminalCtrl.text.trim();
    if (terminalId.isEmpty) return;

    setState(() {
      _loading = true;
      _error = null;
    });

    try {
      final repo = ref.read(virtualTokenRepositoryProvider);
      final provision = await repo.provision(terminalId: terminalId);

      final storage = ref.read(secureStorageProvider);
      await storage.saveVirtualSecret(
        terminalId: provision.terminalId,
        secretBase32: provision.secret,
      );
      await storage.setActiveVirtualTerminal(provision.terminalId);

      if (!mounted) return;
      setState(() {
        _terminalId = provision.terminalId;
        _secret = provision.secret;
        _digits = provision.digits;
        _periodSeconds = provision.periodSeconds;
        _loading = false;
      });

      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Token virtual activado')));
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _error =
            'No se pudo activar el token virtual. Verifica la nube y la sesión.';
      });
    }
  }

  Future<void> _clear() async {
    final terminalId = _terminalId ?? _terminalCtrl.text.trim();
    if (terminalId.isEmpty) return;
    final storage = ref.read(secureStorageProvider);
    await storage.removeVirtualSecret(terminalId);
    if (!mounted) return;
    setState(() {
      _terminalId = null;
      _secret = null;
    });
  }

  Future<void> _copy(String value) async {
    await Clipboard.setData(ClipboardData(text: value));
    if (!mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(const SnackBar(content: Text('Copiado')));
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    final secret = _secret;
    final hasToken = secret != null && secret.trim().isNotEmpty;

    String? code;
    String? codeError;
    int? remaining;
    if (hasToken) {
      try {
        code = generateTotpCode(
          secretBase32: secret,
          now: _now,
          digits: _digits,
          periodSeconds: _periodSeconds,
        );
        remaining = remainingSeconds(now: _now, periodSeconds: _periodSeconds);
      } catch (e) {
        codeError = e.toString();
      }
    }

    return Scaffold(
      appBar: AppBar(title: const Text('Token virtual')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Card(
              child: Padding(
                padding: const EdgeInsets.all(14),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Activación (por terminal)',
                      style: TextStyle(fontWeight: FontWeight.w700),
                    ),
                    const SizedBox(height: 6),
                    const Text(
                      'El POS debe enviar el Terminal ID. Activa el token para ese terminal y comparte el código vigente.',
                      style: TextStyle(fontSize: 12),
                    ),
                    const SizedBox(height: 12),
                    TextField(
                      controller: _terminalCtrl,
                      decoration: const InputDecoration(
                        labelText: 'Terminal ID (UID)',
                        hintText: 'Ej: TERM-001',
                      ),
                      textInputAction: TextInputAction.done,
                      onSubmitted: (_) => _activate(),
                    ),
                    const SizedBox(height: 10),
                    Row(
                      children: [
                        Expanded(
                          child: ElevatedButton.icon(
                            onPressed: _loading ? null : _activate,
                            icon: _loading
                                ? const SizedBox(
                                    width: 14,
                                    height: 14,
                                    child: CircularProgressIndicator(
                                      strokeWidth: 2,
                                    ),
                                  )
                                : const Icon(Icons.verified),
                            label: const Text('Activar token'),
                          ),
                        ),
                        const SizedBox(width: 10),
                        OutlinedButton(
                          onPressed: hasToken ? _clear : null,
                          child: const Text('Quitar'),
                        ),
                      ],
                    ),
                    if (_error != null) ...[
                      const SizedBox(height: 10),
                      Text(
                        _error!,
                        style: const TextStyle(color: Colors.redAccent),
                      ),
                    ],
                  ],
                ),
              ),
            ),
            const SizedBox(height: 14),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Código vigente',
                      style: theme.textTheme.titleMedium?.copyWith(
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    const SizedBox(height: 10),
                    if (!hasToken)
                      const Text('Activa el token para ver el código.')
                    else if (codeError != null)
                      Text('Error generando código: $codeError')
                    else ...[
                      Row(
                        children: const [
                          Icon(Icons.verified, color: Colors.green, size: 18),
                          SizedBox(width: 6),
                          Text(
                            'Token funcionando',
                            style: TextStyle(color: Colors.green),
                          ),
                        ],
                      ),
                      const SizedBox(height: 8),
                      Center(
                        child: SelectableText(
                          code!,
                          style: const TextStyle(
                            fontSize: 42,
                            fontWeight: FontWeight.w800,
                            letterSpacing: 4,
                          ),
                        ),
                      ),
                      const SizedBox(height: 8),
                      Center(
                        child: Text(
                          'Cambia en ${remaining ?? '-'}s',
                          style: const TextStyle(color: Colors.white70),
                        ),
                      ),
                      const SizedBox(height: 12),
                      Row(
                        children: [
                          Expanded(
                            child: ElevatedButton.icon(
                              onPressed: () => _copy(code!),
                              icon: const Icon(Icons.copy),
                              label: const Text('Copiar código'),
                            ),
                          ),
                        ],
                      ),
                      if ((_terminalId ?? '').isNotEmpty) ...[
                        const SizedBox(height: 10),
                        Text(
                          'Terminal: $_terminalId',
                          style: const TextStyle(color: Colors.white70),
                        ),
                      ],
                    ],
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

import '../../../core/constants/app_colors.dart';
import '../../../core/constants/app_sizes.dart';
import '../../../core/logging/app_logger.dart';

class LogsPage extends StatefulWidget {
  const LogsPage({super.key});

  @override
  State<LogsPage> createState() => _LogsPageState();
}

class _LogsPageState extends State<LogsPage> {
  bool _loading = true;
  String? _error;
  String? _logPath;
  String? _tail;

  bool get _showTechnicalDetails => kDebugMode;

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
      final path = await AppLogger.instance.exportLatestLogs();
      if (!mounted) return;

      if (path == null) {
        setState(() {
          _logPath = null;
          _tail = null;
          _loading = false;
          _error = 'No hay logs disponibles.';
        });
        return;
      }

      final file = File(path);
      if (!await file.exists()) {
        setState(() {
          _logPath = path;
          _tail = null;
          _loading = false;
          _error = 'No se encontró el archivo de logs.';
        });
        return;
      }

      // En producción no mostramos contenido técnico en pantalla.
      if (!_showTechnicalDetails) {
        setState(() {
          _logPath = path;
          _tail = null;
          _loading = false;
        });
        return;
      }

      final lines = await file.readAsLines();
      const maxLines = 200;
      final tailLines = lines.length <= maxLines
          ? lines
          : lines.sublist(lines.length - maxLines);

      setState(() {
        _logPath = path;
        _tail = tailLines.join('\n');
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _error = 'No se pudieron cargar los logs.';
      });
    }
  }

  Future<void> _copyToClipboard(String text, {required String label}) async {
    await Clipboard.setData(ClipboardData(text: text));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('$label copiado.'),
        backgroundColor: AppColors.success,
        duration: const Duration(seconds: 2),
      ),
    );
  }

  Future<void> _openLogsFolder() async {
    final logPath = _logPath;

    final dirPath =
        _showTechnicalDetails ? (logPath == null ? null : p.dirname(logPath)) : null;
    final targetDirPath = dirPath ?? (await () async {
      final docsDir = await getApplicationDocumentsDirectory();
      return p.join(docsDir.path, 'support_exports');
    }());

    try {
      if (Platform.isWindows) {
        await Process.run('explorer.exe', [targetDirPath]);
      } else if (Platform.isMacOS) {
        await Process.run('open', [targetDirPath]);
      } else if (Platform.isLinux) {
        await Process.run('xdg-open', [targetDirPath]);
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: const Text('No se pudo abrir la carpeta.'),
          backgroundColor: AppColors.error,
        ),
      );
    }
  }

  Future<void> _exportForSupport() async {
    final logPath = _logPath;
    if (logPath == null) return;

    try {
      final source = File(logPath);
      if (!await source.exists()) return;

      final docsDir = await getApplicationDocumentsDirectory();
      final outDir = Directory(p.join(docsDir.path, 'support_exports'));
      if (!await outDir.exists()) {
        await outDir.create(recursive: true);
      }

      final stamp = DateTime.now()
          .toIso8601String()
          .replaceAll(':', '-')
          .replaceAll('.', '-');
      final outPath = p.join(outDir.path, 'fullpos_log_$stamp.log');
      await source.copy(outPath);

      if (!mounted) return;
      if (_showTechnicalDetails) {
        await _copyToClipboard(outPath, label: 'Ruta del archivo');
      }
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: const Text(
            'Archivo generado para soporte. Envíalo al técnico si te lo solicitan.',
          ),
          backgroundColor: AppColors.success,
          duration: const Duration(seconds: 4),
        ),
      );
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: const Text('No se pudo exportar el archivo para soporte.'),
          backgroundColor: AppColors.error,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final tail = _tail;
    final logPath = _logPath;
    final showTechnical = _showTechnicalDetails;

    return Scaffold(
      backgroundColor: AppColors.bgLight,
      appBar: AppBar(
        title: const Text('Logs y soporte'),
        actions: [
          IconButton(
            tooltip: 'Recargar',
            onPressed: _loading ? null : _load,
            icon: const Icon(Icons.refresh),
          ),
        ],
      ),
      body: Padding(
        padding: const EdgeInsets.all(AppSizes.paddingL),
        child: _loading
            ? const Center(child: CircularProgressIndicator())
            : Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Container(
                    padding: const EdgeInsets.all(AppSizes.paddingM),
                    decoration: BoxDecoration(
                      color: Colors.white,
                      borderRadius: BorderRadius.circular(AppSizes.radiusM),
                      border: Border.all(color: AppColors.surfaceLightBorder),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'Qué ve el cliente',
                          style: TextStyle(fontWeight: FontWeight.w700),
                        ),
                        const SizedBox(height: 6),
                        const Text(
                          'El cliente solo ve un mensaje amigable. Los detalles técnicos se guardan para soporte.',
                          style: TextStyle(height: 1.25),
                        ),
                        if (showTechnical) ...[
                          const SizedBox(height: 8),
                          const Text(
                            'Modo debug: se muestran detalles técnicos en pantalla.',
                            style: TextStyle(color: Colors.grey),
                          ),
                        ],
                      ],
                    ),
                  ),
                  const SizedBox(height: AppSizes.spaceM),
                  Container(
                    padding: const EdgeInsets.all(AppSizes.paddingM),
                    decoration: BoxDecoration(
                      color: Colors.white,
                      borderRadius: BorderRadius.circular(AppSizes.radiusM),
                      border: Border.all(color: AppColors.surfaceLightBorder),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            const Expanded(
                              child: Text(
                                'Archivo actual',
                                style: TextStyle(fontWeight: FontWeight.w700),
                              ),
                            ),
                            if (showTechnical && logPath != null)
                              TextButton.icon(
                                onPressed: () =>
                                    _copyToClipboard(logPath, label: 'Ruta'),
                                icon: const Icon(Icons.copy, size: 18),
                                label: const Text('Copiar ruta'),
                              ),
                          ],
                        ),
                        const SizedBox(height: 6),
                        Text(
                          showTechnical
                              ? (logPath ?? _error ?? '—')
                              : 'Los detalles técnicos están ocultos en producción.',
                          style: const TextStyle(fontSize: 12, height: 1.25),
                        ),
                        const SizedBox(height: AppSizes.spaceM),
                        Wrap(
                          spacing: 10,
                          runSpacing: 10,
                          children: [
                            FilledButton.icon(
                              onPressed: logPath == null ? null : _exportForSupport,
                              icon: const Icon(Icons.support_agent),
                              label: const Text('Generar archivo para soporte'),
                            ),
                            OutlinedButton.icon(
                              onPressed: (logPath == null ||
                                      !(Platform.isWindows ||
                                          Platform.isMacOS ||
                                          Platform.isLinux))
                                  ? null
                                  : _openLogsFolder,
                              icon: const Icon(Icons.folder_open),
                              label: Text(
                                showTechnical
                                    ? 'Abrir carpeta'
                                    : 'Abrir carpeta de soporte',
                              ),
                            ),
                            if (showTechnical)
                              OutlinedButton.icon(
                                onPressed: tail == null
                                    ? null
                                    : () => _copyToClipboard(tail, label: 'Logs'),
                                icon: const Icon(Icons.copy_all),
                                label: const Text('Copiar últimos logs'),
                              ),
                          ],
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: AppSizes.spaceM),
                  if (showTechnical)
                    Expanded(
                      child: Container(
                        width: double.infinity,
                        padding: const EdgeInsets.all(AppSizes.paddingM),
                        decoration: BoxDecoration(
                          color: Colors.white,
                          borderRadius: BorderRadius.circular(AppSizes.radiusM),
                          border: Border.all(color: AppColors.surfaceLightBorder),
                        ),
                        child: tail == null
                            ? Center(
                                child: Text(
                                  _error ?? 'No hay contenido para mostrar.',
                                  style: const TextStyle(color: Colors.grey),
                                ),
                              )
                            : SingleChildScrollView(
                                child: SelectableText(
                                  tail,
                                  style: const TextStyle(
                                    fontSize: 12,
                                    height: 1.25,
                                    fontFamily: 'monospace',
                                  ),
                                ),
                              ),
                      ),
                    )
                  else
                    Expanded(
                      child: Container(
                        width: double.infinity,
                        padding: const EdgeInsets.all(AppSizes.paddingM),
                        decoration: BoxDecoration(
                          color: Colors.white,
                          borderRadius: BorderRadius.circular(AppSizes.radiusM),
                          border: Border.all(color: AppColors.surfaceLightBorder),
                        ),
                        child: const Center(
                          child: Text(
                            'Para asistencia, presiona “Generar archivo para soporte” y compártelo con el técnico.',
                            style: TextStyle(color: Colors.grey),
                            textAlign: TextAlign.center,
                          ),
                        ),
                      ),
                    ),
                ],
              ),
      ),
    );
  }
}

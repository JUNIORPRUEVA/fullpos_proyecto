import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

import '../../../core/constants/app_colors.dart';
import '../../../core/constants/app_sizes.dart';
import '../../../core/logging/app_logger.dart';

import 'training/training_page.dart';

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
  bool _companyInfoLoading = true;
  String? _companyInfoError;
  Map<String, String>? _companyInfo;

  static const String _companyInfoUrl = String.fromEnvironment(
    'FULLPOS_COMPANY_INFO_URL',
    defaultValue: '',
  );

  bool get _showTechnicalDetails => kDebugMode;

  @override
  void initState() {
    super.initState();
    _load();
    _loadCompanyInfo();
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

    final dirPath = _showTechnicalDetails
        ? (logPath == null ? null : p.dirname(logPath))
        : null;
    final targetDirPath =
        dirPath ??
        (await () async {
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

  Future<void> _loadCompanyInfo() async {
    if (_companyInfoUrl.trim().isEmpty) {
      setState(() {
        _companyInfoLoading = false;
        _companyInfoError =
            'No hay URL configurada. Define FULLPOS_COMPANY_INFO_URL.';
      });
      return;
    }

    setState(() {
      _companyInfoLoading = true;
      _companyInfoError = null;
    });

    try {
      final response = await http
          .get(Uri.parse(_companyInfoUrl))
          .timeout(const Duration(seconds: 6));
      if (response.statusCode != 200) {
        throw Exception('HTTP ${response.statusCode}');
      }
      final payload = jsonDecode(response.body) as Map<String, dynamic>;
      setState(() {
        _companyInfo = {
          'name': (payload['name'] ?? 'FULLPOS').toString(),
          'manager': (payload['manager'] ?? '').toString(),
          'phone': (payload['phone'] ?? '').toString(),
          'email': (payload['email'] ?? '').toString(),
          'address': (payload['address'] ?? '').toString(),
          'website': (payload['website'] ?? '').toString(),
          'support': (payload['support'] ?? '').toString(),
        };
        _companyInfoLoading = false;
      });
    } catch (e) {
      setState(() {
        _companyInfoLoading = false;
        _companyInfoError = 'No se pudo cargar la información desde internet.';
      });
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
            : ListView(
                children: [
                  const Text(
                    'Manejo de errores',
                    style: TextStyle(fontWeight: FontWeight.w800, fontSize: 16),
                  ),
                  const SizedBox(height: AppSizes.spaceS),
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
                          'Que ve el cliente',
                          style: TextStyle(fontWeight: FontWeight.w700),
                        ),
                        const SizedBox(height: 6),
                        const Text(
                          'El cliente solo ve un mensaje amigable. Los detalles tecnicos se guardan para soporte.',
                          style: TextStyle(height: 1.25),
                        ),
                        if (showTechnical) ...[
                          const SizedBox(height: 8),
                          const Text(
                            'Modo debug: se muestran detalles tecnicos en pantalla.',
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
                                'Archivo de soporte',
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
                              ? (logPath ?? _error ?? '?')
                              : 'Los detalles tecnicos estan ocultos en produccion.',
                          style: const TextStyle(fontSize: 12, height: 1.25),
                        ),
                        const SizedBox(height: AppSizes.spaceM),
                        Wrap(
                          spacing: 10,
                          runSpacing: 10,
                          children: [
                            FilledButton.icon(
                              onPressed: logPath == null
                                  ? null
                                  : _exportForSupport,
                              icon: const Icon(Icons.support_agent),
                              label: const Text('Generar archivo para soporte'),
                            ),
                            OutlinedButton.icon(
                              onPressed:
                                  (logPath == null ||
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
                                    : () =>
                                          _copyToClipboard(tail, label: 'Logs'),
                                icon: const Icon(Icons.copy_all),
                                label: const Text('Copiar ultimos logs'),
                              ),
                          ],
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: AppSizes.spaceM),
                  if (showTechnical)
                    Container(
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
                    )
                  else
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(AppSizes.paddingM),
                      decoration: BoxDecoration(
                        color: Colors.white,
                        borderRadius: BorderRadius.circular(AppSizes.radiusM),
                        border: Border.all(color: AppColors.surfaceLightBorder),
                      ),
                      child: const Center(
                        child: Text(
                          'Para asistencia, presiona "Generar archivo para soporte" y compartelo con el tecnico.',
                          style: TextStyle(color: Colors.grey),
                          textAlign: TextAlign.center,
                        ),
                      ),
                    ),
                  const SizedBox(height: AppSizes.spaceL),
                  const Text(
                    'Entrenamiento',
                    style: TextStyle(fontWeight: FontWeight.w800, fontSize: 16),
                  ),
                  const SizedBox(height: AppSizes.spaceS),
                  Container(
                    decoration: BoxDecoration(
                      color: Colors.white,
                      borderRadius: BorderRadius.circular(AppSizes.radiusM),
                      border: Border.all(color: AppColors.surfaceLightBorder),
                    ),
                    child: ListTile(
                      leading: const Icon(Icons.school, color: AppColors.teal),
                      title: const Text(
                        'Abrir entrenamiento',
                        style: TextStyle(fontWeight: FontWeight.w700),
                      ),
                      subtitle: const Text(
                        'Instalación paso a paso, manual completo y capacitación por módulo con buscador.',
                      ),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () {
                        Navigator.push(
                          context,
                          MaterialPageRoute(
                            builder: (_) => const TrainingPage(),
                          ),
                        );
                      },
                    ),
                  ),
                  const SizedBox(height: AppSizes.spaceL),
                  Row(
                    children: [
                      const Expanded(
                        child: Text(
                          'Informacion de la empresa',
                          style: TextStyle(
                            fontWeight: FontWeight.w800,
                            fontSize: 16,
                          ),
                        ),
                      ),
                      IconButton(
                        tooltip: 'Actualizar',
                        onPressed: _companyInfoLoading
                            ? null
                            : _loadCompanyInfo,
                        icon: const Icon(Icons.refresh),
                      ),
                    ],
                  ),
                  const SizedBox(height: AppSizes.spaceS),
                  Container(
                    padding: const EdgeInsets.all(AppSizes.paddingM),
                    decoration: BoxDecoration(
                      color: Colors.white,
                      borderRadius: BorderRadius.circular(AppSizes.radiusM),
                      border: Border.all(color: AppColors.surfaceLightBorder),
                    ),
                    child: _companyInfoLoading
                        ? const Center(child: CircularProgressIndicator())
                        : _companyInfoError != null
                        ? Text(
                            _companyInfoError!,
                            style: const TextStyle(color: Colors.grey),
                          )
                        : _buildCompanyInfoCard(),
                  ),
                ],
              ),
      ),
    );
  }

  Widget _buildCompanyInfoCard() {
    final info = _companyInfo ?? const <String, String>{};

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          info['name']?.isNotEmpty == true ? info['name']! : 'FULLPOS',
          style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
        ),
        const SizedBox(height: 8),
        _buildInfoRow('Gerente', info['manager']),
        _buildInfoRow('Telefono', info['phone']),
        _buildInfoRow('Correo', info['email']),
        _buildInfoRow('Direccion', info['address']),
        _buildInfoRow('Web', info['website']),
        _buildInfoRow('Soporte', info['support']),
        const SizedBox(height: 8),
        const Text(
          'Esta informacion se actualiza desde el servidor cuando hay internet.',
          style: TextStyle(color: Colors.grey, fontSize: 12),
        ),
      ],
    );
  }

  Widget _buildInfoRow(String label, String? value) {
    final text = (value ?? '').trim().isNotEmpty ? value!.trim() : '-';
    return Padding(
      padding: const EdgeInsets.only(bottom: 4),
      child: Row(
        children: [
          SizedBox(
            width: 110,
            child: Text(
              label,
              style: const TextStyle(fontWeight: FontWeight.w600),
            ),
          ),
          Expanded(child: Text(text)),
        ],
      ),
    );
  }
}

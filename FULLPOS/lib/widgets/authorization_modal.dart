import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../core/security/app_actions.dart';
import '../core/security/authorization_service.dart';
import '../core/security/scanner_input_controller.dart';
import '../core/security/security_config.dart';
import '../core/services/app_configuration_service.dart';

class AuthorizationModal extends StatefulWidget {
  final AppAction action;
  final String resourceType;
  final String? resourceId;
  final int companyId;
  final int requestedByUserId;
  final String terminalId;
  final SecurityConfig config;
  final bool isOnline;

  const AuthorizationModal({
    super.key,
    required this.action,
    required this.resourceType,
    required this.resourceId,
    required this.companyId,
    required this.requestedByUserId,
    required this.terminalId,
    required this.config,
    required this.isOnline,
  });

  static Future<bool> show({
    required BuildContext context,
    required AppAction action,
    required String resourceType,
    String? resourceId,
    required int companyId,
    required int requestedByUserId,
    required String terminalId,
    required SecurityConfig config,
    required bool isOnline,
  }) async {
    final result = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (_) => AuthorizationModal(
        action: action,
        resourceType: resourceType,
        resourceId: resourceId,
        companyId: companyId,
        requestedByUserId: requestedByUserId,
        terminalId: terminalId,
        config: config,
        isOnline: isOnline,
      ),
    );
    return result ?? false;
  }

  @override
  State<AuthorizationModal> createState() => _AuthorizationModalState();
}

class _AuthorizationModalState extends State<AuthorizationModal> {
  final TextEditingController _tokenController = TextEditingController();
  final TextEditingController _pinController = TextEditingController();
  ScannerInputController? _scanner;
  bool _isProcessing = false;
  String? _lastGeneratedToken;
  DateTime? _lastGeneratedExpiry;
  bool _remoteRequesting = false;
  int? _remoteRequestId;
  String? _remoteStatus;
  String? _remoteError;

  @override
  void initState() {
    super.initState();
    if (widget.config.scannerEnabled) {
      _scanner = ScannerInputController(
        enabled: true,
        suffix: widget.config.scannerSuffix,
        prefix: widget.config.scannerPrefix,
        timeout: Duration(milliseconds: widget.config.scannerTimeoutMs),
        onScan: (data) {
          _tokenController.text = data.trim();
          _validateToken();
        },
      );
    }
  }

  @override
  void dispose() {
    _scanner?.dispose();
    _tokenController.dispose();
    _pinController.dispose();
    super.dispose();
  }

  String? _resolveRemoteBaseUrl() {
    try {
      final settings = appConfigService.settings;
      if (!settings.cloudEnabled) return null;
      final endpoint = settings.cloudEndpoint?.trim();
      if (endpoint == null || endpoint.isEmpty) return null;
      return endpoint;
    } catch (_) {
      return null;
    }
  }

  String? _resolveRemoteApiKey() {
    try {
      final settings = appConfigService.settings;
      final key = settings.cloudApiKey?.trim();
      if (key == null || key.isEmpty) return null;
      return key;
    } catch (_) {
      return null;
    }
  }

  Future<void> _copyText(String label, String value) async {
    await Clipboard.setData(ClipboardData(text: value));
    _showMessage('$label copiado.');
  }

  Future<void> _requestRemoteApproval() async {
    final baseUrl = _resolveRemoteBaseUrl();
    if (baseUrl == null) {
      _showMessage('Configura la URL de nube para solicitudes remotas.');
      return;
    }

    setState(() {
      _remoteRequesting = true;
      _remoteError = null;
    });
    try {
      final result = await AuthorizationService.createRemoteOverrideRequest(
        baseUrl: baseUrl,
        apiKey: _resolveRemoteApiKey(),
        actionCode: widget.action.code,
        resourceType: widget.resourceType,
        resourceId: widget.resourceId,
        companyId: widget.companyId,
        requestedByUserId: widget.requestedByUserId,
        terminalId: widget.terminalId,
        meta: {
          'action_name': widget.action.name,
          'action_desc': widget.action.description,
          'terminal_id': widget.terminalId,
        },
      );
      if (!mounted) return;
      setState(() {
        _remoteRequestId = result.requestId;
        _remoteStatus = result.status;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() => _remoteError = 'No se pudo crear la solicitud remota.');
    } finally {
      if (mounted) {
        setState(() => _remoteRequesting = false);
      }
    }
  }

  Future<void> _authorizeWithPin() async {
    final pin = _pinController.text.trim();
    if (pin.isEmpty) return;
    setState(() => _isProcessing = true);
    try {
      final generated = await AuthorizationService.generateOfflinePinToken(
        pin: pin,
        actionCode: widget.action.code,
        resourceType: widget.resourceType,
        resourceId: widget.resourceId,
        companyId: widget.companyId,
        requestedByUserId: widget.requestedByUserId,
        terminalId: widget.terminalId,
      );
      final result = await AuthorizationService.validateAndConsumeToken(
        token: generated.token,
        actionCode: widget.action.code,
        resourceType: widget.resourceType,
        resourceId: widget.resourceId,
        companyId: widget.companyId,
        usedByUserId: widget.requestedByUserId,
        terminalId: widget.terminalId,
      );
      _handleResult(result);
    } catch (e) {
      _showMessage('Error: $e');
    } finally {
      if (mounted) setState(() => _isProcessing = false);
    }
  }

  Future<void> _generateBarcodeToken() async {
    setState(() => _isProcessing = true);
    try {
      final generated = await AuthorizationService.generateLocalBarcodeToken(
        actionCode: widget.action.code,
        resourceType: widget.resourceType,
        resourceId: widget.resourceId,
        companyId: widget.companyId,
        requestedByUserId: widget.requestedByUserId,
        terminalId: widget.terminalId,
      );
      setState(() {
        _lastGeneratedToken = generated.token;
        _lastGeneratedExpiry = generated.expiresAt;
      });
    } catch (e) {
      _showMessage('No se pudo generar el token: $e');
    } finally {
      if (mounted) setState(() => _isProcessing = false);
    }
  }

  Future<void> _validateToken() async {
    final token = _tokenController.text.trim();
    if (token.isEmpty) return;
    setState(() => _isProcessing = true);
    try {
      final result = await AuthorizationService.validateAndConsumeToken(
        token: token,
        actionCode: widget.action.code,
        resourceType: widget.resourceType,
        resourceId: widget.resourceId,
        companyId: widget.companyId,
        usedByUserId: widget.requestedByUserId,
        terminalId: widget.terminalId,
        allowRemote: widget.config.remoteEnabled && widget.isOnline,
        remoteBaseUrl: _resolveRemoteBaseUrl(),
        remoteApiKey: _resolveRemoteApiKey(),
        remoteRequestId: _remoteRequestId,
      );
      _handleResult(result);
    } catch (e) {
      _showMessage('Error validando token: $e');
    } finally {
      if (mounted) setState(() => _isProcessing = false);
    }
  }

  void _handleResult(AuthorizationResult result) {
    if (result.success) {
      Navigator.of(context).pop(true);
    } else {
      _showMessage(result.message);
    }
  }

  void _showMessage(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message)),
    );
  }

  @override
  Widget build(BuildContext context) {
    final risk = widget.action.risk.toString().split('.').last;

    Widget content = Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Acción: ${widget.action.name}',
          style: const TextStyle(fontWeight: FontWeight.bold),
        ),
        const SizedBox(height: 4),
        Text(widget.action.description),
        const SizedBox(height: 4),
        Text('Riesgo: $risk'),
        const SizedBox(height: 16),
        if (widget.config.offlinePinEnabled) _buildPinSection(),
        if (widget.config.offlineBarcodeEnabled) _buildBarcodeSection(),
        _buildTokenInputSection(),
        _buildRemoteSection(),
      ],
    );

    if (_scanner != null) {
      content = RawKeyboardListener(
        focusNode: FocusNode(),
        autofocus: true,
        onKey: _scanner!.handleKeyEvent,
        child: content,
      );
    }

    return AlertDialog(
      title: const Text('Se requiere autorización'),
      content: SingleChildScrollView(child: content),
      actions: [
        TextButton(
          onPressed: _isProcessing ? null : () => Navigator.of(context).pop(false),
          child: const Text('Cancelar'),
        ),
      ],
    );
  }

  Widget _buildPinSection() {
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Método offline: PIN (OTP de un solo uso)',
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _pinController,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'PIN de administrador',
              ),
            ),
            const SizedBox(height: 8),
            ElevatedButton.icon(
              onPressed: _isProcessing ? null : _authorizeWithPin,
              icon: const Icon(Icons.shield),
              label: const Text('Autorizar con PIN'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildBarcodeSection() {
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Método offline: Código local (QR/Barcode)',
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            ElevatedButton.icon(
              onPressed: _isProcessing ? null : _generateBarcodeToken,
              icon: const Icon(Icons.qr_code),
              label: const Text('Generar token local'),
            ),
            if (_lastGeneratedToken != null) ...[
              const SizedBox(height: 8),
              const Text('Token generado (escanee con el lector):'),
              SelectableText(
                _lastGeneratedToken!,
                style: const TextStyle(fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 8),
              Center(
                child: Container(
                  color: Colors.white,
                  padding: const EdgeInsets.all(6),
                  child: QrImageView(
                    data: _lastGeneratedToken!,
                    size: 160,
                  ),
                ),
              ),
              if (_lastGeneratedExpiry != null)
                Text(
                  'Vence: ${_lastGeneratedExpiry!}',
                  style: const TextStyle(color: Colors.grey),
                ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildTokenInputSection() {
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Ingresar o escanear código',
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _tokenController,
              decoration: const InputDecoration(
                labelText: 'Token de autorización',
              ),
              onSubmitted: (_) => _validateToken(),
            ),
            const SizedBox(height: 8),
            ElevatedButton.icon(
              onPressed: _isProcessing ? null : _validateToken,
              icon: const Icon(Icons.verified_user),
              label: const Text('Validar token'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildRemoteSection() {
    if (!widget.config.remoteEnabled) return const SizedBox.shrink();

    if (!widget.isOnline) {
      return const Padding(
        padding: EdgeInsets.symmetric(vertical: 8),
        child: Text(
          'Metodo remoto requiere internet.',
          style: TextStyle(color: Colors.orange),
        ),
      );
    }

    final baseUrl = _resolveRemoteBaseUrl();
    if (baseUrl == null) {
      return const Padding(
        padding: EdgeInsets.symmetric(vertical: 8),
        child: Text(
          'Configura la nube para solicitudes remotas.',
          style: TextStyle(color: Colors.orange),
        ),
      );
    }

    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Metodo remoto (nube)',
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 6),
            const Text(
              'Envia una solicitud al dueno para aprobar a distancia.',
            ),
            if (_remoteRequestId != null) ...[
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: Text(
                      'Solicitud: #${_remoteRequestId!} (${_remoteStatus ?? 'pending'})',
                      style: const TextStyle(fontWeight: FontWeight.w600),
                    ),
                  ),
                  TextButton.icon(
                    onPressed: () =>
                        _copyText('ID de solicitud', _remoteRequestId!.toString()),
                    icon: const Icon(Icons.copy, size: 16),
                    label: const Text('Copiar'),
                  ),
                ],
              ),
            ],
            if (_remoteError != null) ...[
              const SizedBox(height: 6),
              Text(
                _remoteError!,
                style: const TextStyle(color: Colors.redAccent),
              ),
            ],
            const SizedBox(height: 8),
            ElevatedButton.icon(
              onPressed: _remoteRequesting ? null : _requestRemoteApproval,
              icon: _remoteRequesting
                  ? const SizedBox(
                      width: 14,
                      height: 14,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.cloud_done),
              label: const Text('Solicitar permiso remoto'),
            ),
          ],
        ),
      ),
    );
  }
}

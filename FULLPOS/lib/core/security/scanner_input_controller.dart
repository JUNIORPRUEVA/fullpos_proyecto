import 'dart:async';

import 'package:flutter/services.dart';

/// Controlador reutilizable para lectores de códigos que actúan como teclado.
class ScannerInputController {
  final bool enabled;
  final String suffix;
  final String? prefix;
  final Duration timeout;
  final void Function(String data)? onScan;

  final StringBuffer _buffer = StringBuffer();
  Timer? _timer;

  ScannerInputController({
    required this.enabled,
    required this.suffix,
    required this.timeout,
    this.prefix,
    this.onScan,
  });

  void handleKeyEvent(RawKeyEvent event) {
    if (!enabled) return;
    if (event is! RawKeyDownEvent) return;
    final character = event.character;
    if (character == null || character.isEmpty) return;

    _buffer.write(character);
    _restartTimer();

    final text = _buffer.toString();
    if (text.endsWith(suffix)) {
      _emitBuffer(trimSuffix: true);
    }
  }

  void _restartTimer() {
    _timer?.cancel();
    _timer = Timer(timeout, () {
      _emitBuffer(trimSuffix: false);
    });
  }

  void _emitBuffer({required bool trimSuffix}) {
    if (_buffer.isEmpty) return;
    var data = _buffer.toString();
    if (trimSuffix && data.endsWith(suffix)) {
      data = data.substring(0, data.length - suffix.length);
    }
    if (prefix != null && prefix!.isNotEmpty && data.startsWith(prefix!)) {
      data = data.substring(prefix!.length);
    }
    _buffer.clear();
    _timer?.cancel();
    onScan?.call(data);
  }

  void dispose() {
    _timer?.cancel();
  }
}

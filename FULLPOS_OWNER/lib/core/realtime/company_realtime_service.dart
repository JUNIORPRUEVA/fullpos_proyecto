import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:socket_io_client/socket_io_client.dart' as io;

import '../config/app_config.dart';
import '../storage/secure_storage.dart';
import '../../features/auth/data/auth_state.dart';

class CompanyRealtimeMessage {
  const CompanyRealtimeMessage({
    required this.eventId,
    required this.entity,
    required this.action,
    required this.occurredAt,
  });

  final String eventId;
  final String entity;
  final String action;
  final DateTime occurredAt;
}

class CompanyRealtimeService {
  CompanyRealtimeService(this._storage, this._baseUrl);

  final SecureStorage _storage;
  final String _baseUrl;
  final StreamController<CompanyRealtimeMessage> _controller =
      StreamController<CompanyRealtimeMessage>.broadcast();
  final Set<String> _seenEventIds = <String>{};

  io.Socket? _socket;
  String? _activeToken;
  String connectionState = 'disconnected';

  Stream<CompanyRealtimeMessage> get stream => _controller.stream;

  Future<void> connect(AuthState authState) async {
    final token = authState.accessToken ?? await _storage.readToken();
    if (token == null || token.trim().isEmpty) {
      disconnect();
      return;
    }

    final normalizedToken = token.trim();
    final existing = _socket;
    if (_activeToken == normalizedToken &&
        existing != null &&
        (existing.connected || existing.active)) {
      return;
    }

    if (_activeToken != normalizedToken) {
      disconnect();
    }

    final socket = io.io(
      _baseUrl,
      io.OptionBuilder()
          .setTransports(['websocket'])
          .disableAutoConnect()
          .enableReconnection()
          .setReconnectionAttempts(999999)
          .setReconnectionDelay(1500)
          .setAuth({'token': normalizedToken})
          .build(),
    );

    socket.onConnect((_) {
      connectionState = 'connected';
    });
    socket.onDisconnect((_) {
      connectionState = 'disconnected';
    });
    socket.onConnectError((_) {
      connectionState = 'error';
    });
    socket.on('company.data_changed', (data) {
      if (data is! Map) return;
      final payload = Map<String, dynamic>.from(data);
      final eventId = payload['eventId']?.toString() ?? '';
      if (eventId.isNotEmpty && !_seenEventIds.add(eventId)) {
        return;
      }
      if (_seenEventIds.length > 300) {
        _seenEventIds.remove(_seenEventIds.first);
      }

      final occurredAtRaw = payload['occurredAt']?.toString();
      _controller.add(
        CompanyRealtimeMessage(
          eventId: eventId,
          entity: payload['entity']?.toString() ?? 'unknown',
          action: payload['action']?.toString() ?? 'updated',
          occurredAt: occurredAtRaw == null
              ? DateTime.now()
              : DateTime.tryParse(occurredAtRaw) ?? DateTime.now(),
        ),
      );
    });

    connectionState = 'connecting';
    _activeToken = normalizedToken;
    socket.connect();
    _socket = socket;
  }

  void disconnect() {
    _socket?.dispose();
    _socket = null;
    _activeToken = null;
    connectionState = 'disconnected';
  }
}

final companyRealtimeServiceProvider = Provider<CompanyRealtimeService>((ref) {
  final storage = ref.read(secureStorageProvider);
  final config = ref.watch(appConfigProvider);
  return CompanyRealtimeService(storage, config.baseUrl);
});
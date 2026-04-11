import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:socket_io_client/socket_io_client.dart' as io;

import '../../../core/config/app_config.dart';
import '../../../core/storage/secure_storage.dart';
import '../../auth/data/auth_state.dart';

class SaleRealtimeMessage {
  const SaleRealtimeMessage({
    required this.eventId,
    required this.type,
    required this.sale,
  });

  final String eventId;
  final String type;
  final Map<String, dynamic> sale;
}

class SaleRealtimeService {
  SaleRealtimeService(this._storage, this._baseUrl);

  final SecureStorage _storage;
  final String _baseUrl;
  final StreamController<SaleRealtimeMessage> _controller =
      StreamController<SaleRealtimeMessage>.broadcast();
  final Set<String> _seenEventIds = <String>{};

  io.Socket? _socket;
  String? _activeToken;
  String connectionState = 'disconnected';

  Stream<SaleRealtimeMessage> get stream => _controller.stream;

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
    socket.on('sale.event', (data) {
      if (data is! Map) return;
      final payload = Map<String, dynamic>.from(data);
      final eventId = payload['eventId']?.toString() ?? '';
      if (eventId.isNotEmpty && !_seenEventIds.add(eventId)) {
        return;
      }
      if (_seenEventIds.length > 200) {
        _seenEventIds.remove(_seenEventIds.first);
      }

      final saleJson = payload['sale'];
      if (saleJson is! Map) return;
      _controller.add(
        SaleRealtimeMessage(
          eventId: eventId,
          type: payload['type']?.toString() ?? 'sale.updated',
          sale: Map<String, dynamic>.from(saleJson),
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

final saleRealtimeServiceProvider = Provider<SaleRealtimeService>((ref) {
  final storage = ref.read(secureStorageProvider);
  final config = ref.watch(appConfigProvider);
  return SaleRealtimeService(storage, config.baseUrl);
});
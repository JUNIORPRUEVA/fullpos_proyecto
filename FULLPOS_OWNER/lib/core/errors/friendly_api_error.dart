import 'dart:io';

import 'package:dio/dio.dart';

class FriendlyApiError {
  static String message(
    Object error, {
    String fallback = 'No pudimos completar la operación. Intenta nuevamente.',
  }) {
    if (error is DioException) {
      return _fromDio(error, fallback: fallback);
    }

    return fallback;
  }

  static String messageFromResponse({
    required int statusCode,
    required dynamic data,
    String fallback = 'No pudimos completar la operación. Intenta nuevamente.',
  }) {
    final apiCode = _readStringKey(data, 'errorCode');
    final apiMessage = _readStringKey(data, 'message');

    final codeMessage = _messageForErrorCode(apiCode);
    if (codeMessage != null) return codeMessage;

    if (statusCode == 401) {
      return 'Tu sesión venció. Inicia sesión nuevamente.';
    }
    if (statusCode == 403) {
      return 'No tienes permiso para realizar esta acción.';
    }
    if (statusCode == 404) {
      return 'Servicio no disponible. Intenta más tarde.';
    }
    if (statusCode == 429) {
      return 'Demasiados intentos. Espera un momento e intenta nuevamente.';
    }
    if (statusCode >= 500) {
      return 'Estamos teniendo problemas en el servidor. Intenta más tarde.';
    }

    final safe = _sanitizeApiMessage(apiMessage);
    if (safe != null) return safe;

    return fallback;
  }

  static String _fromDio(DioException error, {required String fallback}) {
    // Network conditions first.
    if (error.type == DioExceptionType.connectionTimeout ||
        error.type == DioExceptionType.receiveTimeout ||
        error.type == DioExceptionType.sendTimeout) {
      return 'La conexión está lenta. Verifica tu Internet e intenta nuevamente.';
    }

    if (error.type == DioExceptionType.connectionError) {
      final inner = error.error;
      if (inner is SocketException) {
        return 'Parece que no tienes Internet. Conéctate e intenta nuevamente.';
      }
      return 'No pudimos conectarnos. Verifica tu Internet e intenta nuevamente.';
    }

    if (error.type == DioExceptionType.badCertificate) {
      return 'No se pudo establecer una conexión segura. Intenta más tarde.';
    }

    // HTTP responses.
    final status = error.response?.statusCode;
    if (status != null) {
      return messageFromResponse(
        statusCode: status,
        data: error.response?.data,
        fallback: fallback,
      );
    }

    return fallback;
  }

  static String? _readStringKey(dynamic data, String key) {
    if (data is Map) {
      final value = data[key];
      final text = value?.toString();
      if (text != null && text.trim().isNotEmpty) return text.trim();
    }
    return null;
  }

  static String? _messageForErrorCode(String? code) {
    if (code == null || code.trim().isEmpty) return null;

    switch (code) {
      // Common auth/session.
      case 'AUTH_ROLE_NOT_ALLOWED':
        return 'Tu cuenta no tiene acceso a esta aplicación.';

      // Override/virtual token typical cases.
      case 'OVERRIDE_TOKEN_INVALID':
      case 'OVERRIDE_TOKEN_NOT_FOUND':
        return 'El código ingresado no es válido. Verifícalo e intenta nuevamente.';
      case 'OVERRIDE_TOKEN_EXPIRED':
        return 'El código ya venció. Genera uno nuevo e intenta nuevamente.';
      case 'OVERRIDE_TOKEN_USED':
        return 'Ese código ya fue utilizado. Genera uno nuevo e intenta nuevamente.';
      case 'OVERRIDE_TERMINAL_CONFLICT':
        return 'Este dispositivo está asociado a otra empresa. Contacta soporte.';
      case 'OVERRIDE_TERMINAL_NOT_FOUND':
      case 'OVERRIDE_TERMINAL_REQUIRED':
        return 'No pudimos identificar la terminal. Intenta nuevamente.';
      case 'OVERRIDE_USER_NOT_FOUND':
        return 'No pudimos identificar el usuario. Verifica los datos e intenta nuevamente.';
      case 'VIRTUAL_TOKEN_DISABLED':
      case 'VIRTUAL_TOKEN_NOT_ENABLED':
        return 'El token virtual no está disponible en este momento.';

      default:
        return null;
    }
  }

  static String? _sanitizeApiMessage(String? message) {
    if (message == null) return null;
    final text = message.trim();
    if (text.isEmpty) return null;

    final lowered = text.toLowerCase();
    // Hide technical/internal messages.
    final looksTechnical =
        lowered.contains('prisma') ||
        lowered.contains('stack') ||
        lowered.contains('exception') ||
        lowered.contains('assert') ||
        lowered.contains('fkey') ||
        lowered.contains('sql') ||
        lowered.contains('tokenhash') ||
        lowered.contains('p2002') ||
        lowered.contains('p2003') ||
        lowered.contains('sequelize') ||
        lowered.contains('null') ||
        lowered.contains('undefined');

    if (looksTechnical) return null;

    // Keep it short and user-facing.
    if (text.length > 180) return null;

    return text;
  }
}

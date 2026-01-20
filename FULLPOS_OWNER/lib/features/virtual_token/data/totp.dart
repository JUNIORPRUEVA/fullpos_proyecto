import 'dart:typed_data';

import 'package:crypto/crypto.dart';

Uint8List _base32Decode(String input) {
  final normalized = input.toUpperCase().replaceAll('=', '').replaceAll(' ', '');
  if (normalized.isEmpty) return Uint8List(0);

  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  final lookup = <int, int>{};
  for (var i = 0; i < alphabet.length; i++) {
    lookup[alphabet.codeUnitAt(i)] = i;
  }

  var bits = 0;
  var value = 0;
  final bytes = <int>[];

  for (final rune in normalized.runes) {
    final v = lookup[rune];
    if (v == null) {
      throw const FormatException('Base32 inválido');
    }
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bytes.add((value >> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Uint8List.fromList(bytes);
}

String generateTotpCode({
  required String secretBase32,
  required DateTime now,
  int digits = 6,
  int periodSeconds = 30,
}) {
  final secret = _base32Decode(secretBase32);
  final counter = now.millisecondsSinceEpoch ~/ 1000 ~/ periodSeconds;
  final counterBytes = Uint8List(8);
  var c = counter;
  for (var i = 7; i >= 0; i--) {
    counterBytes[i] = c & 0xff;
    c = c >> 8;
  }

  final hmac = Hmac(sha1, secret).convert(counterBytes).bytes;
  final offset = hmac[hmac.length - 1] & 0x0f;
  final binary = ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);
  final mod = pow10(digits);
  final code = (binary % mod).toString().padLeft(digits, '0');
  return code;
}

int remainingSeconds({
  required DateTime now,
  int periodSeconds = 30,
}) {
  final seconds = now.millisecondsSinceEpoch ~/ 1000;
  final mod = seconds % periodSeconds;
  return periodSeconds - mod;
}

int pow10(int n) {
  var result = 1;
  for (var i = 0; i < n; i++) {
    result *= 10;
  }
  return result;
}

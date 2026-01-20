import 'package:flutter_test/flutter_test.dart';

import 'package:fullpos_owner/features/virtual_token/data/totp.dart';

void main() {
  test('TOTP (RFC6238 SHA1 vectors)', () {
    const secretBase32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // "12345678901234567890"

    expect(
      generateTotpCode(
        secretBase32: secretBase32,
        now: DateTime.fromMillisecondsSinceEpoch(59 * 1000, isUtc: true),
        digits: 8,
        periodSeconds: 30,
      ),
      '94287082',
    );

    expect(
      generateTotpCode(
        secretBase32: secretBase32,
        now: DateTime.fromMillisecondsSinceEpoch(1111111109 * 1000, isUtc: true),
        digits: 8,
        periodSeconds: 30,
      ),
      '07081804',
    );

    expect(
      generateTotpCode(
        secretBase32: secretBase32,
        now: DateTime.fromMillisecondsSinceEpoch(2000000000 * 1000, isUtc: true),
        digits: 8,
        periodSeconds: 30,
      ),
      '69279037',
    );
  });

  test('remainingSeconds counts down within period', () {
    expect(
      remainingSeconds(
        now: DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
        periodSeconds: 30,
      ),
      30,
    );
    expect(
      remainingSeconds(
        now: DateTime.fromMillisecondsSinceEpoch(29 * 1000, isUtc: true),
        periodSeconds: 30,
      ),
      1,
    );
  });
}


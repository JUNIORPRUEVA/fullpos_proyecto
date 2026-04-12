String formatAccountingAmount(num value) {
  if (value is double && !value.isFinite) return '0.00';

  final sign = value < 0 ? '-' : '';
  final fixed = value.abs().toStringAsFixed(2);
  final parts = fixed.split('.');
  final integerPart = parts.first;
  final decimalPart = parts.length > 1 ? parts[1] : '00';

  final grouped = StringBuffer();
  for (var index = 0; index < integerPart.length; index++) {
    if (index > 0 && (integerPart.length - index) % 3 == 0) {
      grouped.write(',');
    }
    grouped.write(integerPart[index]);
  }

  return '$sign$grouped.$decimalPart';
}

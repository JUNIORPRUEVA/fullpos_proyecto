import '../errors/app_exception.dart';

class BusinessRuleException extends AppException {
  BusinessRuleException({
    required String code,
    required String messageUser,
    required String messageDev,
    Object? originalError,
    StackTrace? stackTrace,
  }) : super(
          type: AppErrorType.validation,
          code: code,
          messageUser: messageUser,
          messageDev: messageDev,
          originalError: originalError,
          stackTrace: stackTrace,
        );
}

class BusinessRules {
  BusinessRules._();

  static void requirePositive(double value, String field) {
    if (value <= 0) {
      throw BusinessRuleException(
        code: 'invalid_$field',
        messageUser: 'Verifica los datos e intenta de nuevo.',
        messageDev: 'Business rule failed: $field must be > 0 (value=$value).',
      );
    }
  }

  static void requireNonNegative(double value, String field) {
    if (value < 0) {
      throw BusinessRuleException(
        code: 'invalid_$field',
        messageUser: 'Verifica los datos e intenta de nuevo.',
        messageDev:
            'Business rule failed: $field must be >= 0 (value=$value).',
      );
    }
  }

  static void requireIntPositive(int value, String field) {
    if (value <= 0) {
      throw BusinessRuleException(
        code: 'invalid_$field',
        messageUser: 'Verifica los datos e intenta de nuevo.',
        messageDev: 'Business rule failed: $field must be > 0 (value=$value).',
      );
    }
  }

  static void requireDateOrder(
    DateTime start,
    DateTime end,
    String startField,
    String endField,
  ) {
    if (start.isAfter(end)) {
      throw BusinessRuleException(
        code: 'invalid_date_order',
        messageUser: 'Verifica las fechas e intenta de nuevo.',
        messageDev:
            'Business rule failed: $startField must be <= $endField (start=$start end=$end).',
      );
    }
  }
}



import 'loan_models.dart';

/// Calculadora para préstamos
class LoansCalculator {
  LoansCalculator._();

  /// Devuelve la próxima fecha de vencimiento para una frecuencia.
  ///
  /// Útil para UI/validaciones (por ejemplo, proponer la primera cuota).
  static DateTime nextDueDate(DateTime current, String frequency) {
    return _getNextDueDate(current, frequency);
  }

  /// Calcula el total a pagar (capital + interés)
  ///
  /// Modo "Interés por Cuota" (estilo dominicano):
  /// - El porcentaje se cobra por cada cuota
  /// - Fórmula: Total = Capital + (Capital × Porcentaje × Cuotas)
  /// - Ejemplo: 10,000 al 10% en 10 cuotas = 10,000 + (10,000 × 0.10 × 10) = 20,000
  /// - Cuota: 20,000 / 10 = 2,000 por cuota
  ///
  /// Modo "Interés Fijo":
  /// - El porcentaje se aplica una sola vez
  /// - Fórmula: Total = Capital + (Capital × Porcentaje)
  /// - Ejemplo: 10,000 al 10% = 10,000 + 1,000 = 11,000
  static double computeTotalDue({
    required double principal,
    required double interestRate,
    required int installmentsCount,
    // Estos parámetros ya no se usan en el cálculo pero se mantienen por compatibilidad
    required String interestMode,
    required String frequency,
  }) {
    if (interestMode == InterestMode.interestPerInstallment ||
        interestMode == 'monthly_flat' ||
        interestMode == 'interest_per_installment') {
      // Interés por cuota (estilo dominicano)
      // Total = Capital + (Capital × Porcentaje × Cuotas)
      final interest = principal * (interestRate / 100) * installmentsCount;
      return principal + interest;
    } else if (interestMode == InterestMode.fixedInterest ||
        interestMode == 'flat_per_period' ||
        interestMode == 'fixed_interest') {
      // Interés fijo (una sola vez)
      // Total = Capital + (Capital × Porcentaje)
      final interest = principal * (interestRate / 100);
      return principal + interest;
    }

    // Por defecto, usar interés por cuota
    final interest = principal * (interestRate / 100) * installmentsCount;
    return principal + interest;
  }

  /// Construye el calendario de cuotas
  static List<LoanInstallmentModel> buildSchedule({
    required int loanId,
    required DateTime startDate,
    required String frequency,
    required int installmentsCount,
    required double totalDue,
  }) {
    final installments = <LoanInstallmentModel>[];
    final amountPerInstallment = totalDue / installmentsCount;

    DateTime currentDueDate = startDate;

    for (int i = 1; i <= installmentsCount; i++) {
      if (i > 1) {
        currentDueDate = _getNextDueDate(currentDueDate, frequency);
      }

      installments.add(
        LoanInstallmentModel(
          loanId: loanId,
          number: i,
          dueDateMs: currentDueDate.millisecondsSinceEpoch,
          amountDue: amountPerInstallment,
          amountPaid: 0,
          status: InstallmentStatus.pending,
        ),
      );
    }

    return installments;
  }

  /// Calcula la próxima fecha de vencimiento
  static DateTime _getNextDueDate(DateTime current, String frequency) {
    switch (frequency) {
      case LoanFrequency.weekly:
        return current.add(const Duration(days: 7));
      case LoanFrequency.biweekly:
        return current.add(const Duration(days: 15));
      case LoanFrequency.monthly:
        return DateTime(
          current.month == 12 ? current.year + 1 : current.year,
          current.month == 12 ? 1 : current.month + 1,
          current.day,
        );
      case LoanFrequency.single:
        return current; // No hay siguiente cuota
      default:
        return current.add(const Duration(days: 30));
    }
  }

  /// Recalcula el estado de las cuotas (detecta vencidas)
  static void updateInstallmentStatuses(
    List<LoanInstallmentModel> installments,
  ) {
    final now = DateTime.now().millisecondsSinceEpoch;

    for (final installment in installments) {
      if (installment.isFullyPaid) {
        // Ya está pagada, no cambiar
        continue;
      }

      if (installment.dueDateMs < now) {
        // Está vencida
        if (installment.amountPaid > 0) {
          installment.toMap()['status'] = InstallmentStatus.partial;
        } else {
          installment.toMap()['status'] = InstallmentStatus.overdue;
        }
      } else {
        // Aún no vence
        if (installment.amountPaid > 0) {
          installment.toMap()['status'] = InstallmentStatus.partial;
        } else {
          installment.toMap()['status'] = InstallmentStatus.pending;
        }
      }
    }
  }

  /// Determina el estado del préstamo según las cuotas
  static String determineLoanStatus({
    required double balance,
    required List<LoanInstallmentModel> installments,
  }) {
    if (balance <= 0) {
      return LoanStatus.paid;
    }

    final now = DateTime.now().millisecondsSinceEpoch;
    final hasOverdue = installments.any(
      (i) => !i.isFullyPaid && i.dueDateMs < now,
    );

    if (hasOverdue) {
      return LoanStatus.overdue;
    }

    return LoanStatus.open;
  }

  /// Genera un resumen del préstamo (para preview)
  static LoanPreview generatePreview({
    required double principal,
    required double interestRate,
    required String interestMode,
    required String frequency,
    required int installmentsCount,
    required DateTime startDate,
  }) {
    final totalDue = computeTotalDue(
      principal: principal,
      interestRate: interestRate,
      interestMode: interestMode,
      installmentsCount: installmentsCount,
      frequency: frequency,
    );

    final interestAmount = totalDue - principal;
    final installmentAmount = totalDue / installmentsCount;

    final schedule = <PreviewInstallment>[];
    DateTime currentDueDate = startDate;

    for (int i = 1; i <= installmentsCount; i++) {
      if (i > 1) {
        currentDueDate = _getNextDueDate(currentDueDate, frequency);
      }

      schedule.add(
        PreviewInstallment(
          number: i,
          dueDate: currentDueDate,
          amount: installmentAmount,
        ),
      );
    }

    return LoanPreview(
      principal: principal,
      interestAmount: interestAmount,
      totalDue: totalDue,
      installmentAmount: installmentAmount,
      schedule: schedule,
    );
  }
}

/// Clase para preview del préstamo
class LoanPreview {
  final double principal;
  final double interestAmount;
  final double totalDue;
  final double installmentAmount;
  final List<PreviewInstallment> schedule;

  LoanPreview({
    required this.principal,
    required this.interestAmount,
    required this.totalDue,
    required this.installmentAmount,
    required this.schedule,
  });
}

/// Cuota del preview
class PreviewInstallment {
  final int number;
  final DateTime dueDate;
  final double amount;

  PreviewInstallment({
    required this.number,
    required this.dueDate,
    required this.amount,
  });
}

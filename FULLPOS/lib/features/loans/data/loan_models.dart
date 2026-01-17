/// Tipos de préstamos
class LoanType {
  static const String secured = 'secured'; // Con garantía
  static const String unsecured = 'unsecured'; // Sin garantía
}

/// Modos de cálculo de interés
class InterestMode {
  /// Interés por cuota: El porcentaje se aplica por cada cuota
  /// Fórmula: Total = Capital + (Capital × % × Cuotas)
  /// Ejemplo: 10,000 al 10% en 10 cuotas = 10,000 + (10,000 × 0.10 × 10) = 20,000
  static const String interestPerInstallment = 'interest_per_installment';
  
  /// Interés fijo: El porcentaje se aplica una sola vez al capital
  /// Fórmula: Total = Capital + (Capital × %)
  /// Ejemplo: 10,000 al 10% = 10,000 + 1,000 = 11,000
  static const String fixedInterest = 'fixed_interest';
  
  // Mantener compatibilidad con valores antiguos
  static const String monthlyFlat = 'interest_per_installment';
  static const String flatPerPeriod = 'fixed_interest';
}

/// Frecuencias de pago
class LoanFrequency {
  static const String weekly = 'weekly';
  static const String biweekly = 'biweekly';
  static const String monthly = 'monthly';
  static const String single = 'single'; // Pago único
}

/// Estados de préstamo
class LoanStatus {
  static const String open = 'OPEN';
  static const String overdue = 'OVERDUE';
  static const String paid = 'PAID';
  static const String cancelled = 'CANCELLED';
}

/// Estados de cuota
class InstallmentStatus {
  static const String pending = 'PENDING';
  static const String paid = 'PAID';
  static const String partial = 'PARTIAL';
  static const String overdue = 'OVERDUE';
}

/// Métodos de pago
class PaymentMethod {
  static const String cash = 'cash';
  static const String transfer = 'transfer';
  static const String card = 'card';
}

/// Modelo de Préstamo
class LoanModel {
  final int? id;
  final int clientId;
  final String type;
  final double principal;
  final double interestRate;
  final String interestMode;
  final String frequency;
  final int installmentsCount;
  final int startDateMs;
  final double totalDue;
  final double balance;
  final double lateFee;
  final String status;
  final String? note;
  final int createdAtMs;
  final int updatedAtMs;
  final int? deletedAtMs;

  LoanModel({
    this.id,
    required this.clientId,
    required this.type,
    required this.principal,
    required this.interestRate,
    required this.interestMode,
    required this.frequency,
    required this.installmentsCount,
    required this.startDateMs,
    required this.totalDue,
    required this.balance,
    this.lateFee = 0,
    required this.status,
    this.note,
    required this.createdAtMs,
    required this.updatedAtMs,
    this.deletedAtMs,
  });

  Map<String, dynamic> toMap() {
    return {
      if (id != null) 'id': id,
      'client_id': clientId,
      'type': type,
      'principal': principal,
      'interest_rate': interestRate,
      'interest_mode': interestMode,
      'frequency': frequency,
      'installments_count': installmentsCount,
      'start_date_ms': startDateMs,
      'total_due': totalDue,
      'balance': balance,
      'late_fee': lateFee,
      'status': status,
      'note': note,
      'created_at_ms': createdAtMs,
      'updated_at_ms': updatedAtMs,
      'deleted_at_ms': deletedAtMs,
    };
  }

  factory LoanModel.fromMap(Map<String, dynamic> map) {
    return LoanModel(
      id: map['id'] as int?,
      clientId: map['client_id'] as int,
      type: map['type'] as String,
      principal: (map['principal'] as num).toDouble(),
      interestRate: (map['interest_rate'] as num).toDouble(),
      interestMode: map['interest_mode'] as String,
      frequency: map['frequency'] as String,
      installmentsCount: map['installments_count'] as int,
      startDateMs: map['start_date_ms'] as int,
      totalDue: (map['total_due'] as num).toDouble(),
      balance: (map['balance'] as num).toDouble(),
      lateFee: (map['late_fee'] as num?)?.toDouble() ?? 0,
      status: map['status'] as String,
      note: map['note'] as String?,
      createdAtMs: map['created_at_ms'] as int,
      updatedAtMs: map['updated_at_ms'] as int,
      deletedAtMs: map['deleted_at_ms'] as int?,
    );
  }

  bool get isOpen => status == LoanStatus.open;
  bool get isOverdue => status == LoanStatus.overdue;
  bool get isPaid => status == LoanStatus.paid;
  bool get isCancelled => status == LoanStatus.cancelled;

  double get paidAmount => totalDue - balance;
  double get progressPercent => totalDue > 0 ? (paidAmount / totalDue) * 100 : 0;
}

/// Modelo de Garantía
class LoanCollateralModel {
  final int? id;
  final int loanId;
  final String description;
  final double? estimatedValue;
  final String? serial;
  final String? condition;

  LoanCollateralModel({
    this.id,
    required this.loanId,
    required this.description,
    this.estimatedValue,
    this.serial,
    this.condition,
  });

  Map<String, dynamic> toMap() {
    return {
      if (id != null) 'id': id,
      'loan_id': loanId,
      'description': description,
      'estimated_value': estimatedValue,
      'serial': serial,
      'condition': condition,
    };
  }

  factory LoanCollateralModel.fromMap(Map<String, dynamic> map) {
    return LoanCollateralModel(
      id: map['id'] as int?,
      loanId: map['loan_id'] as int,
      description: map['description'] as String,
      estimatedValue: (map['estimated_value'] as num?)?.toDouble(),
      serial: map['serial'] as String?,
      condition: map['condition'] as String?,
    );
  }
}

/// Modelo de Cuota
class LoanInstallmentModel {
  final int? id;
  final int loanId;
  final int number;
  final int dueDateMs;
  final double amountDue;
  final double amountPaid;
  final String status;

  LoanInstallmentModel({
    this.id,
    required this.loanId,
    required this.number,
    required this.dueDateMs,
    required this.amountDue,
    this.amountPaid = 0,
    required this.status,
  });

  Map<String, dynamic> toMap() {
    return {
      if (id != null) 'id': id,
      'loan_id': loanId,
      'number': number,
      'due_date_ms': dueDateMs,
      'amount_due': amountDue,
      'amount_paid': amountPaid,
      'status': status,
    };
  }

  factory LoanInstallmentModel.fromMap(Map<String, dynamic> map) {
    return LoanInstallmentModel(
      id: map['id'] as int?,
      loanId: map['loan_id'] as int,
      number: map['number'] as int,
      dueDateMs: map['due_date_ms'] as int,
      amountDue: (map['amount_due'] as num).toDouble(),
      amountPaid: (map['amount_paid'] as num?)?.toDouble() ?? 0,
      status: map['status'] as String,
    );
  }

  bool get isPending => status == InstallmentStatus.pending;
  bool get isPaid => status == InstallmentStatus.paid;
  bool get isPartial => status == InstallmentStatus.partial;
  bool get isOverdue => status == InstallmentStatus.overdue;

  double get remainingAmount => amountDue - amountPaid;
  bool get isFullyPaid => amountPaid >= amountDue;

  DateTime get dueDate => DateTime.fromMillisecondsSinceEpoch(dueDateMs);
}

/// Modelo de Pago
class LoanPaymentModel {
  final int? id;
  final int loanId;
  final int paidAtMs;
  final double amount;
  final String method;
  final String? note;

  LoanPaymentModel({
    this.id,
    required this.loanId,
    required this.paidAtMs,
    required this.amount,
    required this.method,
    this.note,
  });

  Map<String, dynamic> toMap() {
    return {
      if (id != null) 'id': id,
      'loan_id': loanId,
      'paid_at_ms': paidAtMs,
      'amount': amount,
      'method': method,
      'note': note,
    };
  }

  factory LoanPaymentModel.fromMap(Map<String, dynamic> map) {
    return LoanPaymentModel(
      id: map['id'] as int?,
      loanId: map['loan_id'] as int,
      paidAtMs: map['paid_at_ms'] as int,
      amount: (map['amount'] as num).toDouble(),
      method: map['method'] as String,
      note: map['note'] as String?,
    );
  }

  DateTime get paidDate => DateTime.fromMillisecondsSinceEpoch(paidAtMs);
}

/// DTO para crear un préstamo completo
class CreateLoanDto {
  final int clientId;
  final String type;
  final double principal;
  final double interestRate;
  final String interestMode;
  final String frequency;
  final int installmentsCount;
  final DateTime startDate;
  final double lateFee;
  final String? note;

  // Si tiene garantía
  final String? collateralDescription;
  final double? collateralValue;
  final String? collateralSerial;
  final String? collateralCondition;

  CreateLoanDto({
    required this.clientId,
    required this.type,
    required this.principal,
    required this.interestRate,
    required this.interestMode,
    required this.frequency,
    required this.installmentsCount,
    required this.startDate,
    this.lateFee = 0,
    this.note,
    this.collateralDescription,
    this.collateralValue,
    this.collateralSerial,
    this.collateralCondition,
  });

  bool get hasCollateral => type == LoanType.secured;
}

/// DTO para el detalle completo de un préstamo
class LoanDetailDto {
  final LoanModel loan;
  final String clientName;
  final LoanCollateralModel? collateral;
  final List<LoanInstallmentModel> installments;
  final List<LoanPaymentModel> payments;

  LoanDetailDto({
    required this.loan,
    required this.clientName,
    this.collateral,
    required this.installments,
    required this.payments,
  });

  LoanInstallmentModel? get nextPendingInstallment {
    final pending = installments
        .where((i) => !i.isFullyPaid)
        .toList()
      ..sort((a, b) => a.number.compareTo(b.number));
    return pending.isEmpty ? null : pending.first;
  }

  int get overdueCount {
    final now = DateTime.now().millisecondsSinceEpoch;
    return installments
        .where((i) => !i.isFullyPaid && i.dueDateMs < now)
        .length;
  }

  bool get hasOverdueInstallments => overdueCount > 0;
}

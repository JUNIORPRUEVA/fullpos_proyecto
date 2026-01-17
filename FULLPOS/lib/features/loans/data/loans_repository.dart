import '../../../core/db/app_db.dart';
import '../../../core/db/tables.dart';
import '../../../core/validation/business_rules.dart';
import 'loan_models.dart';
import 'loans_calculator.dart';

/// Repositorio para gestionar préstamos
class LoansRepository {
  LoansRepository._();

  static void _validateCreateLoanDto(CreateLoanDto dto) {
    if (dto.clientId <= 0) {
      throw ArgumentError('El cliente es obligatorio');
    }
    if (dto.principal <= 0) {
      throw ArgumentError('El monto principal debe ser mayor que 0');
    }
    if (dto.installmentsCount <= 0) {
      throw ArgumentError('La cantidad de cuotas debe ser mayor que 0');
    }
    if (dto.interestRate < 0) {
      throw ArgumentError('La tasa de interés no puede ser negativa');
    }
    if (dto.lateFee < 0) {
      throw ArgumentError('La mora no puede ser negativa');
    }

    const allowedTypes = {LoanType.secured, LoanType.unsecured};
    const allowedInterestModes = {
      InterestMode.interestPerInstallment,
      InterestMode.fixedInterest,
    };
    const allowedFrequencies = {
      LoanFrequency.weekly,
      LoanFrequency.biweekly,
      LoanFrequency.monthly,
      LoanFrequency.single,
    };

    if (!allowedTypes.contains(dto.type)) {
      throw ArgumentError('Tipo de préstamo inválido');
    }
    if (!allowedInterestModes.contains(dto.interestMode)) {
      throw ArgumentError('Modo de interés inválido');
    }
    if (!allowedFrequencies.contains(dto.frequency)) {
      throw ArgumentError('Frecuencia inválida');
    }

    if (dto.hasCollateral) {
      final desc = dto.collateralDescription?.trim();
      if (desc == null || desc.isEmpty) {
        throw ArgumentError('La descripción de la garantía es obligatoria');
      }
    }
  }

  /// Crea un préstamo completo con cuotas y garantía (si aplica)
  static Future<int> createLoan(CreateLoanDto dto) async {
    _validateCreateLoanDto(dto);
    final db = await AppDb.database;

    // Calcular total
    final totalDue = LoansCalculator.computeTotalDue(
      principal: dto.principal,
      interestRate: dto.interestRate,
      interestMode: dto.interestMode,
      installmentsCount: dto.installmentsCount,
      frequency: dto.frequency,
    );
    BusinessRules.requirePositive(totalDue, 'total_due');

    final now = DateTime.now().millisecondsSinceEpoch;

    // Iniciar transacción
    return await db.transaction((txn) async {
      // Insertar préstamo
      final loanId = await txn.insert(DbTables.loans, {
        'client_id': dto.clientId,
        'type': dto.type,
        'principal': dto.principal,
        'interest_rate': dto.interestRate,
        'interest_mode': dto.interestMode,
        'frequency': dto.frequency,
        'installments_count': dto.installmentsCount,
        'start_date_ms': dto.startDate.millisecondsSinceEpoch,
        'total_due': totalDue,
        'balance': totalDue,
        'late_fee': dto.lateFee,
        'status': LoanStatus.open,
        'note': dto.note,
        'created_at_ms': now,
        'updated_at_ms': now,
      });

      // Insertar garantía si aplica
      if (dto.hasCollateral && dto.collateralDescription != null) {
        await txn.insert(DbTables.loanCollaterals, {
          'loan_id': loanId,
          'description': dto.collateralDescription!,
          'estimated_value': dto.collateralValue,
          'serial': dto.collateralSerial,
          'condition': dto.collateralCondition,
        });
      }

      // Generar cuotas
      final schedule = LoansCalculator.buildSchedule(
        loanId: loanId,
        startDate: dto.startDate,
        frequency: dto.frequency,
        installmentsCount: dto.installmentsCount,
        totalDue: totalDue,
      );

      // Insertar cuotas
      for (final installment in schedule) {
        await txn.insert(DbTables.loanInstallments, installment.toMap());
      }

      return loanId;
    });
  }

  /// Lista préstamos con filtros
  static Future<List<LoanModel>> listLoans({
    String? statusFilter, // 'OPEN', 'OVERDUE', 'PAID', null = all
    int? clientId,
  }) async {
    final db = await AppDb.database;

    String whereClause = 'deleted_at_ms IS NULL';
    final whereArgs = <dynamic>[];

    if (statusFilter != null) {
      whereClause += ' AND status = ?';
      whereArgs.add(statusFilter);
    }

    if (clientId != null) {
      whereClause += ' AND client_id = ?';
      whereArgs.add(clientId);
    }

    final results = await db.query(
      DbTables.loans,
      where: whereClause,
      whereArgs: whereArgs.isEmpty ? null : whereArgs,
      orderBy: 'created_at_ms DESC',
    );

    return results.map((row) => LoanModel.fromMap(row)).toList();
  }

  /// Obtiene el detalle completo de un préstamo
  static Future<LoanDetailDto?> getLoanDetail(int loanId) async {
    final db = await AppDb.database;

    // Obtener préstamo
    final loanResult = await db.query(
      DbTables.loans,
      where: 'id = ? AND deleted_at_ms IS NULL',
      whereArgs: [loanId],
    );

    if (loanResult.isEmpty) return null;

    final loan = LoanModel.fromMap(loanResult.first);

    // Obtener cliente
    final clientResult = await db.query(
      DbTables.clients,
      where: 'id = ?',
      whereArgs: [loan.clientId],
      columns: ['nombre'],
    );

    final clientName = clientResult.isNotEmpty
        ? clientResult.first['nombre'] as String
        : 'Cliente Desconocido';

    // Obtener garantía (si tiene)
    LoanCollateralModel? collateral;
    final collateralResult = await db.query(
      DbTables.loanCollaterals,
      where: 'loan_id = ?',
      whereArgs: [loanId],
    );

    if (collateralResult.isNotEmpty) {
      collateral = LoanCollateralModel.fromMap(collateralResult.first);
    }

    // Obtener cuotas
    final installmentsResult = await db.query(
      DbTables.loanInstallments,
      where: 'loan_id = ?',
      whereArgs: [loanId],
      orderBy: 'number ASC',
    );

    final installments = installmentsResult
        .map((row) => LoanInstallmentModel.fromMap(row))
        .toList();

    // Obtener pagos
    final paymentsResult = await db.query(
      DbTables.loanPayments,
      where: 'loan_id = ?',
      whereArgs: [loanId],
      orderBy: 'paid_at_ms DESC',
    );

    final payments = paymentsResult
        .map((row) => LoanPaymentModel.fromMap(row))
        .toList();

    return LoanDetailDto(
      loan: loan,
      clientName: clientName,
      collateral: collateral,
      installments: installments,
      payments: payments,
    );
  }

  /// Registra un pago y aplica a cuotas
  static Future<void> registerPayment({
    required int loanId,
    required double amount,
    required String method,
    String? note,
  }) async {
    final db = await AppDb.database;

    await db.transaction((txn) async {
      final now = DateTime.now().millisecondsSinceEpoch;

      BusinessRules.requireIntPositive(loanId, 'loan_id');
      BusinessRules.requirePositive(amount, 'amount');
      if (method.trim().isEmpty) {
        throw BusinessRuleException(
          code: 'invalid_method',
          messageUser: 'Selecciona un método de pago.',
          messageDev: 'Payment method is empty.',
        );
      }

      final loanResult = await txn.query(
        DbTables.loans,
        where: 'id = ? AND deleted_at_ms IS NULL',
        whereArgs: [loanId],
        limit: 1,
      );

      if (loanResult.isEmpty) {
        throw BusinessRuleException(
          code: 'loan_not_found',
          messageUser: 'El préstamo no existe o fue eliminado.',
          messageDev: 'Loan not found loanId=$loanId',
        );
      }

      final loan = LoanModel.fromMap(loanResult.first);
      final balance = loan.balance;
      const eps = 0.01;
      if (amount > balance + eps) {
        throw BusinessRuleException(
          code: 'overpayment',
          messageUser:
              'El pago excede el balance pendiente. Ajusta el monto e intenta de nuevo.',
          messageDev:
              'Overpayment blocked. loanId=$loanId balance=$balance amount=$amount',
        );
      }

      // Insertar pago
      await txn.insert(DbTables.loanPayments, {
        'loan_id': loanId,
        'paid_at_ms': now,
        'amount': amount,
        'method': method,
        'note': note,
      });

      // Obtener cuotas pendientes ordenadas
      final installmentsResult = await txn.query(
        DbTables.loanInstallments,
        where: 'loan_id = ? AND amount_paid < amount_due',
        whereArgs: [loanId],
        orderBy: 'number ASC',
      );

      final installments = installmentsResult
          .map((row) => LoanInstallmentModel.fromMap(row))
          .toList();

      // Aplicar pago a cuotas
      double remaining = amount;

      for (final installment in installments) {
        if (remaining <= 0) break;

        final installmentRemaining =
            installment.amountDue - installment.amountPaid;
        final amountToApply = remaining > installmentRemaining
            ? installmentRemaining
            : remaining;

        final newAmountPaid = installment.amountPaid + amountToApply;
        final newStatus = newAmountPaid >= installment.amountDue
            ? InstallmentStatus.paid
            : InstallmentStatus.partial;

        await txn.update(
          DbTables.loanInstallments,
          {'amount_paid': newAmountPaid, 'status': newStatus},
          where: 'id = ?',
          whereArgs: [installment.id!],
        );

        remaining -= amountToApply;
      }

      // Actualizar balance del préstamo
      final newBalance = (balance - amount).clamp(0.0, double.infinity);

      // Determinar nuevo estado
      String newStatus = loan.status;
      if (newBalance <= eps) {
        newStatus = LoanStatus.paid;
      } else {
        // Verificar si hay cuotas vencidas
        final overdueResult = await txn.query(
          DbTables.loanInstallments,
          where: 'loan_id = ? AND amount_paid < amount_due AND due_date_ms < ?',
          whereArgs: [loanId, now],
        );

        newStatus = overdueResult.isNotEmpty ? LoanStatus.overdue : LoanStatus.open;
      }

      await txn.update(
        DbTables.loans,
        {
          'balance': newBalance,
          'status': newStatus,
          'updated_at_ms': now,
        },
        where: 'id = ?',
        whereArgs: [loanId],
      );
    });
  }

  /// Recalcula estados de préstamos (ejecutar al entrar al módulo)
  static Future<void> recalculateOverdueStatuses() async {
    final db = await AppDb.database;
    final now = DateTime.now().millisecondsSinceEpoch;

    // Obtener todos los préstamos abiertos
    final loansResult = await db.query(
      DbTables.loans,
      where: 'status IN (?, ?) AND deleted_at_ms IS NULL',
      whereArgs: [LoanStatus.open, LoanStatus.overdue],
    );

    for (final loanRow in loansResult) {
      final loanId = loanRow['id'] as int;

      // Verificar si tiene cuotas vencidas
      final overdueResult = await db.query(
        DbTables.loanInstallments,
        where: 'loan_id = ? AND amount_paid < amount_due AND due_date_ms < ?',
        whereArgs: [loanId, now],
      );

      String newStatus;
      if (overdueResult.isNotEmpty) {
        newStatus = LoanStatus.overdue;

        // Actualizar cuotas vencidas
        await db.update(
          DbTables.loanInstallments,
          {'status': InstallmentStatus.overdue},
          where:
              'loan_id = ? AND amount_paid < amount_due AND due_date_ms < ? AND status != ?',
          whereArgs: [loanId, now, InstallmentStatus.paid],
        );
      } else {
        newStatus = LoanStatus.open;
      }

      if (loanRow['status'] as String != newStatus) {
        await db.update(
          DbTables.loans,
          {'status': newStatus, 'updated_at_ms': now},
          where: 'id = ?',
          whereArgs: [loanId],
        );
      }
    }
  }

  /// Cancela un préstamo (soft delete)
  static Future<void> cancelLoan(int loanId) async {
    final db = await AppDb.database;
    final now = DateTime.now().millisecondsSinceEpoch;

    await db.update(
      DbTables.loans,
      {
        'status': LoanStatus.cancelled,
        'deleted_at_ms': now,
        'updated_at_ms': now,
      },
      where: 'id = ?',
      whereArgs: [loanId],
    );
  }

  /// Obtiene KPIs de préstamos para el dashboard
  static Future<LoansKpis> getLoansKpis({
    required int startMs,
    required int endMs,
  }) async {
    final db = await AppDb.database;

    // Total prestado
    final totalLentResult = await db.rawQuery(
      '''
      SELECT COALESCE(SUM(principal), 0) as total
      FROM ${DbTables.loans}
      WHERE deleted_at_ms IS NULL
        AND created_at_ms >= ?
        AND created_at_ms <= ?
    ''',
      [startMs, endMs],
    );

    final totalLent = (totalLentResult.first['total'] as num).toDouble();

    // Total cobrado (suma de pagos)
    final totalCollectedResult = await db.rawQuery(
      '''
      SELECT COALESCE(SUM(amount), 0) as total
      FROM ${DbTables.loanPayments}
      WHERE paid_at_ms >= ?
        AND paid_at_ms <= ?
    ''',
      [startMs, endMs],
    );

    final totalCollected = (totalCollectedResult.first['total'] as num)
        .toDouble();

    // Interés generado estimado
    final interestResult = await db.rawQuery(
      '''
      SELECT COALESCE(SUM(total_due - principal), 0) as total_interest
      FROM ${DbTables.loans}
      WHERE deleted_at_ms IS NULL
        AND created_at_ms >= ?
        AND created_at_ms <= ?
    ''',
      [startMs, endMs],
    );

    final interestGenerated = (interestResult.first['total_interest'] as num)
        .toDouble();

    // Cartera activa (saldo pendiente de todos los préstamos abiertos o vencidos)
    final activeBalanceResult = await db.rawQuery('''
      SELECT COALESCE(SUM(balance), 0) as active_balance
      FROM ${DbTables.loans}
      WHERE status IN ('${LoanStatus.open}', '${LoanStatus.overdue}')
        AND deleted_at_ms IS NULL
    ''');

    final activeBalance = (activeBalanceResult.first['active_balance'] as num)
        .toDouble();

    // Préstamos vencidos
    final overdueCountResult = await db.rawQuery('''
      SELECT COUNT(id) as count
      FROM ${DbTables.loans}
      WHERE status = '${LoanStatus.overdue}'
        AND deleted_at_ms IS NULL
    ''');

    final overdueCount = (overdueCountResult.first['count'] as int?) ?? 0;

    return LoansKpis(
      totalLent: totalLent,
      totalCollected: totalCollected,
      interestGenerated: interestGenerated,
      activeBalance: activeBalance,
      overdueCount: overdueCount,
    );
  }
}

/// KPIs de préstamos
class LoansKpis {
  final double totalLent;
  final double totalCollected;
  final double interestGenerated;
  final double activeBalance;
  final int overdueCount;

  LoansKpis({
    required this.totalLent,
    required this.totalCollected,
    required this.interestGenerated,
    required this.activeBalance,
    required this.overdueCount,
  });
}

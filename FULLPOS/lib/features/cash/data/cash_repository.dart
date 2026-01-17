import 'package:sqflite/sqflite.dart';
import '../../../core/db/app_db.dart';
import '../../../core/db/tables.dart';
import 'cash_session_model.dart';
import 'cash_movement_model.dart';
import 'cash_summary_model.dart';

/// Repositorio completo de Caja
class CashRepository {
  CashRepository._();

  // ===================== SESIONES DE CAJA =====================

  /// Obtener sesión abierta (global o por usuario)
  static Future<CashSessionModel?> getOpenSession({int? userId}) async {
    final db = await AppDb.database;

    String where = 'status = ?';
    List<dynamic> args = ['OPEN'];

    if (userId != null) {
      where += ' AND opened_by_user_id = ?';
      args.add(userId);
    }

    final result = await db.query(
      DbTables.cashSessions,
      where: where,
      whereArgs: args,
      orderBy: 'opened_at_ms DESC',
      limit: 1,
    );

    if (result.isEmpty) return null;
    return CashSessionModel.fromMap(result.first);
  }

  /// Abrir nueva sesión de caja
  static Future<int> openSession({
    required int userId,
    required String userName,
    required double openingAmount,
  }) async {
    final db = await AppDb.database;

    // Verificar que no haya otra sesión abierta
    final existing = await getOpenSession();
    if (existing != null) {
      throw Exception('Ya existe una caja abierta. Ciérrela primero.');
    }

    final now = DateTime.now().millisecondsSinceEpoch;

    final session = CashSessionModel(
      userId: userId,
      userName: userName,
      openedAtMs: now,
      openingAmount: openingAmount,
      status: CashSessionStatus.open,
    );

    final id = await db.insert(
      DbTables.cashSessions,
      session.toMap(),
      conflictAlgorithm: ConflictAlgorithm.abort,
    );

    return id;
  }

  /// Cerrar sesión de caja con transacción
  static Future<void> closeSession({
    required int sessionId,
    required double closingAmount,
    required String note,
    required CashSummaryModel summary,
  }) async {
    final db = await AppDb.database;
    final now = DateTime.now().millisecondsSinceEpoch;

    final difference = summary.calculateDifference(closingAmount);

    await db.transaction((txn) async {
      await txn.update(
        DbTables.cashSessions,
        {
          'closed_at_ms': now,
          'closing_amount': closingAmount,
          'expected_cash': summary.expectedCash,
          'difference': difference,
          'note': note,
          'status': CashSessionStatus.closed,
        },
        where: 'id = ?',
        whereArgs: [sessionId],
      );
    });
  }

  /// Obtener sesión por ID
  static Future<CashSessionModel?> getSessionById(int id) async {
    final db = await AppDb.database;

    final result = await db.query(
      DbTables.cashSessions,
      where: 'id = ?',
      whereArgs: [id],
      limit: 1,
    );

    if (result.isEmpty) return null;
    return CashSessionModel.fromMap(result.first);
  }

  /// Listar historial de sesiones cerradas
  static Future<List<CashSessionModel>> listClosedSessions({
    int limit = 50,
    int offset = 0,
  }) async {
    final db = await AppDb.database;

    final result = await db.query(
      DbTables.cashSessions,
      where: 'status = ?',
      whereArgs: ['CLOSED'],
      orderBy: 'closed_at_ms DESC',
      limit: limit,
      offset: offset,
    );

    return result.map((map) => CashSessionModel.fromMap(map)).toList();
  }

  // ===================== MOVIMIENTOS DE CAJA =====================

  /// Agregar movimiento de caja (entrada/salida)
  static Future<int> addMovement({
    required int sessionId,
    required String type, // 'IN' o 'OUT'
    required double amount,
    required String reason,
    required int userId,
  }) async {
    final db = await AppDb.database;
    final now = DateTime.now().millisecondsSinceEpoch;

    // Validar que el tipo sea correcto
    if (type != CashMovementType.income && type != CashMovementType.outcome) {
      throw Exception('Tipo de movimiento inválido: $type');
    }

    // Validar que la sesión esté abierta
    final session = await getSessionById(sessionId);
    if (session == null || !session.isOpen) {
      throw Exception('La sesión de caja no está abierta.');
    }

    final movement = CashMovementModel(
      sessionId: sessionId,
      type: type,
      amount: amount,
      reason: reason,
      createdAtMs: now,
      userId: userId,
    );

    final id = await db.insert(
      DbTables.cashMovements,
      movement.toMap(),
      conflictAlgorithm: ConflictAlgorithm.abort,
    );

    return id;
  }

  /// Listar movimientos de una sesión
  static Future<List<CashMovementModel>> listMovements({
    required int sessionId,
  }) async {
    final db = await AppDb.database;

    final result = await db.query(
      DbTables.cashMovements,
      where: 'session_id = ?',
      whereArgs: [sessionId],
      orderBy: 'created_at_ms ASC',
    );

    return result.map((map) => CashMovementModel.fromMap(map)).toList();
  }

  // ===================== RESUMEN Y CÁLCULOS =====================

  /// Construir resumen completo de la sesión
  static Future<CashSummaryModel> buildSummary({
    required int sessionId,
  }) async {
    final db = await AppDb.database;

    // Obtener sesión para el monto de apertura
    final session = await getSessionById(sessionId);
    if (session == null) {
      throw Exception('Sesión no encontrada: $sessionId');
    }

    final openingAmount = session.openingAmount;

    // Calcular movimientos manuales IN
    final inResult = await db.rawQuery('''
      SELECT COALESCE(SUM(amount), 0) as total
      FROM ${DbTables.cashMovements}
      WHERE session_id = ? AND type = 'IN'
    ''', [sessionId]);
    final cashInManual = (inResult.first['total'] as num?)?.toDouble() ?? 0.0;

    // Calcular movimientos manuales OUT
    final outResult = await db.rawQuery('''
      SELECT COALESCE(SUM(amount), 0) as total
      FROM ${DbTables.cashMovements}
      WHERE session_id = ? AND type = 'OUT'
    ''', [sessionId]);
    final cashOutManual = (outResult.first['total'] as num?)?.toDouble() ?? 0.0;

    // Ventas en efectivo (usando cash_session_id o session_id)
    final cashSalesResult = await db.rawQuery('''
      SELECT COALESCE(SUM(paid_amount), 0) as total
      FROM ${DbTables.sales}
      WHERE (cash_session_id = ? OR session_id = ?)
        AND kind = 'invoice'
        AND status = 'completed'
        AND payment_method = 'cash'
        AND deleted_at_ms IS NULL
    ''', [sessionId, sessionId]);
    final salesCashTotal =
        (cashSalesResult.first['total'] as num?)?.toDouble() ?? 0.0;

    // Ventas con tarjeta
    final cardSalesResult = await db.rawQuery('''
      SELECT COALESCE(SUM(total), 0) as total
      FROM ${DbTables.sales}
      WHERE (cash_session_id = ? OR session_id = ?)
        AND kind = 'invoice'
        AND status = 'completed'
        AND payment_method = 'card'
        AND deleted_at_ms IS NULL
    ''', [sessionId, sessionId]);
    final salesCardTotal =
        (cardSalesResult.first['total'] as num?)?.toDouble() ?? 0.0;

    // Ventas por transferencia
    final transferSalesResult = await db.rawQuery('''
      SELECT COALESCE(SUM(total), 0) as total
      FROM ${DbTables.sales}
      WHERE (cash_session_id = ? OR session_id = ?)
        AND kind = 'invoice'
        AND status = 'completed'
        AND payment_method = 'transfer'
        AND deleted_at_ms IS NULL
    ''', [sessionId, sessionId]);
    final salesTransferTotal =
        (transferSalesResult.first['total'] as num?)?.toDouble() ?? 0.0;

    // Ventas a crédito
    final creditSalesResult = await db.rawQuery('''
      SELECT COALESCE(SUM(total), 0) as total
      FROM ${DbTables.sales}
      WHERE (cash_session_id = ? OR session_id = ?)
        AND kind = 'invoice'
        AND status = 'completed'
        AND payment_method = 'credit'
        AND deleted_at_ms IS NULL
    ''', [sessionId, sessionId]);
    final salesCreditTotal =
        (creditSalesResult.first['total'] as num?)?.toDouble() ?? 0.0;

    // Total de tickets
    final ticketsResult = await db.rawQuery('''
      SELECT COUNT(*) as count
      FROM ${DbTables.sales}
      WHERE (cash_session_id = ? OR session_id = ?)
        AND kind = 'invoice'
        AND status = 'completed'
        AND deleted_at_ms IS NULL
    ''', [sessionId, sessionId]);
    final totalTickets = (ticketsResult.first['count'] as int?) ?? 0;

    // Devoluciones en efectivo
    final refundsResult = await db.rawQuery('''
      SELECT COALESCE(SUM(total), 0) as total
      FROM ${DbTables.sales}
      WHERE (cash_session_id = ? OR session_id = ?)
        AND kind = 'return'
        AND deleted_at_ms IS NULL
    ''', [sessionId, sessionId]);
    final refundsCash =
        (refundsResult.first['total'] as num?)?.toDouble() ?? 0.0;

    // Total de devoluciones (cantidad)
    final refundsCountResult = await db.rawQuery('''
      SELECT COUNT(*) as count
      FROM ${DbTables.sales}
      WHERE (cash_session_id = ? OR session_id = ?)
        AND kind = 'return'
        AND deleted_at_ms IS NULL
    ''', [sessionId, sessionId]);
    final totalRefunds = (refundsCountResult.first['count'] as int?) ?? 0;

    // Calcular efectivo esperado
    // expected = apertura + ventas efectivo + entradas - salidas - devoluciones efectivo
    // Nota: el cambio ya se resta del paid_amount en ventas efectivo
    final expectedCash = openingAmount +
        salesCashTotal +
        cashInManual -
        cashOutManual -
        refundsCash;

    return CashSummaryModel(
      openingAmount: openingAmount,
      cashInManual: cashInManual,
      cashOutManual: cashOutManual,
      salesCashTotal: salesCashTotal,
      salesCardTotal: salesCardTotal,
      salesTransferTotal: salesTransferTotal,
      salesCreditTotal: salesCreditTotal,
      refundsCash: refundsCash,
      expectedCash: expectedCash,
      totalTickets: totalTickets,
      totalRefunds: totalRefunds,
    );
  }

  // ===================== UTILIDADES =====================

  /// Verificar si hay caja abierta
  static Future<bool> hasOpenSession({int? userId}) async {
    final session = await getOpenSession(userId: userId);
    return session != null;
  }

  /// Obtener ID de la sesión abierta actual
  static Future<int?> getCurrentSessionId({int? userId}) async {
    final session = await getOpenSession(userId: userId);
    return session?.id;
  }
}

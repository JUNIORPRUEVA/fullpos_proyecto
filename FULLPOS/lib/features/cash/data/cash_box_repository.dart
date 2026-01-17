import 'package:sqflite/sqflite.dart';
import '../../../core/db/app_db.dart';
import '../../../core/db/tables.dart';
import '../data/cash_model.dart';

/// Repositorio de Caja para abrir y cerrar caja
class CashBoxRepository {
  CashBoxRepository._();

  /// Abrir caja con saldo inicial
  static Future<CashBoxModel> openCashBox({
    required double openingBalance,
    int? sessionId,
  }) async {
    final db = await AppDb.database;
    final now = DateTime.now().millisecondsSinceEpoch;

    final id = await db.insert(
      DbTables.cashSessions,
      {
        'opened_by_user_id': sessionId ?? 1,
        'opened_at_ms': now,
        'initial_amount': openingBalance,
      },
      conflictAlgorithm: ConflictAlgorithm.replace,
    );

    final cashBox = CashBoxModel(
      id: id,
      sessionId: sessionId,
      openingBalance: openingBalance,
      closingBalance: 0,
      expectedBalance: 0,
      difference: 0,
      status: 'OPEN',
      openedAtMs: now,
      closedAtMs: null,
      notes: null,
      createdAtMs: now,
      updatedAtMs: now,
    );

    return cashBox;
  }

  /// Obtener caja abierta (la actual)
  static Future<CashBoxModel?> getCurrentOpenCashBox() async {
    final db = await AppDb.database;

    final result = await db.query(
      DbTables.cashSessions,
      where: 'closed_at_ms IS NULL',
      orderBy: 'opened_at_ms DESC',
      limit: 1,
    );

    if (result.isEmpty) return null;

    final row = result.first;
    return CashBoxModel(
      id: row['id'] as int,
      sessionId: row['opened_by_user_id'] as int,
      openingBalance: (row['initial_amount'] as num).toDouble(),
      closingBalance: 0,
      expectedBalance: 0,
      difference: 0,
      status: 'OPEN',
      openedAtMs: row['opened_at_ms'] as int,
      closedAtMs: null,
      notes: null,
      createdAtMs: row['opened_at_ms'] as int,
      updatedAtMs: row['opened_at_ms'] as int,
    );
  }

  /// Cerrar caja con saldo final y notas
  static Future<void> closeCashBox({
    required int cashBoxId,
    required double closingBalance,
    required double expectedBalance,
    String? notes,
  }) async {
    final db = await AppDb.database;
    final now = DateTime.now().millisecondsSinceEpoch;

    await db.update(
      DbTables.cashSessions,
      {
        'closed_at_ms': now,
        'note': notes,
      },
      where: 'id = ?',
      whereArgs: [cashBoxId],
    );
  }

  /// Obtener historial de cajas (últimas N cajas cerradas)
  static Future<List<CashBoxModel>> getCashBoxHistory({
    int limit = 50,
  }) async {
    final db = await AppDb.database;

    final result = await db.query(
      DbTables.cashSessions,
      where: 'closed_at_ms IS NOT NULL',
      orderBy: 'closed_at_ms DESC',
      limit: limit,
    );

    return result.map((map) {
      return CashBoxModel(
        id: map['id'] as int,
        sessionId: map['opened_by_user_id'] as int,
        openingBalance: (map['initial_amount'] as num).toDouble(),
        closingBalance: 0,
        expectedBalance: 0,
        difference: 0,
        status: 'CLOSED',
        openedAtMs: map['opened_at_ms'] as int,
        closedAtMs: map['closed_at_ms'] as int?,
        notes: map['note'] as String?,
        createdAtMs: map['opened_at_ms'] as int,
        updatedAtMs: map['closed_at_ms'] as int? ?? map['opened_at_ms'] as int,
      );
    }).toList();
  }

  /// Obtener estadísticas de una caja (total de ventas)
  static Future<double> getCashBoxSalesTotal(int sessionId) async {
    final db = await AppDb.database;

    final result = await db.rawQuery(
      '''
      SELECT COALESCE(SUM(total), 0) as total_amount
      FROM ${DbTables.sales}
      WHERE session_id = ? AND status IN ('PAID', 'PARTIAL_REFUND')
      ''',
      [sessionId],
    );

    if (result.isEmpty) return 0.0;
    return ((result.first['total_amount'] ?? 0) as num).toDouble();
  }
}

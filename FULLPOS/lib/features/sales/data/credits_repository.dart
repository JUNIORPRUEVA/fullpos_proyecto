import '../../../core/db/app_db.dart';
import '../../../core/db/tables.dart';
import 'sales_model.dart';

class CreditsRepository {
  CreditsRepository._();

  /// Registra un pago de crédito
  static Future<int> registerCreditPayment({
    required int saleId,
    required int clientId,
    required double amount,
    required String method,
    String? note,
    int? userId,
  }) async {
    final db = await AppDb.database;

    return await db.transaction((txn) async {
      final now = DateTime.now().millisecondsSinceEpoch;

      // Insertar pago
      final paymentId = await txn.insert(DbTables.creditPayments, {
        'sale_id': saleId,
        'client_id': clientId,
        'amount': amount,
        'method': method,
        'note': note,
        'created_at_ms': now,
        'user_id': userId,
      });

      // Verificar si el crédito está completamente pagado
      final payments = await txn.rawQuery(
        '''SELECT SUM(amount) as total FROM ${DbTables.creditPayments} 
           WHERE sale_id = ?''',
        [saleId],
      );

      final totalPaid = (payments.first['total'] as num?)?.toDouble() ?? 0.0;

      // Obtener venta para comparar totales
      final sale = await txn.query(
        DbTables.sales,
        where: 'id = ?',
        whereArgs: [saleId],
      );

      if (sale.isNotEmpty) {
        final saleTotal = (sale.first['total'] as num).toDouble();

        // Si pagó todo, marcar como PAID
        if (totalPaid >= saleTotal) {
          await txn.update(
            DbTables.sales,
            {'status': 'PAID', 'updated_at_ms': now},
            where: 'id = ?',
            whereArgs: [saleId],
          );
        }
      }

      return paymentId;
    });
  }

  /// Obtiene todas las ventas a crédito
  static Future<List<Map<String, dynamic>>> listCreditSales({
    int? clientId,
    String? status,
  }) async {
    final db = await AppDb.database;

    String where = "s.payment_method = 'credit'";
    List<dynamic> args = [];

    if (clientId != null) {
      where += ' AND s.customer_id = ?';
      args.add(clientId);
    }

    if (status != null) {
      where += ' AND s.status = ?';
      args.add(status);
    }

    final result = await db.rawQuery(
      '''SELECT s.*, 
                COALESCE(SUM(cp.amount), 0) as amount_paid,
                (s.total - COALESCE(SUM(cp.amount), 0)) as amount_pending
         FROM ${DbTables.sales} s
         LEFT JOIN ${DbTables.creditPayments} cp ON s.id = cp.sale_id
         WHERE $where
         GROUP BY s.id
         ORDER BY s.created_at_ms DESC''',
      args,
    );

    return result;
  }

  /// Obtiene resumen de créditos por cliente
  static Future<List<Map<String, dynamic>>> getCreditSummaryByClient() async {
    final db = await AppDb.database;

    final result = await db.rawQuery(
      '''SELECT c.id, c.nombre, c.telefono,
                COUNT(DISTINCT s.id) as total_credits,
                SUM(s.total) as total_amount,
                COALESCE(SUM(cp.amount), 0) as total_paid,
                (SUM(s.total) - COALESCE(SUM(cp.amount), 0)) as total_pending
         FROM ${DbTables.clients} c
         LEFT JOIN ${DbTables.sales} s ON c.id = s.customer_id AND s.payment_method = 'credit'
         LEFT JOIN ${DbTables.creditPayments} cp ON s.id = cp.sale_id
         WHERE s.id IS NOT NULL
         GROUP BY c.id, c.nombre, c.telefono
         ORDER BY total_pending DESC''',
    );

    return result;
  }

  /// Obtiene los pagos de un crédito
  static Future<List<CreditPaymentModel>> getCreditPayments(int saleId) async {
    final db = await AppDb.database;

    final result = await db.query(
      DbTables.creditPayments,
      where: 'sale_id = ?',
      whereArgs: [saleId],
      orderBy: 'created_at_ms DESC',
    );

    return result.map((map) => CreditPaymentModel.fromMap(map)).toList();
  }

  /// Obtiene el saldo pendiente de un crédito
  static Future<double> getCreditBalance(int saleId) async {
    final db = await AppDb.database;

    // Obtener total de venta
    final sale = await db.query(
      DbTables.sales,
      where: 'id = ?',
      whereArgs: [saleId],
      columns: ['total'],
    );

    if (sale.isEmpty) return 0.0;

    final saleTotal = (sale.first['total'] as num).toDouble();

    // Obtener total pagado
    final payments = await db.rawQuery(
      '''SELECT SUM(amount) as total FROM ${DbTables.creditPayments} 
         WHERE sale_id = ?''',
      [saleId],
    );

    final totalPaid = (payments.first['total'] as num?)?.toDouble() ?? 0.0;

    return (saleTotal - totalPaid).clamp(0.0, double.infinity);
  }

  /// Obtiene el saldo total de crédito de un cliente
  static Future<double> getClientTotalCredit(int clientId) async {
    final db = await AppDb.database;

    final result = await db.rawQuery(
      '''SELECT SUM(s.total - COALESCE(SUM(cp.amount), 0)) as total_pending
         FROM ${DbTables.sales} s
         LEFT JOIN ${DbTables.creditPayments} cp ON s.id = cp.sale_id
         WHERE s.customer_id = ? AND s.payment_method = 'credit'
         GROUP BY s.customer_id''',
      [clientId],
    );

    if (result.isEmpty) return 0.0;
    return (result.first['total_pending'] as num?)?.toDouble() ?? 0.0;
  }
}

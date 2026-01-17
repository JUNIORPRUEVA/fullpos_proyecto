import '../../../core/db/app_db.dart';
import '../../../core/db/tables.dart';

/// Modelos para los reportes
class KpisData {
  final double totalSales;
  final double totalProfit;
  final double totalCost;
  final int salesCount;
  final int quotesCount;
  final int quotesConverted;
  final double avgTicket;
  // Préstamos
  final double loansLent;
  final double loansCollected;
  final double loansBalance;
  final int loansOverdue;
  final int loansActive;
  // Caja
  final double cashIncome;
  final double cashExpense;

  KpisData({
    required this.totalSales,
    required this.totalProfit,
    this.totalCost = 0,
    required this.salesCount,
    required this.quotesCount,
    required this.quotesConverted,
    required this.avgTicket,
    this.loansLent = 0,
    this.loansCollected = 0,
    this.loansBalance = 0,
    this.loansOverdue = 0,
    this.loansActive = 0,
    this.cashIncome = 0,
    this.cashExpense = 0,
  });
}

/// Datos de préstamos para reportes
class LoanReportItem {
  final int id;
  final String clientName;
  final double principal;
  final double balance;
  final double totalDue;
  final String status;
  final int startDateMs;
  final int overdueInstallments;
  final String frequency;

  LoanReportItem({
    required this.id,
    required this.clientName,
    required this.principal,
    required this.balance,
    required this.totalDue,
    required this.status,
    required this.startDateMs,
    required this.overdueInstallments,
    required this.frequency,
  });

  double get paidAmount => totalDue - balance;
  double get progress => totalDue > 0 ? (paidAmount / totalDue) * 100 : 0;
}

/// Pagos pendientes
class PendingPayment {
  final int loanId;
  final int installmentNumber;
  final String clientName;
  final double amountDue;
  final double amountPaid;
  final int dueDateMs;
  final String status;

  PendingPayment({
    required this.loanId,
    required this.installmentNumber,
    required this.clientName,
    required this.amountDue,
    required this.amountPaid,
    required this.dueDateMs,
    required this.status,
  });

  double get remaining => amountDue - amountPaid;
  bool get isOverdue =>
      DateTime.now().millisecondsSinceEpoch > dueDateMs && remaining > 0;
}

/// Datos para gráfico de distribución de ventas por método de pago
class PaymentMethodData {
  final String method;
  final double amount;
  final int count;

  PaymentMethodData({
    required this.method,
    required this.amount,
    required this.count,
  });
}

/// Datos para gráfico de categorías
class CategorySalesData {
  final String category;
  final double sales;
  final int itemsSold;

  CategorySalesData({
    required this.category,
    required this.sales,
    required this.itemsSold,
  });
}

class SeriesDataPoint {
  final String label; // fecha o período
  final double value;

  SeriesDataPoint(this.label, this.value);
}

class TopProduct {
  final int productId;
  final String productName;
  final double totalSales;
  final double totalQty;
  final double totalProfit;

  TopProduct({
    required this.productId,
    required this.productName,
    required this.totalSales,
    required this.totalQty,
    required this.totalProfit,
  });
}

class TopClient {
  final int clientId;
  final String clientName;
  final double totalSpent;
  final int purchaseCount;

  TopClient({
    required this.clientId,
    required this.clientName,
    required this.totalSpent,
    required this.purchaseCount,
  });
}

class SalesByUser {
  final int userId;
  final String username;
  final double totalSales;
  final int salesCount;

  SalesByUser({
    required this.userId,
    required this.username,
    required this.totalSales,
    required this.salesCount,
  });
}

class SaleRecord {
  final int id;
  final String localCode;
  final String kind;
  final int createdAtMs;
  final String? customerName;
  final double total;
  final String? paymentMethod;

  SaleRecord({
    required this.id,
    required this.localCode,
    required this.kind,
    required this.createdAtMs,
    this.customerName,
    required this.total,
    this.paymentMethod,
  });
}

/// Repositorio para generar reportes y estadísticas
class ReportsRepository {
  ReportsRepository._();

  /// Obtiene KPIs para el rango de fechas
  static Future<KpisData> getKpis({
    required int startMs,
    required int endMs,
    int? userId,
  }) async {
    final db = await AppDb.database;

    // Intentar completar snapshots faltantes en el rango solicitado (solo si existen productos).
    // Esto evita que la ganancia quede igual a las ventas por costos en 0.
    try {
      // 1) Completar product_id cuando venga NULL, usando el código snapshot.
      await db.execute(
        '''
        UPDATE ${DbTables.saleItems}
        SET product_id = (
          SELECT p.id FROM ${DbTables.products} p
          WHERE TRIM(p.code) COLLATE NOCASE = TRIM(${DbTables.saleItems}.product_code_snapshot) COLLATE NOCASE
          LIMIT 1
        )
        WHERE product_id IS NULL
          AND product_code_snapshot IS NOT NULL
          AND TRIM(product_code_snapshot) <> ''
          AND product_code_snapshot <> 'N/A'
          AND sale_id IN (
            SELECT id FROM ${DbTables.sales}
            WHERE kind IN ('invoice', 'sale')
              AND status IN ('completed', 'PAID', 'PARTIAL_REFUND')
              AND deleted_at_ms IS NULL
              AND created_at_ms >= ?
              AND created_at_ms <= ?
          )
          AND EXISTS (
            SELECT 1 FROM ${DbTables.products} p
            WHERE TRIM(p.code) COLLATE NOCASE = TRIM(${DbTables.saleItems}.product_code_snapshot) COLLATE NOCASE
          )
        ''',
        [startMs, endMs],
      );

      // 2) Completar purchase_price_snapshot usando el costo actual del producto.
      await db.execute(
        '''
        UPDATE ${DbTables.saleItems}
        SET purchase_price_snapshot = (
          SELECT COALESCE(p.purchase_price, 0)
          FROM ${DbTables.products} p
          WHERE p.id = ${DbTables.saleItems}.product_id
             OR TRIM(p.code) COLLATE NOCASE = TRIM(${DbTables.saleItems}.product_code_snapshot) COLLATE NOCASE
          LIMIT 1
        )
        WHERE (purchase_price_snapshot IS NULL OR purchase_price_snapshot <= 0)
          AND sale_id IN (
            SELECT id FROM ${DbTables.sales}
            WHERE kind IN ('invoice', 'sale')
              AND status IN ('completed', 'PAID', 'PARTIAL_REFUND')
              AND deleted_at_ms IS NULL
              AND created_at_ms >= ?
              AND created_at_ms <= ?
          )
          AND EXISTS (
            SELECT 1 FROM ${DbTables.products} p
            WHERE (
              p.id = ${DbTables.saleItems}.product_id
              OR TRIM(p.code) COLLATE NOCASE = TRIM(${DbTables.saleItems}.product_code_snapshot) COLLATE NOCASE
            )
              AND COALESCE(p.purchase_price, 0) > 0
          )
        ''',
        [startMs, endMs],
      );
    } catch (_) {
      // No bloquear reportes si no se puede backfillear
    }

    // Totales consolidados desde sale_items.
    // Importante: usar total_line (ya calculado al guardar) para soportar datos legados
    // donde unit_price/discount pudieron quedar en 0 o inconsistentes.
    final totalsQuery =
        '''
      SELECT
        total_sales,
        total_cost,
        total_profit,
        sales_count,
        CASE WHEN sales_count > 0 THEN (total_sales / sales_count) ELSE 0 END AS avg_ticket
      FROM (
        SELECT 
          COALESCE(SUM(COALESCE(si.total_line, 0)), 0) AS total_sales,
          COALESCE(SUM(COALESCE(si.qty, 0) * COALESCE(NULLIF(si.purchase_price_snapshot, 0), p.purchase_price, 0)), 0) AS total_cost,
          COALESCE(SUM(COALESCE(si.total_line, 0) - (COALESCE(si.qty, 0) * COALESCE(NULLIF(si.purchase_price_snapshot, 0), p.purchase_price, 0))), 0) AS total_profit,
          COUNT(DISTINCT s.id) AS sales_count
        FROM ${DbTables.saleItems} si
        INNER JOIN ${DbTables.sales} s ON si.sale_id = s.id
        LEFT JOIN ${DbTables.products} p
          ON (si.product_id = p.id)
          OR (
            si.product_id IS NULL
            AND TRIM(si.product_code_snapshot) COLLATE NOCASE = TRIM(p.code) COLLATE NOCASE
          )
        WHERE s.kind IN ('invoice', 'sale')
          AND s.status IN ('completed', 'PAID', 'PARTIAL_REFUND')
          AND s.deleted_at_ms IS NULL
          AND s.created_at_ms >= ? 
          AND s.created_at_ms <= ?
      ) t
    ''';

    final totalsResult = await db.rawQuery(totalsQuery, [startMs, endMs]);
    final totalSales =
        (totalsResult.first['total_sales'] as num?)?.toDouble() ?? 0.0;
    final totalCost =
        (totalsResult.first['total_cost'] as num?)?.toDouble() ?? 0.0;
    final totalProfit =
        (totalsResult.first['total_profit'] as num?)?.toDouble() ?? 0.0;
    final salesCount = (totalsResult.first['sales_count'] as int?) ?? 0;
    final avgTicket =
        (totalsResult.first['avg_ticket'] as num?)?.toDouble() ?? 0.0;

    // Fallback: si no hay items O si hay conteo pero el monto sale 0 (datos legados), usar tabla sales
    double finalTotalSales = totalSales;
    double finalTotalProfit = totalProfit;
    int finalSalesCount = salesCount;
    double finalAvgTicket = avgTicket;

    if (finalTotalSales == 0) {
      final salesOnly = await db.rawQuery(
        '''
          SELECT 
            COALESCE(SUM(total), 0) AS total_sales,
            COUNT(id) AS sales_count,
            COALESCE(AVG(total), 0) AS avg_ticket
          FROM ${DbTables.sales}
          WHERE kind IN ('invoice', 'sale')
            AND status IN ('completed', 'PAID', 'PARTIAL_REFUND')
            AND deleted_at_ms IS NULL
            AND created_at_ms >= ?
            AND created_at_ms <= ?
        ''' ,
        [startMs, endMs],
      );

      final fallbackTotalSales =
          (salesOnly.first['total_sales'] as num?)?.toDouble() ?? 0.0;
      final fallbackSalesCount = (salesOnly.first['sales_count'] as int?) ?? 0;
      final fallbackAvgTicket =
          (salesOnly.first['avg_ticket'] as num?)?.toDouble() ?? 0.0;

      // Solo aplicar fallback si realmente hay ventas en la tabla sales.
      // Esto cubre el caso típico: existen ventas pero sale_items no tiene líneas útiles.
      if (fallbackSalesCount > 0 && fallbackTotalSales > 0) {
        finalTotalSales = fallbackTotalSales;
        finalSalesCount = fallbackSalesCount;
        finalAvgTicket = fallbackAvgTicket;
        // Si llegamos aquí es porque sale_items no tiene líneas útiles para costo/ganancia.
        // No es posible calcular ganancia real; evitamos mostrar 100% margen.
        finalTotalProfit = 0.0;
      }
    }

    // Cotizaciones
    final quotesQuery =
        '''
      SELECT COUNT(id) as quotes_count
      FROM ${DbTables.sales}
      WHERE kind = 'quote'
        AND deleted_at_ms IS NULL
        AND created_at_ms >= ?
        AND created_at_ms <= ?
    ''';

    final quotesResult = await db.rawQuery(quotesQuery, [startMs, endMs]);
    final quotesCount = (quotesResult.first['quotes_count'] as int?) ?? 0;

    // Cotizaciones convertidas (las que tienen status='converted' o similar)
    // Nota: si no tienes este campo, cuenta las ventas que tengan referencia a quote
    final quotesConvertedQuery =
        '''
      SELECT COUNT(id) as converted_count
      FROM ${DbTables.sales}
      WHERE kind IN ('invoice', 'sale')
        AND status IN ('completed', 'PAID', 'PARTIAL_REFUND')
        AND deleted_at_ms IS NULL
        AND created_at_ms >= ?
        AND created_at_ms <= ?
    ''';

    final quotesConvertedResult = await db.rawQuery(quotesConvertedQuery, [
      startMs,
      endMs,
    ]);
    final quotesConverted =
        (quotesConvertedResult.first['converted_count'] as int?) ?? 0;

    // ========== DATOS DE PRÉSTAMOS ==========
    // Total prestado en el período
    final loansLentQuery =
        '''
      SELECT COALESCE(SUM(principal), 0) as total
      FROM ${DbTables.loans}
      WHERE deleted_at_ms IS NULL
        AND created_at_ms >= ?
        AND created_at_ms <= ?
    ''';
    final loansLentResult = await db.rawQuery(loansLentQuery, [startMs, endMs]);
    final loansLent =
        (loansLentResult.first['total'] as num?)?.toDouble() ?? 0.0;

    // Total cobrado en el período
    final loansCollectedQuery =
        '''
      SELECT COALESCE(SUM(amount), 0) as total
      FROM ${DbTables.loanPayments}
      WHERE paid_at_ms >= ?
        AND paid_at_ms <= ?
    ''';
    final loansCollectedResult = await db.rawQuery(loansCollectedQuery, [
      startMs,
      endMs,
    ]);
    final loansCollected =
        (loansCollectedResult.first['total'] as num?)?.toDouble() ?? 0.0;

    // Cartera activa (balance total pendiente)
    final loansBalanceQuery =
        '''
      SELECT COALESCE(SUM(balance), 0) as total
      FROM ${DbTables.loans}
      WHERE status IN ('OPEN', 'OVERDUE')
        AND deleted_at_ms IS NULL
    ''';
    final loansBalanceResult = await db.rawQuery(loansBalanceQuery);
    final loansBalance =
        (loansBalanceResult.first['total'] as num?)?.toDouble() ?? 0.0;

    // Préstamos vencidos
    final loansOverdueQuery =
        '''
      SELECT COUNT(id) as count
      FROM ${DbTables.loans}
      WHERE status = 'OVERDUE'
        AND deleted_at_ms IS NULL
    ''';
    final loansOverdueResult = await db.rawQuery(loansOverdueQuery);
    final loansOverdue = (loansOverdueResult.first['count'] as int?) ?? 0;

    // Préstamos activos
    final loansActiveQuery =
        '''
      SELECT COUNT(id) as count
      FROM ${DbTables.loans}
      WHERE status IN ('OPEN', 'OVERDUE')
        AND deleted_at_ms IS NULL
    ''';
    final loansActiveResult = await db.rawQuery(loansActiveQuery);
    final loansActive = (loansActiveResult.first['count'] as int?) ?? 0;

    // ========== DATOS DE CAJA ==========
    double cashIncome = 0;
    double cashExpense = 0;
    try {
      final cashIncomeQuery =
          '''
        SELECT COALESCE(SUM(amount), 0) as total
        FROM ${DbTables.cashMovements}
        WHERE type = 'IN'
          AND created_at_ms >= ?
          AND created_at_ms <= ?
      ''';
      final cashIncomeResult = await db.rawQuery(cashIncomeQuery, [
        startMs,
        endMs,
      ]);
      cashIncome = (cashIncomeResult.first['total'] as num?)?.toDouble() ?? 0.0;

      final cashExpenseQuery =
          '''
        SELECT COALESCE(SUM(amount), 0) as total
        FROM ${DbTables.cashMovements}
        WHERE type = 'OUT'
          AND created_at_ms >= ?
          AND created_at_ms <= ?
      ''';
      final cashExpenseResult = await db.rawQuery(cashExpenseQuery, [
        startMs,
        endMs,
      ]);
      cashExpense =
          (cashExpenseResult.first['total'] as num?)?.toDouble() ?? 0.0;
    } catch (_) {
      // La tabla puede no existir
    }

    return KpisData(
      totalSales: finalTotalSales,
      totalProfit: finalTotalProfit,
      totalCost: totalCost,
      salesCount: finalSalesCount,
      quotesCount: quotesCount,
      quotesConverted: quotesConverted,
      avgTicket: finalAvgTicket,
      loansLent: loansLent,
      loansCollected: loansCollected,
      loansBalance: loansBalance,
      loansOverdue: loansOverdue,
      loansActive: loansActive,
      cashIncome: cashIncome,
      cashExpense: cashExpense,
    );
  }

  /// Serie temporal de ventas totales por día
  static Future<List<SeriesDataPoint>> getSalesSeries({
    required int startMs,
    required int endMs,
    String groupBy = 'day', // day, week, month
  }) async {
    final db = await AppDb.database;

    final query =
        '''
      SELECT 
        DATE(datetime(s.created_at_ms/1000, 'unixepoch', 'localtime')) as date_label,
        COALESCE(SUM(COALESCE(si.total_line, 0)), 0) as daily_total
      FROM ${DbTables.saleItems} si
      INNER JOIN ${DbTables.sales} s ON si.sale_id = s.id
      WHERE s.kind IN ('invoice', 'sale')
        AND s.status IN ('completed', 'PAID', 'PARTIAL_REFUND')
        AND s.deleted_at_ms IS NULL
        AND s.created_at_ms >= ?
        AND s.created_at_ms <= ?
      GROUP BY date_label
      ORDER BY date_label ASC
    ''';

    final results = await db.rawQuery(query, [startMs, endMs]);
    var series = results.map((row) {
      final label = row['date_label'] as String;
      final value = (row['daily_total'] as num?)?.toDouble() ?? 0.0;
      return SeriesDataPoint(label, value);
    }).toList();

    // Fallback: si no hay items, usar tabla sales
    if (series.isEmpty) {
      final fallback = await db.rawQuery(
        '''
          SELECT 
            DATE(datetime(created_at_ms/1000, 'unixepoch', 'localtime')) as date_label,
            COALESCE(SUM(total), 0) as daily_total
          FROM ${DbTables.sales}
          WHERE kind IN ('invoice', 'sale')
            AND status IN ('completed', 'PAID', 'PARTIAL_REFUND')
            AND deleted_at_ms IS NULL
            AND created_at_ms >= ?
            AND created_at_ms <= ?
          GROUP BY date_label
          ORDER BY date_label ASC
        ''',
        [startMs, endMs],
      );

      series = fallback.map((row) {
        final label = row['date_label'] as String;
        final value = (row['daily_total'] as num?)?.toDouble() ?? 0.0;
        return SeriesDataPoint(label, value);
      }).toList();
    }

    return series;
  }

  /// Serie temporal de ganancias por día
  static Future<List<SeriesDataPoint>> getProfitSeries({
    required int startMs,
    required int endMs,
  }) async {
    final db = await AppDb.database;

    final query =
        '''
      SELECT 
        DATE(datetime(s.created_at_ms/1000, 'unixepoch', 'localtime')) as date_label,
        COALESCE(SUM(
          COALESCE(si.total_line, 0)
          - (si.qty * COALESCE(NULLIF(si.purchase_price_snapshot, 0), p.purchase_price, 0))
        ), 0) as daily_profit
      FROM ${DbTables.saleItems} si
      INNER JOIN ${DbTables.sales} s ON si.sale_id = s.id
      LEFT JOIN ${DbTables.products} p
        ON (si.product_id = p.id)
        OR (
          si.product_id IS NULL
          AND TRIM(si.product_code_snapshot) COLLATE NOCASE = TRIM(p.code) COLLATE NOCASE
        )
      WHERE s.kind IN ('invoice', 'sale')
        AND s.status IN ('completed', 'PAID', 'PARTIAL_REFUND')
        AND s.deleted_at_ms IS NULL
        AND s.created_at_ms >= ?
        AND s.created_at_ms <= ?
      GROUP BY date_label
      ORDER BY date_label ASC
    ''';

    final results = await db.rawQuery(query, [startMs, endMs]);
    var series = results.map((row) {
      final label = row['date_label'] as String;
      final value = (row['daily_profit'] as num?)?.toDouble() ?? 0.0;
      return SeriesDataPoint(label, value);
    }).toList();

    if (series.isEmpty) {
      // Sin items/costos no se puede calcular ganancia; devolver 0 por período.
      final fallback = await db.rawQuery(
        '''
          SELECT 
            DATE(datetime(created_at_ms/1000, 'unixepoch', 'localtime')) as date_label,
            0 as daily_profit
          FROM ${DbTables.sales}
          WHERE kind IN ('invoice', 'sale')
            AND status IN ('completed', 'PAID', 'PARTIAL_REFUND')
            AND deleted_at_ms IS NULL
            AND created_at_ms >= ?
            AND created_at_ms <= ?
          GROUP BY date_label
          ORDER BY date_label ASC
        ''',
        [startMs, endMs],
      );

      series = fallback.map((row) {
        final label = row['date_label'] as String;
        return SeriesDataPoint(label, 0.0);
      }).toList();
    }

    return series;
  }

  /// Top productos por ventas
  static Future<List<TopProduct>> getTopProducts({
    required int startMs,
    required int endMs,
    int limit = 10,
  }) async {
    final db = await AppDb.database;

    final query =
        '''
      SELECT 
        si.product_id,
        (CASE WHEN LENGTH(TRIM(si.product_name_snapshot)) > 0 THEN si.product_name_snapshot ELSE COALESCE(p.name, '') END) as product_name,
        COALESCE(SUM(COALESCE(si.total_line, 0)), 0) as total_sales,
        COALESCE(SUM(si.qty), 0) as total_qty,
        COALESCE(SUM((COALESCE(si.total_line, 0)) - (si.qty * COALESCE(NULLIF(si.purchase_price_snapshot, 0), p.purchase_price, 0))), 0) as total_profit
      FROM ${DbTables.saleItems} si
      INNER JOIN ${DbTables.sales} s ON si.sale_id = s.id
      LEFT JOIN ${DbTables.products} p
        ON (si.product_id = p.id)
        OR (
          si.product_id IS NULL
          AND TRIM(si.product_code_snapshot) COLLATE NOCASE = TRIM(p.code) COLLATE NOCASE
        )
      WHERE s.kind IN ('invoice', 'sale')
        AND s.status IN ('completed', 'PAID', 'PARTIAL_REFUND')
        AND s.deleted_at_ms IS NULL
        AND s.created_at_ms >= ?
        AND s.created_at_ms <= ?
      GROUP BY si.product_id, product_name
      ORDER BY total_sales DESC
      LIMIT ?
    ''';

    final results = await db.rawQuery(query, [startMs, endMs, limit]);

    return results.map((row) {
      return TopProduct(
        productId: row['product_id'] as int? ?? 0,
        productName: row['product_name'] as String? ?? '',
        totalSales: (row['total_sales'] as num?)?.toDouble() ?? 0.0,
        totalQty: (row['total_qty'] as num?)?.toDouble() ?? 0.0,
        totalProfit: (row['total_profit'] as num?)?.toDouble() ?? 0.0,
      );
    }).toList();
  }

  /// Top clientes por monto gastado
  static Future<List<TopClient>> getTopClients({
    required int startMs,
    required int endMs,
    int limit = 10,
  }) async {
    final db = await AppDb.database;

    final query =
        '''
      SELECT 
        s.customer_id as client_id,
        s.customer_name_snapshot as client_name,
        COALESCE(SUM(s.total), 0) as total_spent,
        COUNT(s.id) as purchase_count
      FROM ${DbTables.sales} s
      WHERE s.kind IN ('invoice', 'sale')
        AND s.status IN ('completed', 'PAID', 'PARTIAL_REFUND')
        AND s.deleted_at_ms IS NULL
        AND s.customer_id IS NOT NULL
        AND s.created_at_ms >= ?
        AND s.created_at_ms <= ?
      GROUP BY s.customer_id, s.customer_name_snapshot
      ORDER BY total_spent DESC
      LIMIT ?
    ''';

    final results = await db.rawQuery(query, [startMs, endMs, limit]);

    return results.map((row) {
      return TopClient(
        clientId: row['client_id'] as int? ?? 0,
        clientName: row['client_name'] as String? ?? 'Cliente General',
        totalSpent: (row['total_spent'] as num?)?.toDouble() ?? 0.0,
        purchaseCount: row['purchase_count'] as int? ?? 0,
      );
    }).toList();
  }

  /// Ventas por usuario
  static Future<List<SalesByUser>> getSalesByUser({
    required int startMs,
    required int endMs,
  }) async {
    final db = await AppDb.database;

    // Nota: si no tienes user_id en sales, ajusta según tu esquema
    final query =
        '''
      SELECT 
        1 as user_id,
        'admin' as username,
        COALESCE(SUM(s.total), 0) as total_sales,
        COUNT(s.id) as sales_count
      FROM ${DbTables.sales} s
      WHERE s.kind IN ('invoice', 'sale')
        AND s.status IN ('completed', 'PAID', 'PARTIAL_REFUND')
        AND s.deleted_at_ms IS NULL
        AND s.created_at_ms >= ?
        AND s.created_at_ms <= ?
    ''';

    final results = await db.rawQuery(query, [startMs, endMs]);

    return results.map((row) {
      return SalesByUser(
        userId: row['user_id'] as int? ?? 1,
        username: row['username'] as String? ?? 'admin',
        totalSales: (row['total_sales'] as num?)?.toDouble() ?? 0.0,
        salesCount: row['sales_count'] as int? ?? 0,
      );
    }).toList();
  }

  /// Lista de ventas para el rango
  static Future<List<SaleRecord>> getSalesList({
    required int startMs,
    required int endMs,
    int? userId,
  }) async {
    final db = await AppDb.database;

    final query =
        '''
      SELECT 
        id,
        local_code,
        kind,
        created_at_ms,
        customer_name_snapshot,
        total,
        payment_method
      FROM ${DbTables.sales}
      WHERE kind IN ('invoice', 'sale')
        AND status IN ('completed', 'PAID', 'PARTIAL_REFUND')
        AND deleted_at_ms IS NULL
        AND created_at_ms >= ?
        AND created_at_ms <= ?
      ORDER BY created_at_ms DESC
    ''';

    final results = await db.rawQuery(query, [startMs, endMs]);

    return results.map((row) {
      return SaleRecord(
        id: row['id'] as int,
        localCode: row['local_code'] as String,
        kind: row['kind'] as String,
        createdAtMs: row['created_at_ms'] as int,
        customerName: row['customer_name_snapshot'] as String?,
        total: (row['total'] as num).toDouble(),
        paymentMethod: row['payment_method'] as String?,
      );
    }).toList();
  }

  /// Exportar a CSV (simple)
  static Future<String> exportToCSV({
    required int startMs,
    required int endMs,
  }) async {
    final sales = await getSalesList(startMs: startMs, endMs: endMs);

    final buffer = StringBuffer();
    buffer.writeln('Código,Tipo,Fecha,Cliente,Total,Método Pago');

    for (final sale in sales) {
      final date = DateTime.fromMillisecondsSinceEpoch(sale.createdAtMs);
      final dateStr =
          '${date.year}-${date.month.toString().padLeft(2, '0')}-${date.day.toString().padLeft(2, '0')}';

      buffer.writeln(
        '${sale.localCode},${sale.kind},$dateStr,${sale.customerName ?? 'N/A'},${sale.total.toStringAsFixed(2)},${sale.paymentMethod ?? 'N/A'}',
      );
    }

    return buffer.toString();
  }

  /// Obtiene distribución de ventas por método de pago
  static Future<List<PaymentMethodData>> getPaymentMethodDistribution({
    required int startMs,
    required int endMs,
  }) async {
    final db = await AppDb.database;

    final query =
        '''
      SELECT 
        COALESCE(s.payment_method, 'Efectivo') as method,
        COALESCE(SUM(COALESCE(si.total_line, 0)), 0) as amount,
        COUNT(DISTINCT s.id) as count
      FROM ${DbTables.saleItems} si
      INNER JOIN ${DbTables.sales} s ON si.sale_id = s.id
      WHERE s.kind IN ('invoice', 'sale')
        AND s.status IN ('completed', 'PAID', 'PARTIAL_REFUND')
        AND s.deleted_at_ms IS NULL
        AND s.created_at_ms >= ?
        AND s.created_at_ms <= ?
      GROUP BY method
      ORDER BY amount DESC
    ''';

    final results = await db.rawQuery(query, [startMs, endMs]);
    var data = results.map((row) {
      String method = row['method'] as String? ?? 'Efectivo';
      if (method == 'cash' || method.isEmpty) method = 'Efectivo';
      if (method == 'card') method = 'Tarjeta';
      if (method == 'transfer') method = 'Transferencia';
      if (method == 'credit') method = 'Crédito';

      return PaymentMethodData(
        method: method,
        amount: (row['amount'] as num?)?.toDouble() ?? 0.0,
        count: (row['count'] as int?) ?? 0,
      );
    }).toList();

    final totalAmount = data.fold<double>(0, (sum, e) => sum + e.amount);
    final totalCount = data.fold<int>(0, (sum, e) => sum + e.count);

    // Si hay conteo pero el monto sale 0, es un indicador fuerte de datos legados/inconsistentes
    // en sale_items. En ese caso, usamos fallback desde sales.
    if (data.isEmpty || (totalCount > 0 && totalAmount == 0)) {
      final fallback = await db.rawQuery(
        '''
          SELECT 
            COALESCE(payment_method, 'Efectivo') as method,
            COALESCE(SUM(total), 0) as amount,
            COUNT(id) as count
          FROM ${DbTables.sales}
          WHERE kind IN ('invoice', 'sale')
            AND status IN ('completed', 'PAID', 'PARTIAL_REFUND')
            AND deleted_at_ms IS NULL
            AND created_at_ms >= ?
            AND created_at_ms <= ?
          GROUP BY method
          ORDER BY amount DESC
        ''',
        [startMs, endMs],
      );

      data = fallback.map((row) {
        String method = row['method'] as String? ?? 'Efectivo';
        if (method == 'cash' || method.isEmpty) method = 'Efectivo';
        if (method == 'card') method = 'Tarjeta';
        if (method == 'transfer') method = 'Transferencia';
        if (method == 'credit') method = 'Crédito';

        return PaymentMethodData(
          method: method,
          amount: (row['amount'] as num?)?.toDouble() ?? 0.0,
          count: (row['count'] as int?) ?? 0,
        );
      }).toList();
    }

    return data;
  }

  /// Obtiene los préstamos activos para el reporte
  static Future<List<LoanReportItem>> getActiveLoans() async {
    final db = await AppDb.database;
    final now = DateTime.now().millisecondsSinceEpoch;

    final query =
        '''
      SELECT 
        l.id,
        COALESCE(c.nombre, 'Cliente Desconocido') as client_name,
        l.principal,
        l.balance,
        l.total_due,
        l.status,
        l.start_date_ms,
        l.frequency,
        (
          SELECT COUNT(*)
          FROM ${DbTables.loanInstallments} li
          WHERE li.loan_id = l.id
            AND li.amount_paid < li.amount_due
            AND li.due_date_ms < ?
        ) as overdue_count
      FROM ${DbTables.loans} l
      LEFT JOIN ${DbTables.clients} c ON l.client_id = c.id
      WHERE l.status IN ('OPEN', 'OVERDUE')
        AND l.deleted_at_ms IS NULL
      ORDER BY l.status DESC, l.start_date_ms DESC
    ''';

    final results = await db.rawQuery(query, [now]);

    return results.map((row) {
      return LoanReportItem(
        id: row['id'] as int,
        clientName: row['client_name'] as String,
        principal: (row['principal'] as num).toDouble(),
        balance: (row['balance'] as num).toDouble(),
        totalDue: (row['total_due'] as num).toDouble(),
        status: row['status'] as String,
        startDateMs: row['start_date_ms'] as int,
        overdueInstallments: (row['overdue_count'] as int?) ?? 0,
        frequency: row['frequency'] as String? ?? 'monthly',
      );
    }).toList();
  }

  /// Obtiene los pagos pendientes (cuotas próximas o vencidas)
  static Future<List<PendingPayment>> getPendingPayments({
    int limit = 50,
  }) async {
    final db = await AppDb.database;

    // Cuotas pendientes ordenadas por fecha de vencimiento
    final query =
        '''
      SELECT 
        li.loan_id,
        li.number as installment_number,
        COALESCE(c.nombre, 'Cliente Desconocido') as client_name,
        li.amount_due,
        li.amount_paid,
        li.due_date_ms,
        li.status
      FROM ${DbTables.loanInstallments} li
      INNER JOIN ${DbTables.loans} l ON li.loan_id = l.id
      LEFT JOIN ${DbTables.clients} c ON l.client_id = c.id
      WHERE li.amount_paid < li.amount_due
        AND l.deleted_at_ms IS NULL
        AND l.status IN ('OPEN', 'OVERDUE')
      ORDER BY li.due_date_ms ASC
      LIMIT ?
    ''';

    final results = await db.rawQuery(query, [limit]);

    return results.map((row) {
      return PendingPayment(
        loanId: row['loan_id'] as int,
        installmentNumber: row['installment_number'] as int,
        clientName: row['client_name'] as String,
        amountDue: (row['amount_due'] as num).toDouble(),
        amountPaid: (row['amount_paid'] as num?)?.toDouble() ?? 0.0,
        dueDateMs: row['due_date_ms'] as int,
        status: row['status'] as String,
      );
    }).toList();
  }

  /// Serie de cobros de préstamos por día
  static Future<List<SeriesDataPoint>> getLoanCollectionsSeries({
    required int startMs,
    required int endMs,
  }) async {
    final db = await AppDb.database;

    final query =
        '''
      SELECT 
        DATE(paid_at_ms / 1000, 'unixepoch') as date_label,
        COALESCE(SUM(amount), 0) as daily_total
      FROM ${DbTables.loanPayments}
      WHERE paid_at_ms >= ?
        AND paid_at_ms <= ?
      GROUP BY date_label
      ORDER BY date_label ASC
    ''';

    final results = await db.rawQuery(query, [startMs, endMs]);

    return results.map((row) {
      final label = row['date_label'] as String;
      final value = (row['daily_total'] as num?)?.toDouble() ?? 0.0;
      return SeriesDataPoint(label, value);
    }).toList();
  }

  /// Obtiene estadísticas comparativas (hoy vs ayer, esta semana vs anterior)
  static Future<Map<String, dynamic>> getComparativeStats() async {
    final db = await AppDb.database;
    final now = DateTime.now();
    final today = DateTime(now.year, now.month, now.day);
    final yesterday = today.subtract(const Duration(days: 1));
    final weekStart = today.subtract(Duration(days: today.weekday - 1));
    final lastWeekStart = weekStart.subtract(const Duration(days: 7));
    final lastWeekEnd = weekStart.subtract(const Duration(milliseconds: 1));
    final monthStart = DateTime(now.year, now.month, 1);
    final lastMonthStart = DateTime(now.year, now.month - 1, 1);
    final lastMonthEnd = monthStart.subtract(const Duration(milliseconds: 1));

    // Ventas de hoy
    final todayQuery =
        '''
      SELECT COALESCE(SUM(total), 0) as total, COUNT(id) as count
      FROM ${DbTables.sales}
      WHERE kind IN ('invoice', 'sale') AND status IN ('completed', 'PAID', 'PARTIAL_REFUND') AND deleted_at_ms IS NULL
        AND created_at_ms >= ? AND created_at_ms < ?
    ''';
    final todayResult = await db.rawQuery(todayQuery, [
      today.millisecondsSinceEpoch,
      today.add(const Duration(days: 1)).millisecondsSinceEpoch,
    ]);

    // Ventas de ayer
    final yesterdayResult = await db.rawQuery(todayQuery, [
      yesterday.millisecondsSinceEpoch,
      today.millisecondsSinceEpoch,
    ]);

    // Ventas esta semana
    final weekResult = await db.rawQuery(todayQuery, [
      weekStart.millisecondsSinceEpoch,
      now.millisecondsSinceEpoch,
    ]);

    // Ventas semana pasada
    final lastWeekResult = await db.rawQuery(todayQuery, [
      lastWeekStart.millisecondsSinceEpoch,
      lastWeekEnd.millisecondsSinceEpoch,
    ]);

    // Ventas este mes
    final monthResult = await db.rawQuery(todayQuery, [
      monthStart.millisecondsSinceEpoch,
      now.millisecondsSinceEpoch,
    ]);

    // Ventas mes pasado
    final lastMonthResult = await db.rawQuery(todayQuery, [
      lastMonthStart.millisecondsSinceEpoch,
      lastMonthEnd.millisecondsSinceEpoch,
    ]);

    return {
      'today': {
        'sales': (todayResult.first['total'] as num?)?.toDouble() ?? 0.0,
        'count': (todayResult.first['count'] as int?) ?? 0,
      },
      'yesterday': {
        'sales': (yesterdayResult.first['total'] as num?)?.toDouble() ?? 0.0,
        'count': (yesterdayResult.first['count'] as int?) ?? 0,
      },
      'thisWeek': {
        'sales': (weekResult.first['total'] as num?)?.toDouble() ?? 0.0,
        'count': (weekResult.first['count'] as int?) ?? 0,
      },
      'lastWeek': {
        'sales': (lastWeekResult.first['total'] as num?)?.toDouble() ?? 0.0,
        'count': (lastWeekResult.first['count'] as int?) ?? 0,
      },
      'thisMonth': {
        'sales': (monthResult.first['total'] as num?)?.toDouble() ?? 0.0,
        'count': (monthResult.first['count'] as int?) ?? 0,
      },
      'lastMonth': {
        'sales': (lastMonthResult.first['total'] as num?)?.toDouble() ?? 0.0,
        'count': (lastMonthResult.first['count'] as int?) ?? 0,
      },
    };
  }
}

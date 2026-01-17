import 'package:sqflite/sqflite.dart';

import '../../../core/db/app_db.dart';
import '../../../core/db/tables.dart';
import '../models/stock_movement_model.dart';

/// Repositorio para operaciones de movimientos de stock
class StockRepository {
  /// Obtiene todos los movimientos de un producto
  Future<List<StockMovementModel>> getByProductId(
    int productId, {
    int? limit,
  }) async {
    final db = await AppDb.database;

    final List<Map<String, dynamic>> maps = await db.query(
      DbTables.stockMovements,
      where: 'product_id = ?',
      whereArgs: [productId],
      orderBy: 'created_at_ms DESC',
      limit: limit,
    );

    return List.generate(
      maps.length,
      (i) => StockMovementModel.fromMap(maps[i]),
    );
  }

  /// Obtiene todos los movimientos con filtros opcionales
  Future<List<StockMovementModel>> getAll({
    StockMovementType? type,
    DateTime? from,
    DateTime? to,
    int? limit,
  }) async {
    final db = await AppDb.database;

    String? where;
    List<dynamic> whereArgs = [];

    if (type != null) {
      where = 'type = ?';
      whereArgs.add(type.value);
    }

    if (from != null) {
      where = (where == null) ? '' : '$where AND ';
      where += 'created_at_ms >= ?';
      whereArgs.add(from.millisecondsSinceEpoch);
    }

    if (to != null) {
      where = (where == null) ? '' : '$where AND ';
      where += 'created_at_ms <= ?';
      whereArgs.add(to.millisecondsSinceEpoch);
    }

    final List<Map<String, dynamic>> maps = await db.query(
      DbTables.stockMovements,
      where: where?.isEmpty ?? true ? null : where,
      whereArgs: whereArgs.isEmpty ? null : whereArgs,
      orderBy: 'created_at_ms DESC',
      limit: limit,
    );

    return List.generate(
      maps.length,
      (i) => StockMovementModel.fromMap(maps[i]),
    );
  }

  /// Ajusta el stock de un producto y registra el movimiento
  /// Esta operación es ATÓMICA (usa transacción)
  Future<int> adjustStock({
    required int productId,
    required StockMovementType type,
    required double quantity,
    String? note,
    int? userId,
  }) async {
    if (quantity <= 0) {
      throw ArgumentError('La cantidad debe ser mayor que 0');
    }

    final db = await AppDb.database;
    int movementId = 0;

    // Usar transacción para garantizar atomicidad
    await db.transaction((txn) async {
      // 1. Obtener el producto actual
      final productMaps = await txn.query(
        DbTables.products,
        where: 'id = ?',
        whereArgs: [productId],
        limit: 1,
      );

      if (productMaps.isEmpty) {
        throw ArgumentError('No existe un producto con ID $productId');
      }

      final currentStock =
          (productMaps.first['stock'] as num?)?.toDouble() ?? 0.0;

      // 2. Calcular el nuevo stock según el tipo de movimiento
      double newStock = currentStock;

      switch (type) {
        case StockMovementType.input:
          newStock = currentStock + quantity;
          break;
        case StockMovementType.output:
          newStock = currentStock - quantity;
          if (newStock < 0) {
            throw ArgumentError(
              'Stock insuficiente. Stock actual: $currentStock, cantidad solicitada: $quantity',
            );
          }
          break;
        case StockMovementType.adjust:
          // Para ajustes, quantity es el nuevo valor de stock (no delta)
          newStock = quantity;
          break;
      }

      // 3. Actualizar el stock del producto
      final now = DateTime.now().millisecondsSinceEpoch;
      await txn.update(
        DbTables.products,
        {'stock': newStock, 'updated_at_ms': now},
        where: 'id = ?',
        whereArgs: [productId],
      );

      // 4. Registrar el movimiento de stock
      // Para ajustes, guardamos el delta (diferencia)
      final movementQuantity = type == StockMovementType.adjust
          ? (newStock - currentStock)
          : quantity;

      final movement = StockMovementModel(
        productId: productId,
        type: type,
        quantity: movementQuantity,
        note: note,
        userId: userId,
        createdAtMs: now,
      );

      movementId = await txn.insert(DbTables.stockMovements, movement.toMap());
    });

    return movementId;
  }

  /// Registra una entrada de stock
  Future<int> recordInput({
    required int productId,
    required double quantity,
    String? note,
    int? userId,
  }) async {
    return adjustStock(
      productId: productId,
      type: StockMovementType.input,
      quantity: quantity,
      note: note,
      userId: userId,
    );
  }

  /// Registra una salida de stock
  Future<int> recordOutput({
    required int productId,
    required double quantity,
    String? note,
    int? userId,
  }) async {
    return adjustStock(
      productId: productId,
      type: StockMovementType.output,
      quantity: quantity,
      note: note,
      userId: userId,
    );
  }

  /// Ajusta el stock a un valor específico
  Future<int> setStock({
    required int productId,
    required double newStock,
    String? note,
  }) async {
    if (newStock < 0) {
      throw ArgumentError('El stock no puede ser negativo');
    }

    return adjustStock(
      productId: productId,
      type: StockMovementType.adjust,
      quantity: newStock,
      note: note,
    );
  }

  /// Obtiene el historial completo de movimientos de un producto
  Future<List<StockMovementModel>> getHistory(
    int productId, {
    int? limit = 50,
  }) async {
    return getByProductId(productId, limit: limit);
  }

  /// Cuenta los movimientos
  Future<int> count({
    int? productId,
    StockMovementType? type,
    DateTime? from,
    DateTime? to,
  }) async {
    final db = await AppDb.database;

    String where = '';
    List<dynamic> whereArgs = [];

    if (productId != null) {
      where = 'product_id = ?';
      whereArgs.add(productId);
    }

    if (type != null) {
      where += where.isEmpty ? '' : ' AND ';
      where += 'type = ?';
      whereArgs.add(type.value);
    }

    if (from != null) {
      where += where.isEmpty ? '' : ' AND ';
      where += 'created_at_ms >= ?';
      whereArgs.add(from.millisecondsSinceEpoch);
    }

    if (to != null) {
      where += where.isEmpty ? '' : ' AND ';
      where += 'created_at_ms <= ?';
      whereArgs.add(to.millisecondsSinceEpoch);
    }

    final result = await db.query(
      DbTables.stockMovements,
      columns: ['COUNT(*) as count'],
      where: where.isEmpty ? null : where,
      whereArgs: whereArgs.isEmpty ? null : whereArgs,
    );

    return Sqflite.firstIntValue(result) ?? 0;
  }

  /// Elimina movimientos antiguos (limpieza de datos)
  Future<int> deleteOlderThan(DateTime date) async {
    final db = await AppDb.database;

    return await db.delete(
      DbTables.stockMovements,
      where: 'created_at_ms < ?',
      whereArgs: [date.millisecondsSinceEpoch],
    );
  }
}

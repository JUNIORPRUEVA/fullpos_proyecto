import 'package:sqflite/sqflite.dart';

import '../db/app_db.dart';
import 'db_logger.dart';
import 'db_preflight.dart';
import 'db_repair.dart';

class DbHardening {
  DbHardening._();

  static final DbHardening instance = DbHardening._();

  final _preflight = DbPreflight();

  Future<void> preflight() => _preflight.run();

  Future<T> runDbSafe<T>(
    Future<T> Function() action, {
    String stage = 'db_operation',
  }) async {
    var attempts = 0;
    while (true) {
      try {
        return await action();
      } on DatabaseException catch (error, trace) {
        final message = error.toString().toLowerCase();
        if (_isLockError(message) && attempts < 3) {
          attempts++;
          await Future.delayed(Duration(milliseconds: 100 * attempts));
          continue;
        }

        final repaired = await DbRepair.instance.tryFix(error, trace);
        if (repaired && attempts < 1) {
          attempts++;
          continue;
        }

        await DbLogger.instance.log(
          stage: stage,
          status: 'error',
          detail: error.toString(),
          schemaVersion: AppDb.schemaVersion,
        );

        rethrow;
      }
    }
  }

  bool _isLockError(String message) => message.contains('database is locked');
}

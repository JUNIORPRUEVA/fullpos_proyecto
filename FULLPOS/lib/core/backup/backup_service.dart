import 'dart:async';
import 'dart:io';
import 'dart:isolate';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:path/path.dart' as p;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:sqflite/sqflite.dart';

import '../db/app_db.dart';
import '../db/db_init.dart';
import '../errors/error_handler.dart';
import '../errors/error_mapper.dart';
import '../logging/app_logger.dart';
import 'backup_models.dart';
import 'backup_paths.dart';
import 'backup_zip.dart';

class BackupService {
  BackupService._();

  static final BackupService instance = BackupService._();

  static const String _prefsRetentionKey = 'backup_retention_count';

  bool _running = false;
  DateTime? _lastAutoBackupAt;

  bool get isRunning => _running;

  Future<int> getRetentionCount() async {
    final prefs = await SharedPreferences.getInstance();
    final value = prefs.getInt(_prefsRetentionKey);
    return (value == null || value <= 0) ? 15 : value;
  }

  Future<void> setRetentionCount(int value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setInt(_prefsRetentionKey, value.clamp(1, 60));
  }

  Future<List<FileSystemEntity>> listBackups() async {
    final base = await BackupPaths.backupsBaseDir();
    if (!await base.exists()) return const [];

    final items = base
        .listSync()
        .whereType<File>()
        .where((f) => f.path.toLowerCase().endsWith('.zip'))
        .toList(growable: false);

    items.sort((a, b) => b.lastModifiedSync().compareTo(a.lastModifiedSync()));
    return items;
  }

  Future<BackupResult> createBackup({
    required BackupTrigger trigger,
    String? notes,
    Duration maxWait = const Duration(seconds: 30),
    bool includeOptionalFiles = true,
    bool verifyIntegrity = true,
  }) async {
    if (_running) {
      return const BackupResult(
        ok: false,
        messageUser: 'Ya hay un backup en progreso.',
      );
    }
    _running = true;

    final startedAt = DateTime.now();
    try {
      unawaited(
        AppLogger.instance.logInfo(
          'Backup iniciado: trigger=${trigger.name}',
          module: 'backup',
        ),
      );

      // 1) Cerrar DB para copiar consistente.
      await _closeDbSafely();

      // 2) Preparar paths.
      final baseDir = await BackupPaths.backupsBaseDir();
      final stamp = _formatStamp(startedAt);
      final fileName = 'backup_${stamp}_${trigger.name}.zip';
      final outZip = p.join(baseDir.path, fileName);

      final dbPath = await BackupPaths.databaseFilePath();
      final dbFile = File(dbPath);
      if (!await dbFile.exists()) {
        return BackupResult(
          ok: false,
          messageUser: 'No se encontró la base de datos para respaldar.',
          messageDev: 'DB no existe en $dbPath',
        );
      }

      final included = <String>['db/${p.basename(dbPath)}'];
      final entries = <Map<String, String>>[
        {'sourcePath': dbPath, 'zipPath': 'db/${p.basename(dbPath)}'},
      ];

      final wal = File('$dbPath-wal');
      if (await wal.exists()) {
        included.add('db/${p.basename(dbPath)}-wal');
        entries.add({
          'sourcePath': wal.path,
          'zipPath': 'db/${p.basename(dbPath)}-wal',
        });
      }
      final shm = File('$dbPath-shm');
      if (await shm.exists()) {
        included.add('db/${p.basename(dbPath)}-shm');
        entries.add({
          'sourcePath': shm.path,
          'zipPath': 'db/${p.basename(dbPath)}-shm',
        });
      }

      if (includeOptionalFiles) {
        final dirs = await BackupPaths.optionalDataDirs();
        for (final dir in dirs) {
          final name = p.basename(dir.path);
          included.add('files/$name/');
          await for (final entity
              in dir.list(recursive: true, followLinks: false)) {
            if (entity is! File) continue;
            final rel = p.relative(entity.path, from: dir.path);
            final relZip = rel.replaceAll('\\', '/');
            entries.add({
              'sourcePath': entity.path,
              'zipPath': p.posix.join('files', name, relZip),
            });
          }
        }
      }

      final meta = BackupMeta(
        createdAtIso: startedAt.toIso8601String(),
        trigger: trigger,
        appVersion: const String.fromEnvironment(
          'APP_VERSION',
          defaultValue: 'unknown',
        ),
        platform: Platform.operatingSystem,
        dbFileName: AppDb.dbFileName,
        includedPaths: included,
        notes: notes,
      );

      // 3) Crear zip (aislar CPU/IO pesado).
      await Isolate.run(() async {
        await BackupZip.createZip(
          outputZipPath: outZip,
          files: entries,
          metaJson: meta.toPrettyJson(),
        );
      }).timeout(maxWait);

      final outFile = File(outZip);
      if (!await outFile.exists()) {
        return BackupResult(
          ok: false,
          messageUser: 'No se pudo crear el archivo de backup.',
          messageDev: 'ZIP no existe en $outZip',
        );
      }

      final len = await outFile.length();
      if (len <= 0) {
        return BackupResult(
          ok: false,
          path: outZip,
          messageUser: 'El backup se creó pero parece inválido.',
          messageDev: 'ZIP demasiado pequeño ($len bytes)',
        );
      }

      bool? integrityOk;
      if (verifyIntegrity) {
        integrityOk = await _verifyZipDbIntegrity(outZip, timeout: maxWait);
      }

      // 4) Retención.
      await _applyRetention();

      unawaited(
        AppLogger.instance.logInfo(
          'Backup finalizado: ok=true path=$outZip integrity=$integrityOk',
          module: 'backup',
        ),
      );

      return BackupResult(
        ok: true,
        path: outZip,
        integrityCheckOk: integrityOk,
      );
    } catch (e, st) {
      if (e is TimeoutException) {
        unawaited(
          AppLogger.instance.logWarn(
            'Backup timeout: trigger=${trigger.name} wait=${maxWait.inSeconds}s',
            module: 'backup',
          ),
        );
        return BackupResult(
          ok: false,
          messageUser:
              'La copia de seguridad tardó demasiado. Intenta de nuevo (si tienes muchas imágenes, puede tardar).',
          messageDev: 'TimeoutException: $e',
        );
      }
      final ex = ErrorMapper.map(e, st, 'backup_create');
      unawaited(AppLogger.instance.logError(ex, module: 'backup'));
      if (kDebugMode) {
        // ignore: avoid_print
        print('Backup create failed: ${ex.messageDev}');
      }
      return BackupResult(
        ok: false,
        messageUser: 'No se pudo crear la copia de seguridad. Intenta de nuevo.',
        messageDev: ex.messageDev,
      );
    } finally {
      // Reabrir DB para que la app siga normal (manual/auto-lifecycle).
      // En autoWindowClose probablemente la app cerrará igual.
      if (trigger != BackupTrigger.autoWindowClose) {
        await _reopenDbSafely();
      }
      _running = false;
      if (trigger != BackupTrigger.manual) {
        _lastAutoBackupAt = DateTime.now();
      }
    }
  }

  Future<BackupResult> restoreBackup({
    required String zipPath,
    Duration maxWait = const Duration(seconds: 10),
  }) async {
    if (_running) {
      return const BackupResult(
        ok: false,
        messageUser: 'Ya hay un proceso de backup en progreso.',
      );
    }
    _running = true;

    try {
      final zipFile = File(zipPath);
      if (!await zipFile.exists()) {
        return BackupResult(
          ok: false,
          messageUser: 'El archivo seleccionado no existe.',
          messageDev: 'ZIP no existe: $zipPath',
        );
      }

      unawaited(
        AppLogger.instance.logInfo(
          'Restore iniciado: $zipPath',
          module: 'backup',
        ),
      );

      await _closeDbSafely();

      final dbPath = await BackupPaths.databaseFilePath();
      final dbFile = File(dbPath);

      // Safety backup del DB actual.
      final baseDir = await BackupPaths.backupsBaseDir();
      final stamp = _formatStamp(DateTime.now());
      final safetyPath = p.join(baseDir.path, 'backup_before_restore_$stamp.db');
      if (await dbFile.exists()) {
        await dbFile.copy(safetyPath);
      }

      // Extraer a temp.
      await BackupPaths.cleanTempWorkDir();
      final tempDir = await BackupPaths.tempWorkDir();
      final extractDir = Directory(p.join(tempDir.path, 'restore_$stamp'));
      if (!await extractDir.exists()) await extractDir.create(recursive: true);

      await Isolate.run(() async {
        await BackupZip.extractZip(
          zipPath: zipPath,
          outDirPath: extractDir.path,
        );
      }).timeout(maxWait);

      final extractedDb = File(p.join(extractDir.path, 'db', AppDb.dbFileName));
      if (!await extractedDb.exists()) {
        return BackupResult(
          ok: false,
          messageUser: 'El backup no contiene la base de datos.',
          messageDev: 'No existe db/${AppDb.dbFileName} en el ZIP',
        );
      }

      // Reemplazar DB.
      if (!await dbFile.parent.exists()) {
        await dbFile.parent.create(recursive: true);
      }
      await extractedDb.copy(dbPath);

      // Restaurar WAL/SHM si existen en el ZIP (para integridad en modo WAL).
      final extractedWal =
          File(p.join(extractDir.path, 'db', '${AppDb.dbFileName}-wal'));
      final extractedShm =
          File(p.join(extractDir.path, 'db', '${AppDb.dbFileName}-shm'));
      final destWal = File('$dbPath-wal');
      final destShm = File('$dbPath-shm');
      if (await extractedWal.exists()) {
        await extractedWal.copy(destWal.path);
      } else {
        try {
          if (await destWal.exists()) await destWal.delete();
        } catch (_) {}
      }
      if (await extractedShm.exists()) {
        await extractedShm.copy(destShm.path);
      } else {
        try {
          if (await destShm.exists()) await destShm.delete();
        } catch (_) {}
      }

      // Restaurar archivos opcionales (si existen en zip).
      final extractedFilesDir = Directory(p.join(extractDir.path, 'files'));
      if (await extractedFilesDir.exists()) {
        final docs = await BackupPaths.documentsDir();
        for (final entity
            in extractedFilesDir.listSync(recursive: false).whereType<Directory>()) {
          final name = p.basename(entity.path);
          final dest = Directory(p.join(docs.path, name));
          await _copyDir(entity, dest);
        }
      }

      // Verificar DB restaurada.
      final integrityOk = await _verifyDbIntegrity(dbPath);
      if (integrityOk == false) {
        // Revertir.
        if (await File(safetyPath).exists()) {
          await File(safetyPath).copy(dbPath);
        }
        return BackupResult(
          ok: false,
          messageUser:
              'El backup parece corrupto (integridad falló). Se restauró tu DB anterior.',
          messageDev: 'PRAGMA integrity_check falló para DB restaurada',
          integrityCheckOk: false,
        );
      }

      unawaited(
        AppLogger.instance.logInfo(
          'Restore finalizado: ok=true safety=$safetyPath',
          module: 'backup',
        ),
      );

      return BackupResult(
        ok: true,
        path: zipPath,
        integrityCheckOk: integrityOk,
      );
    } catch (e, st) {
      final ex = ErrorMapper.map(e, st, 'backup_restore');
      unawaited(AppLogger.instance.logError(ex, module: 'backup'));
      return BackupResult(
        ok: false,
        messageUser: 'No se pudo restaurar el backup. Intenta de nuevo.',
        messageDev: ex.messageDev,
      );
    } finally {
      await _reopenDbSafely();
      _running = false;
    }
  }

  Future<void> triggerAutoBackupIfAllowed({
    required bool enabled,
    required BackupTrigger trigger,
  }) async {
    if (!enabled) return;

    // Anti-spam: no disparar varios auto-backups seguidos.
    final last = _lastAutoBackupAt;
    if (last != null &&
        DateTime.now().difference(last) < const Duration(seconds: 30)) {
      return;
    }

    unawaited(createBackup(trigger: trigger, verifyIntegrity: false));
  }

  Future<void> _applyRetention() async {
    final keep = await getRetentionCount();
    final base = await BackupPaths.backupsBaseDir();
    if (!await base.exists()) return;

    final zips = base
        .listSync()
        .whereType<File>()
        .where((f) => f.path.toLowerCase().endsWith('.zip'))
        .toList();

    zips.sort((a, b) => b.lastModifiedSync().compareTo(a.lastModifiedSync()));

    if (zips.length <= keep) return;
    final toDelete = zips.sublist(keep);
    for (final f in toDelete) {
      try {
        await f.delete();
      } catch (_) {
        // Ignorar.
      }
    }
  }

  Future<void> _closeDbSafely() async {
    try {
      await AppDb.close().timeout(const Duration(seconds: 2));
    } catch (_) {
      // Ignorar.
    }
  }

  Future<void> _reopenDbSafely() async {
    try {
      await AppDb.database.timeout(const Duration(seconds: 2));
    } catch (_) {
      // Ignorar.
    }
  }

  Future<bool?> _verifyZipDbIntegrity(
    String zipPath, {
    required Duration timeout,
  }) async {
    try {
      await BackupPaths.cleanTempWorkDir();
      final tempDir = await BackupPaths.tempWorkDir();
      final stamp = _formatStamp(DateTime.now());
      final outDir = Directory(p.join(tempDir.path, 'verify_$stamp'));
      if (!await outDir.exists()) await outDir.create(recursive: true);

      try {
        await Isolate.run(() async {
          await BackupZip.extractZip(zipPath: zipPath, outDirPath: outDir.path);
        }).timeout(timeout);

        final extractedDb = File(p.join(outDir.path, 'db', AppDb.dbFileName));
        if (!await extractedDb.exists()) return false;
        return await _verifyDbIntegrity(extractedDb.path);
      } finally {
        try {
          if (await outDir.exists()) await outDir.delete(recursive: true);
        } catch (_) {
          // Ignorar.
        }
      }
    } catch (_) {
      return null;
    }
  }

  Future<bool?> _verifyDbIntegrity(String dbPath) async {
    try {
      // Desktop necesita sqflite_ffi listo.
      DbInit.ensureInitialized();

      final db = await openDatabase(dbPath, readOnly: true);
      final result = await db.rawQuery('PRAGMA integrity_check;');
      await db.close();
      final msg = (result.isNotEmpty ? (result.first.values.first) : null)
          ?.toString()
          .toLowerCase();
      return msg == 'ok';
    } catch (_) {
      return null;
    }
  }

  static Future<void> _copyDir(Directory from, Directory to) async {
    if (!await to.exists()) await to.create(recursive: true);

    for (final entity in from.listSync(recursive: false)) {
      if (entity is File) {
        final dest = File(p.join(to.path, p.basename(entity.path)));
        await dest.parent.create(recursive: true);
        await entity.copy(dest.path);
      } else if (entity is Directory) {
        final destDir = Directory(p.join(to.path, p.basename(entity.path)));
        await _copyDir(entity, destDir);
      }
    }
  }

  static String _formatStamp(DateTime dt) {
    String two(int v) => v.toString().padLeft(2, '0');
    final us = dt.microsecond.toString().padLeft(6, '0');
    return '${dt.year}${two(dt.month)}${two(dt.day)}_${two(dt.hour)}${two(dt.minute)}${two(dt.second)}_$us';
  }
}

Future<BackupResult> createBackupNow({
  required BackupTrigger trigger,
  BuildContext? context,
}) async {
  try {
    return await BackupService.instance.createBackup(trigger: trigger);
  } catch (e, st) {
    final ex = ErrorMapper.map(e, st, 'backup');
    unawaited(AppLogger.instance.logError(ex, module: 'backup'));
    if (context != null) {
      unawaited(
        ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          module: 'backup',
        ),
      );
    }
    return BackupResult(
      ok: false,
      messageUser: 'No se pudo crear el backup.',
      messageDev: ex.messageDev,
    );
  }
}

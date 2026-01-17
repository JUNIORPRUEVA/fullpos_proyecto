import 'package:sqflite/sqflite.dart';

import '../db/app_db.dart';
import '../db/tables.dart';
import '../session/session_manager.dart';
import 'app_actions.dart';
import 'security_config.dart';

class PermissionDecision {
  final bool allowed;
  final bool overrideAllowed;
  final bool requiresOverride;
  final AppAction? action;

  PermissionDecision({
    required this.allowed,
    required this.overrideAllowed,
    required this.requiresOverride,
    required this.action,
  });
}

class PermissionService {
  PermissionService._();

  static const String roleAdmin = 'admin';
  static const String roleSupervisor = 'supervisor';
  static const String roleCashier = 'cashier';
  static const String roleCajero = 'cajero';

  static Future<PermissionDecision> check({
    required String actionCode,
    int? companyId,
    int? userId,
    String? role,
    SecurityConfig? config,
  }) async {
    final resolvedUserId = userId ?? await SessionManager.userId();
    final resolvedRole = normalizeRole(role ?? (await SessionManager.role()) ?? roleCashier);
    final resolvedCompanyId = companyId ?? await SessionManager.companyId() ?? 1;
    if (resolvedUserId == null) {
      final action = AppActions.findByCode(actionCode);
      final requiresOverride =
          await SecurityConfigRepository.requiresOverride(actionCode, companyId: resolvedCompanyId, cached: config);
      return PermissionDecision(
        allowed: false,
        overrideAllowed: action?.overrideAllowed ?? true,
        requiresOverride: requiresOverride,
        action: action,
      );
    }

    final allowed = await can(
      actionCode: actionCode,
      companyId: resolvedCompanyId,
      userId: resolvedUserId,
      role: resolvedRole,
    );
    final action = AppActions.findByCode(actionCode);
    final requiresOverride =
        await SecurityConfigRepository.requiresOverride(actionCode, companyId: resolvedCompanyId, cached: config);

    return PermissionDecision(
      allowed: allowed,
      overrideAllowed: action?.overrideAllowed ?? true,
      requiresOverride: requiresOverride,
      action: action,
    );
  }

  static Future<bool> can({
    required String actionCode,
    required int companyId,
    required int userId,
    required String role,
  }) async {
    final normalizedRole = normalizeRole(role);
    if (normalizedRole == roleAdmin) return true;

    final db = await AppDb.database;
    final rows = await db.query(
      DbTables.userPermissions,
      columns: ['allowed'],
      where: 'company_id = ? AND user_id = ? AND action_code = ?',
      whereArgs: [companyId, userId, actionCode],
      limit: 1,
    );

    if (rows.isNotEmpty) {
      return (rows.first['allowed'] as int? ?? 0) == 1;
    }

    final defaults = defaultAllowedActionsForRole(normalizedRole);
    return defaults.contains(actionCode);
  }

  static Future<void> setUserPermission({
    required int companyId,
    required int userId,
    required String actionCode,
    required bool allowed,
  }) async {
    final db = await AppDb.database;
    final now = DateTime.now().millisecondsSinceEpoch;
    await db.insert(
      DbTables.userPermissions,
      {
        'company_id': companyId,
        'user_id': userId,
        'action_code': actionCode,
        'allowed': allowed ? 1 : 0,
        'created_at_ms': now,
        'updated_at_ms': now,
      },
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  static Future<Map<String, bool>> effectivePermissions({
    required int companyId,
    required int userId,
    required String role,
  }) async {
    final overrides = await _loadOverrides(
      companyId: companyId,
      userId: userId,
    );
    final defaults = defaultAllowedActionsForRole(role);

    final map = <String, bool>{};
    for (final action in AppActions.all) {
      final override = overrides[action.code];
      if (override != null) {
        map[action.code] = override;
      } else {
        map[action.code] = defaults.contains(action.code);
      }
    }
    return map;
  }

  static Future<Map<String, bool>> _loadOverrides({
    required int companyId,
    required int userId,
  }) async {
    final db = await AppDb.database;
    final rows = await db.query(
      DbTables.userPermissions,
      where: 'company_id = ? AND user_id = ?',
      whereArgs: [companyId, userId],
    );
    final map = <String, bool>{};
    for (final row in rows) {
      map[row['action_code'] as String] = (row['allowed'] as int? ?? 0) == 1;
    }
    return map;
  }

  static Set<String> defaultAllowedActionsForRole(String role) {
    final normalized = normalizeRole(role);
    if (normalized == roleAdmin) {
      return AppActions.all.map((a) => a.code).toSet();
    }
    if (normalized == roleSupervisor) {
      return <String>{
        AppActions.cancelSale.code,
        AppActions.deleteSaleItem.code,
        AppActions.modifyLinePrice.code,
        AppActions.applyDiscount.code,
        AppActions.processReturn.code,
        AppActions.adjustStock.code,
        AppActions.editCost.code,
        AppActions.editSalePrice.code,
        AppActions.deleteProduct.code,
        AppActions.importProducts.code,
        AppActions.openCash.code,
        AppActions.closeCash.code,
        AppActions.cashMovement.code,
        AppActions.configureScanner.code,
      };
    }
    // Cajero: solo lo básico de venta/caja.
    return <String>{
      AppActions.deleteSaleItem.code,
      AppActions.applyDiscount.code,
      AppActions.openCash.code,
      AppActions.closeCash.code,
      AppActions.configureScanner.code,
    };
  }

  static String normalizeRole(String role) {
    final lower = role.toLowerCase();
    if (lower == roleCajero) return roleCashier;
    return lower;
  }
}

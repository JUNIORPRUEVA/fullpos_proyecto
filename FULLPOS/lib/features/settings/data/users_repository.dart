import 'dart:convert';
import 'package:crypto/crypto.dart';
import '../../../core/db/app_db.dart';
import '../../../core/db/tables.dart';
import 'user_model.dart';

/// Repositorio para gestión de usuarios
class UsersRepository {
  UsersRepository._();

  /// Genera hash SHA256 de una contraseña
  static String hashPassword(String password) {
    final bytes = utf8.encode(password);
    final digest = sha256.convert(bytes);
    return digest.toString();
  }

  /// Obtener todos los usuarios activos
  static Future<List<UserModel>> getAll({int? companyId}) async {
    final db = await AppDb.database;
    final companyFilter = companyId ?? 1;
    final maps = await db.query(
      DbTables.users,
      where: 'deleted_at_ms IS NULL AND company_id = ?',
      whereArgs: [companyFilter],
      orderBy: 'role ASC, username ASC',
    );
    return maps.map((m) => UserModel.fromMap(m)).toList();
  }

  /// Obtener usuario por ID
  static Future<UserModel?> getById(int id, {int? companyId}) async {
    final db = await AppDb.database;
    final companyFilter = companyId ?? 1;
    final maps = await db.query(
      DbTables.users,
      where: 'id = ? AND deleted_at_ms IS NULL AND company_id = ?',
      whereArgs: [id, companyFilter],
    );
    if (maps.isEmpty) return null;
    return UserModel.fromMap(maps.first);
  }

  /// Obtener usuario por username
  static Future<UserModel?> getByUsername(
    String username, {
    int? companyId,
  }) async {
    final db = await AppDb.database;
    final companyFilter = companyId ?? 1;
    final maps = await db.query(
      DbTables.users,
      where: 'username = ? AND deleted_at_ms IS NULL AND company_id = ?',
      whereArgs: [username.toLowerCase(), companyFilter],
    );
    if (maps.isEmpty) return null;
    return UserModel.fromMap(maps.first);
  }

  /// Verificar credenciales (username + password)
  static Future<UserModel?> verifyCredentials(
    String username,
    String password, {
    int? companyId,
  }) async {
    final db = await AppDb.database;
    final passwordHash = hashPassword(password);
    final companyFilter = companyId ?? 1;

    final maps = await db.query(
      DbTables.users,
      where:
          'LOWER(username) = ? AND password_hash = ? AND is_active = 1 AND deleted_at_ms IS NULL AND company_id = ?',
      whereArgs: [username.toLowerCase(), passwordHash, companyFilter],
    );
    if (maps.isEmpty) return null;
    return UserModel.fromMap(maps.first);
  }

  /// Verificar PIN de usuario
  static Future<UserModel?> verifyPin(
    String username,
    String pin, {
    int? companyId,
  }) async {
    final db = await AppDb.database;
    final companyFilter = companyId ?? 1;
    final maps = await db.query(
      DbTables.users,
      where:
          'username = ? AND pin = ? AND is_active = 1 AND deleted_at_ms IS NULL AND company_id = ?',
      whereArgs: [username, pin, companyFilter],
    );
    if (maps.isEmpty) return null;
    return UserModel.fromMap(maps.first);
  }

  /// Crear nuevo usuario
  static Future<int> create(UserModel user) async {
    final db = await AppDb.database;
    return await db.insert(DbTables.users, user.toMap());
  }

  /// Actualizar usuario
  static Future<int> update(UserModel user) async {
    final db = await AppDb.database;
    final now = DateTime.now().millisecondsSinceEpoch;
    final data = user.toMap();
    data['updated_at_ms'] = now;
    
    return await db.update(
      DbTables.users,
      data,
      where: 'id = ?',
      whereArgs: [user.id],
    );
  }

  /// Eliminar usuario (soft delete)
  static Future<int> delete(int id) async {
    final db = await AppDb.database;
    final now = DateTime.now().millisecondsSinceEpoch;
    
    return await db.update(
      DbTables.users,
      {
        'deleted_at_ms': now,
        'is_active': 0,
        'updated_at_ms': now,
      },
      where: 'id = ?',
      whereArgs: [id],
    );
  }

  /// Activar/Desactivar usuario
  static Future<int> toggleActive(int id, bool active) async {
    final db = await AppDb.database;
    final now = DateTime.now().millisecondsSinceEpoch;
    
    return await db.update(
      DbTables.users,
      {
        'is_active': active ? 1 : 0,
        'updated_at_ms': now,
      },
      where: 'id = ?',
      whereArgs: [id],
    );
  }

  /// Cambiar contraseña de usuario
  static Future<int> changePassword(int id, String newPassword) async {
    final db = await AppDb.database;
    final now = DateTime.now().millisecondsSinceEpoch;
    final passwordHash = hashPassword(newPassword);
    
    return await db.update(
      DbTables.users,
      {
        'password_hash': passwordHash,
        'updated_at_ms': now,
      },
      where: 'id = ?',
      whereArgs: [id],
    );
  }

  /// Cambiar PIN de usuario
  static Future<int> changePin(int id, String? newPin) async {
    final db = await AppDb.database;
    final now = DateTime.now().millisecondsSinceEpoch;
    
    return await db.update(
      DbTables.users,
      {
        'pin': newPin,
        'updated_at_ms': now,
      },
      where: 'id = ?',
      whereArgs: [id],
    );
  }

  /// Cambiar rol de usuario
  static Future<int> changeRole(int id, String role) async {
    final db = await AppDb.database;
    final now = DateTime.now().millisecondsSinceEpoch;
    
    return await db.update(
      DbTables.users,
      {
        'role': role,
        'updated_at_ms': now,
      },
      where: 'id = ?',
      whereArgs: [id],
    );
  }

  /// Guardar permisos personalizados
  static Future<int> savePermissions(int id, UserPermissions permissions) async {
    final db = await AppDb.database;
    final now = DateTime.now().millisecondsSinceEpoch;
    
    return await db.update(
      DbTables.users,
      {
        'permissions': jsonEncode(permissions.toMap()),
        'updated_at_ms': now,
      },
      where: 'id = ?',
      whereArgs: [id],
    );
  }

  /// Obtener permisos de usuario
  static Future<UserPermissions> getPermissions(int userId) async {
    final user = await getById(userId);
    if (user == null) return UserPermissions.cashier();
    
    // Admin tiene todos los permisos
    if (user.isAdmin) return UserPermissions.admin();
    
    // Si tiene permisos personalizados
    if (user.permissions != null && user.permissions!.isNotEmpty) {
      try {
        final map = jsonDecode(user.permissions!) as Map<String, dynamic>;
        return UserPermissions.fromMap(map);
      } catch (_) {
        return UserPermissions.cashier();
      }
    }
    
    // Permisos por defecto según rol
    return UserPermissions.cashier();
  }

  /// Verificar si existe username
  static Future<bool> usernameExists(String username, {int? excludeId}) async {
    final db = await AppDb.database;
    final where = excludeId != null 
        ? 'username = ? AND id != ? AND deleted_at_ms IS NULL'
        : 'username = ? AND deleted_at_ms IS NULL';
    final whereArgs = excludeId != null ? [username, excludeId] : [username];
    
    final maps = await db.query(
      DbTables.users,
      where: where,
      whereArgs: whereArgs,
    );
    return maps.isNotEmpty;
  }

  /// Contar usuarios por rol
  static Future<Map<String, int>> countByRole() async {
    final db = await AppDb.database;
    final result = await db.rawQuery('''
      SELECT role, COUNT(*) as count 
      FROM ${DbTables.users} 
      WHERE deleted_at_ms IS NULL AND is_active = 1
      GROUP BY role
    ''');
    
    final counts = <String, int>{'admin': 0, 'cashier': 0};
    for (final row in result) {
      final role = row['role'] as String;
      counts[role] = row['count'] as int;
    }
    return counts;
  }

  /// Obtener usuarios activos para selector
  static Future<List<UserModel>> getActiveUsers() async {
    final db = await AppDb.database;
    final maps = await db.query(
      DbTables.users,
      where: 'is_active = 1 AND deleted_at_ms IS NULL',
      orderBy: 'display_name ASC, username ASC',
    );
    return maps.map((m) => UserModel.fromMap(m)).toList();
  }
}

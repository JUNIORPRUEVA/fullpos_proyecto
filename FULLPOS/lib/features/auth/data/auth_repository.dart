import 'dart:convert';
import '../../settings/data/user_model.dart';
import '../../settings/data/users_repository.dart';
import '../../../core/session/session_manager.dart';

/// Repositorio de autenticación
class AuthRepository {
  AuthRepository._();

  /// Valida las credenciales del usuario y retorna el usuario si es válido
  static Future<UserModel?> login(String username, String password) async {
    final user = await UsersRepository.verifyCredentials(username, password);

    if (user != null) {
      // Guardar sesión
      await SessionManager.login(
        userId: user.id!,
        username: user.username,
        displayName: user.displayLabel,
        role: user.role,
        permissions: user.permissions,
        companyId: user.companyId,
      );
    }

    return user;
  }

  /// Cierra la sesión del usuario
  static Future<void> logout() async {
    await SessionManager.logout();
  }

  /// Verifica si hay un usuario logueado
  static Future<bool> isLoggedIn() async {
    return await SessionManager.isLoggedIn();
  }

  /// Obtiene el usuario actual logueado
  static Future<UserModel?> getCurrentUser() async {
    final userId = await SessionManager.userId();
    if (userId == null) return null;
    final companyId = await SessionManager.companyId();
    return await UsersRepository.getById(userId, companyId: companyId);
  }

  /// Obtiene los permisos del usuario actual
  static Future<UserPermissions> getCurrentPermissions() async {
    // Fast path: usar cache de sesión (SharedPreferences) para evitar I/O de DB.
    // Esto reduce mucho el tiempo de arranque y evita parpadeos al navegar.
    if (await SessionManager.isAdmin()) return UserPermissions.admin();

    final cached = await SessionManager.permissions();
    if (cached != null && cached.isNotEmpty) {
      try {
        final map = jsonDecode(cached) as Map<String, dynamic>;
        return UserPermissions.fromMap(map);
      } catch (_) {
        // Si el JSON está corrupto o viejo, caer al camino de DB.
      }
    }

    final userId = await SessionManager.userId();
    if (userId == null) return UserPermissions.none();

    final companyId = await SessionManager.companyId();
    final user = await UsersRepository.getById(userId, companyId: companyId);
    if (user == null) return UserPermissions.none();

    // Admin tiene todos los permisos
    if (user.isAdmin) return UserPermissions.admin();

    final permissionsJson = user.permissions;

    // Si tiene permisos personalizados
    if (permissionsJson != null && permissionsJson.isNotEmpty) {
      try {
        final map = jsonDecode(permissionsJson) as Map<String, dynamic>;
        return UserPermissions.fromMap(map);
      } catch (_) {
        return UserPermissions.cashier();
      }
    }

    // Permisos por defecto según rol
    return UserPermissions.cashier();
  }

  /// Verifica si el usuario tiene un permiso específico
  static Future<bool> hasPermission(String permission) async {
    final permissions = await getCurrentPermissions();

    switch (permission) {
      case 'can_sell':
        return permissions.canSell;
      case 'can_void_sale':
        return permissions.canVoidSale;
      case 'can_apply_discount':
        return permissions.canApplyDiscount;
      case 'can_view_sales_history':
        return permissions.canViewSalesHistory;
      case 'can_view_products':
        return permissions.canViewProducts;
      case 'can_edit_products':
        return permissions.canEditProducts;
      case 'can_delete_products':
        return permissions.canDeleteProducts;
      case 'can_adjust_stock':
        return permissions.canAdjustStock;
      case 'can_view_purchase_price':
        return permissions.canViewPurchasePrice;
      case 'can_view_profit':
        return permissions.canViewProfit;
      case 'can_view_clients':
        return permissions.canViewClients;
      case 'can_edit_clients':
        return permissions.canEditClients;
      case 'can_delete_clients':
        return permissions.canDeleteClients;
      case 'can_open_cash':
        return permissions.canOpenCash;
      case 'can_close_cash':
        return permissions.canCloseCash;
      case 'can_view_cash_history':
        return permissions.canViewCashHistory;
      case 'can_make_cash_movements':
        return permissions.canMakeCashMovements;
      case 'can_view_reports':
        return permissions.canViewReports;
      case 'can_export_reports':
        return permissions.canExportReports;
      case 'can_create_quotes':
        return permissions.canCreateQuotes;
      case 'can_view_quotes':
        return permissions.canViewQuotes;
      case 'can_view_loans':
        return permissions.canViewLoans;
      case 'can_create_loans':
        return permissions.canCreateLoans;
      case 'can_edit_loans':
        return permissions.canEditLoans;
      case 'can_access_tools':
        return permissions.canAccessTools;
      case 'can_process_returns':
        return permissions.canProcessReturns;
      case 'can_view_credits':
        return permissions.canViewCredits;
      case 'can_manage_credits':
        return permissions.canManageCredits;
      case 'can_manage_users':
        return permissions.canManageUsers;
      case 'can_access_settings':
        return permissions.canAccessSettings;
      default:
        return false;
    }
  }

  /// Verifica si el usuario actual es admin
  static Future<bool> isAdmin() async {
    // Fast path: el rol está cacheado en sesión.
    return SessionManager.isAdmin();
  }
}

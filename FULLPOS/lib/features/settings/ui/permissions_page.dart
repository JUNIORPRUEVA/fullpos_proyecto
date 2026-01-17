import 'dart:convert';
import 'dart:convert';

import 'package:flutter/material.dart';
import '../../../core/constants/app_colors.dart';
import '../../../core/errors/error_handler.dart';
import '../../../core/security/app_actions.dart';
import '../../../core/security/security_config.dart';
import '../../../core/session/session_manager.dart';
import '../data/user_model.dart';
import '../data/users_repository.dart';

/// Página de gestión de permisos de usuario
class PermissionsPage extends StatefulWidget {
  final UserModel user;
  
  const PermissionsPage({super.key, required this.user});

  @override
  State<PermissionsPage> createState() => _PermissionsPageState();
}

class _PermissionsPageState extends State<PermissionsPage> {
  late UserPermissions _permissions;
  bool _isLoading = false;
  bool _hasChanges = false;
  SecurityConfig? _securityConfig;
  bool _securityLoading = true;
  String _terminalId = '';
  int _companyId = 1;

  @override
  void initState() {
    super.initState();
    _loadPermissions();
    _loadSecurityConfig();
  }

  void _loadPermissions() {
    if (widget.user.isAdmin) {
      _permissions = UserPermissions.admin();
    } else if (widget.user.permissions != null && widget.user.permissions!.isNotEmpty) {
      try {
        final map = jsonDecode(widget.user.permissions!) as Map<String, dynamic>;
        _permissions = UserPermissions.fromMap(map);
      } catch (_) {
        _permissions = UserPermissions.cashier();
      }
    } else {
      _permissions = UserPermissions.cashier();
    }
  }

  Future<void> _loadSecurityConfig() async {
    final companyId = await SessionManager.companyId() ?? 1;
    final terminalId =
        await SessionManager.terminalId() ?? await SessionManager.ensureTerminalId();
    final config = await SecurityConfigRepository.load(
      companyId: companyId,
      terminalId: terminalId,
    );

    if (!mounted) return;
    setState(() {
      _securityConfig = config;
      _terminalId = terminalId;
      _companyId = companyId;
      _securityLoading = false;
    });
  }

  Future<void> _savePermissions() async {
    setState(() => _isLoading = true);
    
    try {
      await UsersRepository.savePermissions(widget.user.id!, _permissions);
      
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Permisos guardados correctamente'),
            backgroundColor: AppColors.success,
          ),
        );
        setState(() {
          _hasChanges = false;
        });
      }
    } catch (e, st) {
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: _savePermissions,
          module: 'settings/permissions/save',
        );
      }
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  void _updatePermission(UserPermissions Function(UserPermissions) updater) {
    setState(() {
      _permissions = updater(_permissions);
      _hasChanges = true;
    });
  }

  void _selectAll(bool value) {
    setState(() {
      _permissions = value ? UserPermissions.admin() : UserPermissions.none();
      _hasChanges = true;
    });
  }

  @override
  Widget build(BuildContext context) {
    final isAdmin = widget.user.isAdmin;
    
    return Scaffold(
      backgroundColor: Colors.grey.shade100,
      body: Column(
        children: [
          // Header
          _buildHeader(),
          
          // Content
          Expanded(
            child: isAdmin
                ? _buildAdminMessage()
                : SingleChildScrollView(
                    padding: const EdgeInsets.all(16),
                    child: Column(
                      children: [
                        // Quick actions
                        _buildQuickActions(),
                        const SizedBox(height: 16),
                        
                        // Permission sections
                        _buildPermissionSection(
                          'Ventas',
                          Icons.point_of_sale,
                          AppColors.teal700,
                          [
                            _PermissionItem(
                              'Realizar ventas',
                              'Puede crear nuevas ventas',
                              _permissions.canSell,
                              (v) => _updatePermission((p) => p.copyWith(canSell: v)),
                            ),
                            _PermissionItem(
                              'Anular ventas',
                              'Puede cancelar o anular ventas completadas',
                              _permissions.canVoidSale,
                              (v) => _updatePermission((p) => p.copyWith(canVoidSale: v)),
                            ),
                            _PermissionItem(
                              'Aplicar descuentos',
                              'Puede aplicar descuentos en ventas',
                              _permissions.canApplyDiscount,
                              (v) => _updatePermission((p) => p.copyWith(canApplyDiscount: v)),
                            ),
                            _PermissionItem(
                              'Ver historial de ventas',
                              'Puede consultar el historial completo de ventas',
                              _permissions.canViewSalesHistory,
                              (v) => _updatePermission((p) => p.copyWith(canViewSalesHistory: v)),
                            ),
                          ],
                        ),
                        
                        const SizedBox(height: 16),
                        
                        _buildPermissionSection(
                          'Productos',
                          Icons.inventory_2,
                          Colors.blue,
                          [
                            _PermissionItem(
                              'Ver productos',
                              'Puede ver el catálogo de productos',
                              _permissions.canViewProducts,
                              (v) => _updatePermission((p) => p.copyWith(canViewProducts: v)),
                            ),
                            _PermissionItem(
                              'Ver costo de compra',
                              'Puede ver el precio de compra (costo) de los productos',
                              _permissions.canViewPurchasePrice,
                              (v) => _updatePermission(
                                (p) => p.copyWith(canViewPurchasePrice: v),
                              ),
                            ),
                            _PermissionItem(
                              'Ver ganancia/margen',
                              'Puede ver ganancia, margen y métricas relacionadas',
                              _permissions.canViewProfit,
                              (v) => _updatePermission(
                                (p) => p.copyWith(canViewProfit: v),
                              ),
                            ),
                            _PermissionItem(
                              'Editar productos',
                              'Puede modificar información de productos',
                              _permissions.canEditProducts,
                              (v) => _updatePermission((p) => p.copyWith(canEditProducts: v)),
                            ),
                            _PermissionItem(
                              'Eliminar productos',
                              'Puede eliminar productos del sistema',
                              _permissions.canDeleteProducts,
                              (v) => _updatePermission((p) => p.copyWith(canDeleteProducts: v)),
                            ),
                            _PermissionItem(
                              'Ajustar inventario',
                              'Puede realizar ajustes de stock',
                              _permissions.canAdjustStock,
                              (v) => _updatePermission((p) => p.copyWith(canAdjustStock: v)),
                            ),
                          ],
                        ),
                        
                        const SizedBox(height: 16),
                        
                        _buildPermissionSection(
                          'Clientes',
                          Icons.people,
                          Colors.purple,
                          [
                            _PermissionItem(
                              'Ver clientes',
                              'Puede ver la lista de clientes',
                              _permissions.canViewClients,
                              (v) => _updatePermission((p) => p.copyWith(canViewClients: v)),
                            ),
                            _PermissionItem(
                              'Editar clientes',
                              'Puede modificar información de clientes',
                              _permissions.canEditClients,
                              (v) => _updatePermission((p) => p.copyWith(canEditClients: v)),
                            ),
                            _PermissionItem(
                              'Eliminar clientes',
                              'Puede eliminar clientes del sistema',
                              _permissions.canDeleteClients,
                              (v) => _updatePermission((p) => p.copyWith(canDeleteClients: v)),
                            ),
                          ],
                        ),
                        
                        const SizedBox(height: 16),
                        
                        _buildPermissionSection(
                          'Caja',
                          Icons.account_balance_wallet,
                          Colors.green,
                          [
                            _PermissionItem(
                              'Abrir caja',
                              'Puede iniciar una sesión de caja',
                              _permissions.canOpenCash,
                              (v) => _updatePermission((p) => p.copyWith(canOpenCash: v)),
                            ),
                            _PermissionItem(
                              'Cerrar caja',
                              'Puede realizar el cierre de caja',
                              _permissions.canCloseCash,
                              (v) => _updatePermission((p) => p.copyWith(canCloseCash: v)),
                            ),
                            _PermissionItem(
                              'Ver historial de caja',
                              'Puede consultar sesiones anteriores',
                              _permissions.canViewCashHistory,
                              (v) => _updatePermission((p) => p.copyWith(canViewCashHistory: v)),
                            ),
                            _PermissionItem(
                              'Movimientos de caja',
                              'Puede registrar entradas y salidas',
                              _permissions.canMakeCashMovements,
                              (v) => _updatePermission((p) => p.copyWith(canMakeCashMovements: v)),
                            ),
                          ],
                        ),
                        
                        const SizedBox(height: 16),
                        
                        _buildPermissionSection(
                          'Reportes',
                          Icons.bar_chart,
                          Colors.orange,
                          [
                            _PermissionItem(
                              'Ver reportes',
                              'Puede acceder a los reportes del sistema',
                              _permissions.canViewReports,
                              (v) => _updatePermission((p) => p.copyWith(canViewReports: v)),
                            ),
                            _PermissionItem(
                              'Exportar reportes',
                              'Puede exportar reportes a Excel/PDF',
                              _permissions.canExportReports,
                              (v) => _updatePermission((p) => p.copyWith(canExportReports: v)),
                            ),
                          ],
                        ),
                        
                        const SizedBox(height: 16),
                        
                        _buildPermissionSection(
                          'Cotizaciones',
                          Icons.request_quote,
                          Colors.cyan,
                          [
                            _PermissionItem(
                              'Crear cotizaciones',
                              'Puede generar nuevas cotizaciones',
                              _permissions.canCreateQuotes,
                              (v) => _updatePermission((p) => p.copyWith(canCreateQuotes: v)),
                            ),
                            _PermissionItem(
                              'Ver cotizaciones',
                              'Puede consultar cotizaciones existentes',
                              _permissions.canViewQuotes,
                              (v) => _updatePermission((p) => p.copyWith(canViewQuotes: v)),
                            ),
                          ],
                        ),
                        
                        const SizedBox(height: 16),
                        
                        _buildPermissionSection(
                          'Préstamos/Empeños',
                          Icons.handshake,
                          Colors.amber.shade700,
                          [
                            _PermissionItem(
                              'Ver préstamos',
                              'Puede ver la lista de préstamos y empeños',
                              _permissions.canViewLoans,
                              (v) => _updatePermission((p) => p.copyWith(canViewLoans: v)),
                            ),
                            _PermissionItem(
                              'Crear préstamos',
                              'Puede registrar nuevos préstamos',
                              _permissions.canCreateLoans,
                              (v) => _updatePermission((p) => p.copyWith(canCreateLoans: v)),
                            ),
                            _PermissionItem(
                              'Editar préstamos',
                              'Puede modificar préstamos existentes',
                              _permissions.canEditLoans,
                              (v) => _updatePermission((p) => p.copyWith(canEditLoans: v)),
                            ),
                          ],
                        ),
                        
                        const SizedBox(height: 16),
                        
                        _buildPermissionSection(
                          'Devoluciones',
                          Icons.assignment_return,
                          Colors.red.shade400,
                          [
                            _PermissionItem(
                              'Procesar devoluciones',
                              'Puede registrar y procesar devoluciones',
                              _permissions.canProcessReturns,
                              (v) => _updatePermission((p) => p.copyWith(canProcessReturns: v)),
                            ),
                          ],
                        ),
                        
                        const SizedBox(height: 16),
                        
                        _buildPermissionSection(
                          'Créditos',
                          Icons.credit_card,
                          Colors.indigo,
                          [
                            _PermissionItem(
                              'Ver créditos',
                              'Puede ver ventas a crédito pendientes',
                              _permissions.canViewCredits,
                              (v) => _updatePermission((p) => p.copyWith(canViewCredits: v)),
                            ),
                            _PermissionItem(
                              'Gestionar créditos',
                              'Puede registrar abonos y modificar créditos',
                              _permissions.canManageCredits,
                              (v) => _updatePermission((p) => p.copyWith(canManageCredits: v)),
                            ),
                          ],
                        ),
                        
                        const SizedBox(height: 16),
                        
                        _buildPermissionSection(
                          'Sistema',
                          Icons.settings,
                          Colors.grey.shade700,
                          [
                            _PermissionItem(
                              'Acceso a herramientas',
                              'Puede acceder al módulo de herramientas',
                              _permissions.canAccessTools,
                              (v) => _updatePermission((p) => p.copyWith(canAccessTools: v)),
                            ),
                            _PermissionItem(
                              'Gestionar usuarios',
                              'Puede crear, editar y eliminar usuarios',
                              _permissions.canManageUsers,
                              (v) => _updatePermission((p) => p.copyWith(canManageUsers: v)),
                            ),
                            _PermissionItem(
                              'Acceso a configuración',
                              'Puede acceder al módulo de configuración',
                              _permissions.canAccessSettings,
                              (v) => _updatePermission((p) => p.copyWith(canAccessSettings: v)),
                            ),
                          ],
                        ),
                        const SizedBox(height: 16),

                        _buildSecurityOverridesCard(),

                        const SizedBox(height: 80),
                      ],
                    ),
                  ),
          ),
        ],
      ),
      
      // FAB para guardar
      floatingActionButton: !isAdmin && _hasChanges
          ? FloatingActionButton.extended(
              onPressed: _isLoading ? null : _savePermissions,
              backgroundColor: AppColors.teal700,
              icon: _isLoading
                  ? const SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                        color: Colors.white,
                      ),
                    )
                  : const Icon(Icons.save, color: Colors.white),
              label: Text(
                _isLoading ? 'Guardando...' : 'Guardar Cambios',
                style: const TextStyle(color: Colors.white),
              ),
            )
          : null,
    );
  }

  Widget _buildHeader() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.white,
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.05),
            blurRadius: 4,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: Row(
        children: [
          IconButton(
            onPressed: () => Navigator.pop(context),
            icon: const Icon(Icons.arrow_back),
            tooltip: 'Volver',
          ),
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: AppColors.teal700.withOpacity(0.1),
              borderRadius: BorderRadius.circular(10),
            ),
            child: const Icon(Icons.security, color: AppColors.teal700, size: 24),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'PERMISOS DE USUARIO',
                  style: TextStyle(
                    fontSize: 18,
                    fontWeight: FontWeight.bold,
                    letterSpacing: 0.5,
                  ),
                ),
                Text(
                  widget.user.displayLabel,
                  style: TextStyle(color: Colors.grey.shade600, fontSize: 13),
                ),
              ],
            ),
          ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            decoration: BoxDecoration(
              color: widget.user.isAdmin 
                  ? Colors.purple.withOpacity(0.1) 
                  : AppColors.teal700.withOpacity(0.1),
              borderRadius: BorderRadius.circular(20),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  widget.user.isAdmin 
                      ? Icons.admin_panel_settings 
                      : Icons.person,
                  size: 16,
                  color: widget.user.isAdmin ? Colors.purple : AppColors.teal700,
                ),
                const SizedBox(width: 6),
                Text(
                  widget.user.roleLabel,
                  style: TextStyle(
                    color: widget.user.isAdmin ? Colors.purple : AppColors.teal700,
                    fontWeight: FontWeight.w600,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildAdminMessage() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              padding: const EdgeInsets.all(24),
              decoration: BoxDecoration(
                color: Colors.purple.withOpacity(0.1),
                shape: BoxShape.circle,
              ),
              child: const Icon(
                Icons.admin_panel_settings,
                size: 64,
                color: Colors.purple,
              ),
            ),
            const SizedBox(height: 24),
            const Text(
              'Usuario Administrador',
              style: TextStyle(
                fontSize: 22,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 12),
            Text(
              'Los administradores tienen acceso completo a todas las funciones del sistema.\nNo es posible restringir sus permisos.',
              textAlign: TextAlign.center,
              style: TextStyle(
                color: Colors.grey.shade600,
                fontSize: 14,
                height: 1.5,
              ),
            ),
            const SizedBox(height: 32),
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.green.withOpacity(0.1),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: Colors.green.withOpacity(0.3)),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Icon(Icons.check_circle, color: Colors.green),
                  const SizedBox(width: 12),
                  const Text(
                    'Todos los permisos habilitados',
                    style: TextStyle(
                      color: Colors.green,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildQuickActions() {
    return Card(
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            Expanded(
              child: OutlinedButton.icon(
                onPressed: () => _selectAll(true),
                icon: const Icon(Icons.check_box),
                label: const Text('Seleccionar Todo'),
                style: OutlinedButton.styleFrom(
                  foregroundColor: AppColors.teal700,
                  side: BorderSide(color: AppColors.teal700),
                  padding: const EdgeInsets.symmetric(vertical: 12),
                ),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: OutlinedButton.icon(
                onPressed: () => _selectAll(false),
                icon: const Icon(Icons.check_box_outline_blank),
                label: const Text('Deseleccionar Todo'),
                style: OutlinedButton.styleFrom(
                  foregroundColor: Colors.grey.shade700,
                  side: BorderSide(color: Colors.grey.shade400),
                  padding: const EdgeInsets.symmetric(vertical: 12),
                ),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: OutlinedButton.icon(
                onPressed: () {
                  setState(() {
                    _permissions = UserPermissions.cashier();
                    _hasChanges = true;
                  });
                },
                icon: const Icon(Icons.restore),
                label: const Text('Por Defecto'),
                style: OutlinedButton.styleFrom(
                  foregroundColor: Colors.blue,
                  side: const BorderSide(color: Colors.blue),
                  padding: const EdgeInsets.symmetric(vertical: 12),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSecurityOverridesCard() {
    if (_securityLoading) {
      return const Card(
        child: Padding(
          padding: EdgeInsets.all(16),
          child: Row(
            children: [
              SizedBox(
                width: 18,
                height: 18,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
              SizedBox(width: 12),
              Text('Cargando configuraci\u00f3n de seguridad...'),
            ],
          ),
        ),
      );
    }

    final config = _securityConfig;
    if (config == null) return const SizedBox.shrink();

    return Card(
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Seguridad (Overrides globales)',
              style: TextStyle(fontWeight: FontWeight.w700, fontSize: 16),
            ),
            const SizedBox(height: 4),
            Text(
              'Activa qu\u00e9 acciones requieren token/override para todos los usuarios. Terminal: $_terminalId',
              style: TextStyle(color: Colors.grey.shade700, fontSize: 12),
            ),
            const SizedBox(height: 12),
            ...AppActionCategory.values.map(
              (cat) => _buildOverrideCategory(cat, config),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildOverrideCategory(AppActionCategory category, SecurityConfig config) {
    final actions = AppActions.byCategory(category);
    if (actions.isEmpty) return const SizedBox.shrink();

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Divider(),
        Text(
          category.name.toUpperCase(),
          style: const TextStyle(fontWeight: FontWeight.w600),
        ),
        const SizedBox(height: 8),
        ...actions.map((a) {
          final current = config.overrideByAction[a.code] ?? a.requiresOverrideByDefault;
          return SwitchListTile(
            contentPadding: EdgeInsets.zero,
            title: Text(a.name),
            subtitle: Text('${a.description} \u2022 Riesgo: ${a.risk.name}'),
            value: current,
            onChanged: (v) async {
              final updated = Map<String, bool>.from(config.overrideByAction)
                ..[a.code] = v;
              final next = config.copyWith(overrideByAction: updated);
              setState(() {
                _securityConfig = next;
              });
              await SecurityConfigRepository.save(
                config: next,
                companyId: _companyId,
                terminalId: _terminalId,
              );
            },
          );
        }),
      ],
    );
  }

  Widget _buildPermissionSection(
    String title,
    IconData icon,
    Color color,
    List<_PermissionItem> items,
  ) {
    return Card(
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: color.withOpacity(0.05),
              borderRadius: const BorderRadius.only(
                topLeft: Radius.circular(12),
                topRight: Radius.circular(12),
              ),
            ),
            child: Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: color.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Icon(icon, color: color, size: 20),
                ),
                const SizedBox(width: 12),
                Text(
                  title,
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: color,
                  ),
                ),
                const Spacer(),
                Text(
                  '${items.where((i) => i.value).length}/${items.length}',
                  style: TextStyle(
                    color: color,
                    fontWeight: FontWeight.w600,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
          ...items.map((item) => _buildPermissionTile(item, color)),
        ],
      ),
    );
  }

  Widget _buildPermissionTile(_PermissionItem item, Color color) {
    return SwitchListTile(
      title: Text(
        item.title,
        style: TextStyle(
          fontWeight: FontWeight.w500,
          color: item.value ? Colors.black87 : Colors.grey.shade600,
        ),
      ),
      subtitle: Text(
        item.description,
        style: TextStyle(
          fontSize: 12,
          color: Colors.grey.shade500,
        ),
      ),
      value: item.value,
      onChanged: item.onChanged,
      activeColor: color,
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
    );
  }
}

class _PermissionItem {
  final String title;
  final String description;
  final bool value;
  final ValueChanged<bool> onChanged;

  _PermissionItem(this.title, this.description, this.value, this.onChanged);
}

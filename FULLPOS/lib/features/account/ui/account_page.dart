import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../../core/constants/app_colors.dart';
import '../../../core/constants/app_sizes.dart';
import '../../../core/session/ui_preferences.dart';
import '../../../core/session/session_manager.dart';
import '../../auth/data/auth_repository.dart';
import '../../settings/data/user_model.dart';
import '../../settings/data/users_repository.dart';

/// Página de cuenta de usuario
class AccountPage extends StatefulWidget {
  const AccountPage({super.key});

  @override
  State<AccountPage> createState() => _AccountPageState();
}

class _AccountPageState extends State<AccountPage> {
  bool _loading = true;
  UserModel? _user;
  String? _sessionUsername;
  String? _sessionDisplayName;
  String? _sessionRole;

  @override
  void initState() {
    super.initState();
    _loadData();
  }

  Future<void> _loadData() async {
    setState(() => _loading = true);
    final username = await SessionManager.username();
    final displayName = await SessionManager.displayName();
    final role = await SessionManager.role();

    final user = await AuthRepository.getCurrentUser();

    if (!mounted) return;
    setState(() {
      _sessionUsername = username;
      _sessionDisplayName = displayName;
      _sessionRole = role;
      _user = user;
      _loading = false;
    });
  }

  Future<void> _openEditProfile() async {
    final user = _user;
    if (user == null) return;

    final displayNameCtrl = TextEditingController(text: user.displayName ?? '');
    final formKey = GlobalKey<FormState>();

    final result = await showDialog<bool>(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text('Editar Perfil'),
          content: SizedBox(
            width: 520,
            child: Form(
              key: formKey,
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  TextFormField(
                    initialValue: user.username,
                    enabled: false,
                    decoration: const InputDecoration(
                      labelText: 'Usuario',
                      prefixIcon: Icon(Icons.person),
                    ),
                  ),
                  const SizedBox(height: AppSizes.paddingM),
                  TextFormField(
                    controller: displayNameCtrl,
                    decoration: const InputDecoration(
                      labelText: 'Nombre para mostrar',
                      hintText: 'Ej: Juan Pérez',
                      prefixIcon: Icon(Icons.badge),
                    ),
                    validator: (v) {
                      final value = (v ?? '').trim();
                      if (value.isNotEmpty && value.length < 2) {
                        return 'El nombre debe tener al menos 2 caracteres';
                      }
                      return null;
                    },
                  ),
                  const SizedBox(height: AppSizes.paddingM),
                  Row(
                    children: [
                      Expanded(
                        child: _InfoPill(label: 'Rol', value: user.roleLabel),
                      ),
                      const SizedBox(width: AppSizes.paddingM),
                      Expanded(
                        child: _InfoPill(
                          label: 'Estado',
                          value: user.isActiveUser ? 'Activo' : 'Inactivo',
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancelar'),
            ),
            ElevatedButton(
              onPressed: () {
                if (formKey.currentState?.validate() != true) return;
                Navigator.pop(context, true);
              },
              child: const Text('Guardar'),
            ),
          ],
        );
      },
    );

    if (result != true) return;

    final newDisplayName = displayNameCtrl.text.trim();
    final updated = user.copyWith(
      displayName: newDisplayName.isEmpty ? null : newDisplayName,
    );

    try {
      await UsersRepository.update(updated);
      await SessionManager.setDisplayName(updated.displayLabel);
      if (!mounted) return;
      setState(() {
        _user = updated;
        _sessionDisplayName = updated.displayLabel;
      });
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('✅ Perfil actualizado'),
          backgroundColor: AppColors.success,
        ),
      );
    } catch (_) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('❌ No se pudo actualizar el perfil'),
          backgroundColor: AppColors.error,
        ),
      );
    }
  }

  Future<void> _openChangePassword() async {
    final user = _user;
    if (user == null || user.id == null) return;

    final formKey = GlobalKey<FormState>();
    final currentCtrl = TextEditingController();
    final newCtrl = TextEditingController();
    final confirmCtrl = TextEditingController();

    bool showCurrent = false;
    bool showNew = false;
    bool showConfirm = false;

    final result = await showDialog<bool>(
      context: context,
      builder: (context) {
        return StatefulBuilder(
          builder: (context, setLocal) {
            return AlertDialog(
              title: const Text('Cambiar Contraseña'),
              content: SizedBox(
                width: 520,
                child: Form(
                  key: formKey,
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      if (user.hasPassword) ...[
                        TextFormField(
                          controller: currentCtrl,
                          obscureText: !showCurrent,
                          decoration: InputDecoration(
                            labelText: 'Contraseña actual',
                            prefixIcon: const Icon(Icons.lock_outline),
                            suffixIcon: IconButton(
                              onPressed: () =>
                                  setLocal(() => showCurrent = !showCurrent),
                              icon: Icon(
                                showCurrent
                                    ? Icons.visibility_off
                                    : Icons.visibility,
                              ),
                            ),
                          ),
                          validator: (v) {
                            if (!user.hasPassword) return null;
                            if ((v ?? '').isEmpty)
                              return 'Ingrese la contraseña actual';
                            return null;
                          },
                        ),
                        const SizedBox(height: AppSizes.paddingM),
                      ],
                      TextFormField(
                        controller: newCtrl,
                        obscureText: !showNew,
                        decoration: InputDecoration(
                          labelText: user.hasPassword
                              ? 'Nueva contraseña'
                              : 'Establecer contraseña',
                          prefixIcon: const Icon(Icons.lock),
                          suffixIcon: IconButton(
                            onPressed: () => setLocal(() => showNew = !showNew),
                            icon: Icon(
                              showNew ? Icons.visibility_off : Icons.visibility,
                            ),
                          ),
                        ),
                        validator: (v) {
                          final value = (v ?? '');
                          if (value.isEmpty)
                            return 'Ingrese la nueva contraseña';
                          if (value.length < 4)
                            return 'Debe tener al menos 4 caracteres';
                          return null;
                        },
                      ),
                      const SizedBox(height: AppSizes.paddingM),
                      TextFormField(
                        controller: confirmCtrl,
                        obscureText: !showConfirm,
                        decoration: InputDecoration(
                          labelText: 'Confirmar contraseña',
                          prefixIcon: const Icon(Icons.lock_reset),
                          suffixIcon: IconButton(
                            onPressed: () =>
                                setLocal(() => showConfirm = !showConfirm),
                            icon: Icon(
                              showConfirm
                                  ? Icons.visibility_off
                                  : Icons.visibility,
                            ),
                          ),
                        ),
                        validator: (v) {
                          if ((v ?? '').isEmpty)
                            return 'Confirme la contraseña';
                          if (v != newCtrl.text)
                            return 'Las contraseñas no coinciden';
                          return null;
                        },
                      ),
                    ],
                  ),
                ),
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context, false),
                  child: const Text('Cancelar'),
                ),
                ElevatedButton(
                  onPressed: () {
                    if (formKey.currentState?.validate() != true) return;
                    Navigator.pop(context, true);
                  },
                  child: const Text('Guardar'),
                ),
              ],
            );
          },
        );
      },
    );

    if (result != true) return;

    try {
      if (user.hasPassword) {
        final ok = await UsersRepository.verifyCredentials(
          user.username,
          currentCtrl.text,
        );
        if (ok == null) {
          if (!mounted) return;
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('❌ Contraseña actual incorrecta'),
              backgroundColor: AppColors.error,
            ),
          );
          return;
        }
      }

      await UsersRepository.changePassword(user.id!, newCtrl.text);
      if (!mounted) return;
      // Refrescar usuario (para que user.hasPassword quede true)
      await _loadData();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('✅ Contraseña actualizada'),
          backgroundColor: AppColors.success,
        ),
      );
    } catch (_) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('❌ No se pudo cambiar la contraseña'),
          backgroundColor: AppColors.error,
        ),
      );
    }
  }

  Future<void> _openPreferences() async {
    final current = await UiPreferences.isSidebarCollapsed();
    if (!mounted) return;

    bool collapsed = current;
    await showDialog<void>(
      context: context,
      builder: (context) {
        return StatefulBuilder(
          builder: (context, setLocal) {
            return AlertDialog(
              title: const Text('Preferencias'),
              content: SizedBox(
                width: 520,
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    SwitchListTile(
                      value: collapsed,
                      onChanged: (v) async {
                        setLocal(() => collapsed = v);
                        await UiPreferences.setSidebarCollapsed(v);
                      },
                      title: const Text('Menú lateral colapsado'),
                      subtitle: const Text(
                        'Mantener el menú compacto por defecto.',
                      ),
                    ),
                  ],
                ),
              ),
              actions: [
                ElevatedButton(
                  onPressed: () => Navigator.pop(context),
                  child: const Text('Cerrar'),
                ),
              ],
            );
          },
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }

    final user = _user;
    final titleName = (_sessionDisplayName?.isNotEmpty == true)
        ? _sessionDisplayName!
        : (_sessionUsername ?? 'Usuario');

    return Scaffold(
      backgroundColor: AppColors.bgLight,
      appBar: AppBar(title: const Text('Mi Cuenta')),
      body: Center(
        child: Container(
          constraints: const BoxConstraints(maxWidth: 600),
          padding: const EdgeInsets.all(AppSizes.paddingXL),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              // Avatar
              Container(
                width: 120,
                height: 120,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  gradient: LinearGradient(
                    colors: [AppColors.teal600, AppColors.teal800],
                  ),
                  border: Border.all(color: AppColors.gold, width: 4),
                ),
                child: const Icon(
                  Icons.person,
                  size: 60,
                  color: AppColors.textLight,
                ),
              ),

              const SizedBox(height: AppSizes.paddingL),

              // Nombre de usuario
              Text(
                titleName,
                style: const TextStyle(
                  fontSize: 28,
                  fontWeight: FontWeight.bold,
                  color: AppColors.textDark,
                ),
              ),

              const SizedBox(height: AppSizes.paddingS),

              Text(
                '@${_sessionUsername ?? ''}',
                style: const TextStyle(
                  fontSize: 14,
                  fontWeight: FontWeight.w600,
                  color: AppColors.textMuted,
                ),
              ),

              const SizedBox(height: AppSizes.paddingS),

              // Rol (placeholder)
              Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: AppSizes.paddingM,
                  vertical: AppSizes.paddingS,
                ),
                decoration: BoxDecoration(
                  color: AppColors.gold.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(AppSizes.radiusM),
                  border: Border.all(color: AppColors.gold),
                ),
                child: Text(
                  (user?.roleLabel ??
                      (_sessionRole == 'admin' ? 'Administrador' : 'Cajero')),
                  style: const TextStyle(
                    color: AppColors.gold,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),

              const SizedBox(height: AppSizes.paddingL),

              if (user == null) ...[
                const Text(
                  'No hay un usuario cargado en la sesión.',
                  style: TextStyle(color: AppColors.textMuted),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: AppSizes.paddingM),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton.icon(
                    onPressed: () => context.go('/login'),
                    icon: const Icon(Icons.login),
                    label: const Text('Ir a iniciar sesión'),
                  ),
                ),
                const SizedBox(height: AppSizes.paddingXL),
              ],

              const SizedBox(height: AppSizes.paddingXL * 2),

              // Opciones
              Card(
                child: Column(
                  children: [
                    ListTile(
                      leading: const Icon(
                        Icons.person,
                        color: AppColors.teal700,
                      ),
                      title: const Text('Editar Perfil'),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () {
                        if (user == null) return;
                        _openEditProfile();
                      },
                    ),
                    const Divider(height: 1),
                    ListTile(
                      leading: const Icon(Icons.lock, color: AppColors.teal700),
                      title: const Text('Cambiar Contraseña'),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () {
                        if (user == null) return;
                        _openChangePassword();
                      },
                    ),
                    const Divider(height: 1),
                    ListTile(
                      leading: const Icon(
                        Icons.notifications,
                        color: AppColors.teal700,
                      ),
                      title: const Text('Preferencias'),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () {
                        _openPreferences();
                      },
                    ),
                  ],
                ),
              ),

              const SizedBox(height: AppSizes.paddingXL),

              // Botón cerrar sesión
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  onPressed: () async {
                    // Confirmación
                    final confirm = await showDialog<bool>(
                      context: context,
                      builder: (context) => AlertDialog(
                        title: const Text('Cerrar Sesión'),
                        content: const Text(
                          '¿Estás seguro de que deseas cerrar sesión?',
                        ),
                        actions: [
                          TextButton(
                            onPressed: () => Navigator.pop(context, false),
                            child: const Text('Cancelar'),
                          ),
                          ElevatedButton(
                            onPressed: () => Navigator.pop(context, true),
                            style: ElevatedButton.styleFrom(
                              backgroundColor: AppColors.error,
                            ),
                            child: const Text('Cerrar Sesión'),
                          ),
                        ],
                      ),
                    );

                    if (confirm == true && context.mounted) {
                      await SessionManager.logout();
                      if (context.mounted) {
                        context.go('/login');
                      }
                    }
                  },
                  icon: const Icon(Icons.logout),
                  label: const Text('Cerrar Sesión'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppColors.error,
                    foregroundColor: AppColors.textLight,
                    minimumSize: const Size(0, 52),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _InfoPill extends StatelessWidget {
  final String label;
  final String value;

  const _InfoPill({required this.label, required this.value});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(
        horizontal: AppSizes.paddingM,
        vertical: AppSizes.paddingS,
      ),
      decoration: BoxDecoration(
        color: AppColors.bgLight,
        borderRadius: BorderRadius.circular(AppSizes.radiusM),
        border: Border.all(color: AppColors.textMuted.withOpacity(0.25)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: const TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.w700,
              color: AppColors.textMuted,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            value,
            style: const TextStyle(
              fontSize: 13,
              fontWeight: FontWeight.w700,
              color: AppColors.textDark,
            ),
          ),
        ],
      ),
    );
  }
}

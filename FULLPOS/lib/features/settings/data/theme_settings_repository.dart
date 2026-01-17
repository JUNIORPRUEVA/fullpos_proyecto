import 'package:shared_preferences/shared_preferences.dart';
import 'dart:convert';
import 'theme_settings_model.dart';

/// Repositorio para persistir la configuración del tema
class ThemeSettingsRepository {
  static const String _themeKey = 'theme_settings';
  
  SharedPreferences? _prefs;
  
  /// Inicializar SharedPreferences
  Future<void> _ensureInitialized() async {
    _prefs ??= await SharedPreferences.getInstance();
  }
  
  /// Cargar configuración de tema guardada
  Future<ThemeSettings> loadThemeSettings() async {
    await _ensureInitialized();
    
    final String? jsonStr = _prefs!.getString(_themeKey);
    if (jsonStr == null) {
      return ThemeSettings.defaultSettings;
    }
    
    try {
      final Map<String, dynamic> map = json.decode(jsonStr) as Map<String, dynamic>;
      return ThemeSettings.fromMap(map);
    } catch (e) {
      // Si hay error al parsear, retornar valores por defecto
      return ThemeSettings.defaultSettings;
    }
  }
  
  /// Guardar configuración de tema
  Future<bool> saveThemeSettings(ThemeSettings settings) async {
    await _ensureInitialized();
    
    try {
      final String jsonStr = json.encode(settings.toMap());
      return await _prefs!.setString(_themeKey, jsonStr);
    } catch (e) {
      return false;
    }
  }
  
  /// Resetear a valores por defecto
  Future<bool> resetToDefault() async {
    await _ensureInitialized();
    
    try {
      await _prefs!.remove(_themeKey);
      return true;
    } catch (e) {
      return false;
    }
  }
  
  /// Verificar si hay configuración personalizada
  Future<bool> hasCustomTheme() async {
    await _ensureInitialized();
    return _prefs!.containsKey(_themeKey);
  }
}

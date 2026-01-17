import '../../../core/db/app_db.dart';
import 'business_settings_model.dart';

/// Repositorio para la configuración del negocio
class BusinessSettingsRepository {
  static const String _tableName = 'business_settings';

  /// Lista de todas las columnas esperadas con sus definiciones
  static const Map<String, String> _expectedColumns = {
    'id': 'INTEGER PRIMARY KEY DEFAULT 1',
    'business_name': "TEXT NOT NULL DEFAULT 'MI NEGOCIO'",
    'logo_path': 'TEXT',
    'phone': 'TEXT',
    'phone2': 'TEXT',
    'email': 'TEXT',
    'address': 'TEXT',
    'city': 'TEXT',
    'rnc': 'TEXT',
    'slogan': 'TEXT',
    'website': 'TEXT',
    'default_interest_rate': 'REAL DEFAULT 5.0',
    'default_late_fee_rate': 'REAL DEFAULT 2.0',
    'default_loan_term_days': 'INTEGER DEFAULT 30',
    'grace_period_days': 'INTEGER DEFAULT 3',
    'loan_contract_representative_name': "TEXT DEFAULT ''",
    'loan_contract_representative_cedula': "TEXT DEFAULT ''",
    'default_tax_rate': 'REAL DEFAULT 18.0',
    'tax_included_in_prices': 'INTEGER DEFAULT 1',
    'default_currency': "TEXT DEFAULT 'DOP'",
    'currency_symbol': "TEXT DEFAULT 'RD\$'",
    'receipt_header': "TEXT DEFAULT ''",
    'receipt_footer': "TEXT DEFAULT '¡Gracias por su compra!'",
    'show_logo_on_receipt': 'INTEGER DEFAULT 1',
    'print_receipt_automatically': 'INTEGER DEFAULT 0',
    'enable_auto_backup': 'INTEGER DEFAULT 1',
    'enable_notifications': 'INTEGER DEFAULT 1',
    'enable_loan_reminders': 'INTEGER DEFAULT 1',
    'enable_inventory_tracking': 'INTEGER DEFAULT 1',
    'enable_client_approval': 'INTEGER DEFAULT 0',
    'enable_data_encryption': 'INTEGER DEFAULT 1',
    'show_details_on_dashboard': 'INTEGER DEFAULT 1',
    'dark_mode_enabled': 'INTEGER DEFAULT 0',
    'session_timeout_minutes': 'INTEGER DEFAULT 30',
    'cloud_enabled': 'INTEGER DEFAULT 0',
    'cloud_provider': "TEXT DEFAULT 'custom'",
    'cloud_endpoint': 'TEXT',
    'cloud_bucket': 'TEXT',
    'cloud_api_key': 'TEXT',
    'cloud_allowed_roles': "TEXT DEFAULT '[\"admin\"]'",
    'cloud_owner_app_android_url': 'TEXT',
    'cloud_owner_app_ios_url': 'TEXT',
    'created_at': 'TEXT DEFAULT CURRENT_TIMESTAMP',
    'updated_at': 'TEXT DEFAULT CURRENT_TIMESTAMP',
  };

  /// Inicializar tabla de configuración del negocio
  static Future<void> initTable() async {
    final db = await AppDb.database;

    // Verificar si la tabla existe
    final tables = await db.rawQuery(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='$_tableName'",
    );

    if (tables.isEmpty) {
      // Crear tabla nueva con todas las columnas
      final columns = _expectedColumns.entries
          .map((e) => '${e.key} ${e.value}')
          .join(',\n          ');

      await db.execute('CREATE TABLE $_tableName ($columns)');

      // Insertar configuración por defecto
      await db.insert(_tableName, {
        'id': 1,
        'business_name': 'MI NEGOCIO',
        'created_at': DateTime.now().toIso8601String(),
        'updated_at': DateTime.now().toIso8601String(),
      });
    } else {
      // Tabla existe, verificar y agregar columnas faltantes
      await _migrateTableColumns(db);
    }
  }

  /// Migrar tabla agregando columnas faltantes
  static Future<void> _migrateTableColumns(dynamic db) async {
    try {
      // Obtener columnas existentes
      final tableInfo = await db.rawQuery('PRAGMA table_info($_tableName)');
      final existingColumns = tableInfo
          .map((row) => row['name'] as String)
          .toSet();

      // Agregar columnas faltantes
      for (final entry in _expectedColumns.entries) {
        if (!existingColumns.contains(entry.key) && entry.key != 'id') {
          try {
            // Extraer el tipo base de la definición
            final definition = entry.value;
            String columnDef = definition;

            // Para ALTER TABLE, necesitamos simplificar la definición
            if (definition.contains('DEFAULT')) {
              columnDef = definition;
            }

            await db.execute(
              'ALTER TABLE $_tableName ADD COLUMN ${entry.key} $columnDef',
            );
            print('✅ Columna ${entry.key} agregada a $_tableName');
          } catch (e) {
            print('⚠️ No se pudo agregar columna ${entry.key}: $e');
          }
        }
      }
    } catch (e) {
      print('Error migrando tabla $_tableName: $e');
    }
  }

  /// Cargar configuración del negocio
  Future<BusinessSettings> loadSettings() async {
    try {
      await initTable();
      final db = await AppDb.database;

      final results = await db.query(_tableName, where: 'id = 1');

      if (results.isEmpty) {
        // Si no hay configuración, crear una por defecto
        await db.insert(_tableName, {
          'id': 1,
          'business_name': 'MI NEGOCIO',
          'created_at': DateTime.now().toIso8601String(),
          'updated_at': DateTime.now().toIso8601String(),
        });
        return BusinessSettings.defaultSettings;
      }

      return BusinessSettings.fromMap(results.first);
    } catch (e) {
      print('Error cargando configuración del negocio: $e');
      return BusinessSettings.defaultSettings;
    }
  }

  /// Guardar configuración del negocio (solo columnas válidas)
  Future<void> saveSettings(BusinessSettings settings) async {
    try {
      await initTable();
      final db = await AppDb.database;

      // Obtener columnas existentes en la tabla
      final tableInfo = await db.rawQuery('PRAGMA table_info($_tableName)');
      final existingColumns = tableInfo
          .map((row) => row['name'] as String)
          .toSet();

      // Filtrar el mapa para solo incluir columnas que existen
      final map = settings.toMap();
      map['updated_at'] = DateTime.now().toIso8601String();

      final filteredMap = <String, dynamic>{};
      for (final entry in map.entries) {
        if (existingColumns.contains(entry.key) && entry.key != 'id') {
          filteredMap[entry.key] = entry.value;
        }
      }

      await db.update(_tableName, filteredMap, where: 'id = ?', whereArgs: [1]);
    } catch (e) {
      print('Error guardando configuración del negocio: $e');
      rethrow;
    }
  }

  /// Actualizar un campo específico
  Future<void> updateField(String field, dynamic value) async {
    try {
      await initTable();
      final db = await AppDb.database;

      await db.update(
        _tableName,
        {field: value, 'updated_at': DateTime.now().toIso8601String()},
        where: 'id = ?',
        whereArgs: [1],
      );
    } catch (e) {
      print('Error actualizando campo $field: $e');
      rethrow;
    }
  }

  /// Obtener valor de interés por defecto
  Future<double> getDefaultInterestRate() async {
    final settings = await loadSettings();
    return settings.defaultInterestRate;
  }

  /// Obtener valor de mora por defecto
  Future<double> getDefaultLateFeeRate() async {
    final settings = await loadSettings();
    return settings.defaultLateFeeRate;
  }

  /// Obtener tasa de impuesto por defecto
  Future<double> getDefaultTaxRate() async {
    final settings = await loadSettings();
    return settings.defaultTaxRate;
  }

  /// Resetear a valores por defecto
  Future<void> resetToDefault() async {
    await saveSettings(BusinessSettings.defaultSettings);
  }
}

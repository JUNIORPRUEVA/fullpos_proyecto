# LOS NILKAS POS

Sistema de Punto de Venta (POS) desarrollado en Flutter para Desktop Windows.

## 🚀 Características

- **Base de datos local persistente**: SQLite con soporte desktop (sqflite_common_ffi)
- **Navegación con ShellRoute**: Layout reutilizable (Sidebar + Topbar + Footer)
- **Material 3 Dark Theme**: Colores personalizados Teal + Gold
- **State Management**: Riverpod
- **Gestión de sesión**: SharedPreferences

## 📁 Estructura del Proyecto

```
lib/
├── main.dart                          # Punto de entrada
├── app/
│   ├── app.dart                       # MaterialApp.router
│   └── router.dart                    # Configuración go_router
├── core/
│   ├── constants/
│   │   ├── app_colors.dart           # Colores del tema
│   │   └── app_sizes.dart            # Constantes de tamaño
│   ├── theme/
│   │   └── app_theme.dart            # Tema Material 3 Dark
│   ├── layout/
│   │   ├── app_shell.dart            # Layout principal
│   │   ├── sidebar.dart              # Menú lateral
│   │   ├── topbar.dart               # Barra superior
│   │   └── footer.dart               # Pie de página
│   ├── session/
│   │   └── session_manager.dart      # Gestión de sesión
│   └── db/
│       ├── db_init.dart              # Inicialización SQLite
│       ├── app_db.dart               # Singleton de base de datos
│       └── tables.dart               # Nombres de tablas
└── features/
    ├── auth/
    │   ├── data/
    │   │   └── auth_repository.dart
    │   └── ui/
    │       ├── splash_page.dart
    │       └── login_page.dart
    ├── clients/
    │   ├── data/
    │   │   ├── client_model.dart
    │   │   └── clients_repository.dart
    │   └── ui/
    │       ├── clients_page.dart
    │       └── client_form_dialog.dart
    ├── products/
    │   ├── data/
    │   │   ├── product_model.dart
    │   │   └── products_repository.dart
    │   └── ui/
    │       └── products_page.dart
    ├── sales/
    │   ├── data/
    │   │   ├── sale_model.dart
    │   │   └── sales_repository.dart
    │   └── ui/
    │       └── sales_page.dart
    ├── pawn/
    │   ├── data/
    │   │   ├── pawn_model.dart
    │   │   └── pawn_repository.dart
    │   └── ui/
    │       └── pawn_page.dart
    ├── services/
    │   ├── data/
    │   │   ├── service_model.dart
    │   │   └── services_repository.dart
    │   └── ui/
    │       └── services_page.dart
    └── settings/
        └── ui/
            └── settings_page.dart
```

## 🛠️ Dependencias

- **go_router**: Navegación declarativa
- **flutter_riverpod**: State management
- **shared_preferences**: Persistencia de preferencias
- **sqflite**: Base de datos SQLite (mobile)
- **sqflite_common_ffi**: Base de datos SQLite (desktop)
- **path**: Utilidades de rutas
- **path_provider**: Acceso a directorios del sistema
- **intl**: Internacionalización y formateo

## 🚦 Cómo ejecutar

### Windows Desktop
```bash
flutter run -d windows
```

### Instalar dependencias
```bash
flutter pub get
```

### Análisis de código
```bash
flutter analyze
```

### Formatear código
```bash
dart format lib/
```

## 📝 Estado Actual

### ✅ Completado
- Estructura de carpetas y archivos
- Configuración de tema Material 3 (Teal + Gold)
- Layout principal con Sidebar, Topbar y Footer
- Router con ShellRoute y redirección por sesión
- Pantallas de Splash y Login
- Inicialización de base de datos SQLite
- **Módulo de Clientes COMPLETO**:
  - Esquema de base de datos con migración automática (v1 → v2)
  - Modelo de datos con soporte para soft delete
  - Repository con CRUD completo y filtros avanzados
  - Interfaz de usuario con búsqueda, filtros y acciones
  - Sistema de activación/desactivación de clientes
  - Sistema de crédito por cliente
  - Eliminación suave (soft delete) con restauración
  - Filtros por: nombre, teléfono, estado, crédito, rango de fechas
  - Ordenamiento: recientes, antiguos, alfabético
  - Pruebas unitarias completas (27 test cases)
- Placeholders para: Productos, Ventas, Empeño, Servicios, Configuración

### 🚧 Pendiente (TODO)
- Implementar módulo de productos
- Implementar módulo de ventas (punto de venta)
- Implementar módulo de empeño
- Implementar módulo de servicios
- Agregar validación de usuarios en base de datos
- Agregar funcionalidad de backup y restore
- Agregar reportes y estadísticas

## 🎨 Paleta de Colores

- **Teal 900-500**: Colores principales
- **Gold/Dorado**: Color de acento
- **Dark Background**: Fondo oscuro con gradient

## � Módulo de Clientes (Completado)

### Características Implementadas

#### Base de Datos
- **Migración automática**: Sistema de versionado que actualiza la base de datos de v1 a v2
- **Campos disponibles**:
  - `id`: Identificador único (autoincremental)
  - `nombre`: Nombre del cliente (requerido)
  - `telefono`: Teléfono (opcional)
  - `direccion`: Dirección (opcional)
  - `rnc`: Registro Nacional de Contribuyente (opcional)
  - `cedula`: Cédula de identidad (opcional)
  - `is_active`: Estado activo/inactivo (booleano)
  - `has_credit`: Indica si tiene crédito disponible (booleano)
  - `created_at_ms`: Fecha de creación (timestamp)
  - `updated_at_ms`: Fecha de última actualización (timestamp)
  - `deleted_at_ms`: Fecha de eliminación suave (timestamp nullable)
- **Índices de rendimiento**: Optimización para búsquedas por fecha, estado activo y crédito

#### API del Repository (`ClientsRepository`)

**CRUD Básico**:
- `create(ClientModel)` → Crear nuevo cliente
- `update(ClientModel)` → Actualizar cliente existente
- `delete(int id)` → Eliminación suave (soft delete)
- `restore(int id)` → Restaurar cliente eliminado
- `getById(int id)` → Obtener por ID
- `getByPhone(String phone)` → Buscar por teléfono

**Operaciones Especiales**:
- `toggleActive(int id, bool value)` → Activar/desactivar cliente
- `toggleCredit(int id, bool value)` → Habilitar/deshabilitar crédito

**Listado con Filtros Avanzados**:
```dart
list({
  String? query,              // Búsqueda por nombre o teléfono
  bool? isActive,             // Filtrar por estado (null = todos)
  bool? hasCredit,            // Filtrar por crédito (null = todos)
  int? createdFromMs,         // Fecha de creación desde
  int? createdToMs,           // Fecha de creación hasta
  bool includeDeleted,        // Incluir eliminados
  String orderBy,             // 'recent', 'old', 'name'
  int? limit,                 // Límite de resultados
})
```

#### Interfaz de Usuario

**Pantalla Principal** (`ClientsPage`):
- Barra de búsqueda con debounce de 500ms
- Botón de filtros avanzados
- Botón "Nuevo Cliente"
- Contador de resultados
- Lista de clientes con toda la información

**Tarjeta de Cliente** (`_ClientListItem`):
- Avatar con inicial del nombre
- Badge de estado: ACTIVO (verde) / INACTIVO (rojo)
- Badge de CRÉDITO (dorado) si aplica
- Información: teléfono, dirección, RNC, cédula
- Fecha de creación
- Menú de opciones (PopupMenu):
  - Editar
  - Activar/Desactivar
  - Dar/Quitar crédito
  - Eliminar (con confirmación)

**Diálogo de Filtros** (`_FiltersDialog`):
- **Estado**: Todos / Activos / Inactivos (SegmentedButton)
- **Crédito**: Todos / Con crédito / Sin crédito (SegmentedButton)
- **Rango de fechas**: Selector de fecha desde/hasta
- **Ordenar por**: Más recientes / Más antiguos / Nombre A-Z
- **Mostrar eliminados**: Switch para incluir clientes borrados
- Botones: "Limpiar todo" y "Aplicar"

**Diálogo de Formulario** (`ClientFormDialog`):
- Campos: Nombre (requerido), Teléfono, Dirección, RNC, Cédula
- Switch "Activo" (default: true)
- Switch "Tiene Crédito" (default: false)
- Validación en tiempo real
- Botones: Cancelar / Guardar

#### Tests Automatizados

27 casos de prueba cubriendo:
- ✅ CRUD Operations (crear, actualizar, eliminar, restaurar)
- ✅ Toggle Operations (activar/desactivar, dar/quitar crédito)
- ✅ Filtering and Search (9 tests con múltiples combinaciones)
- ✅ Búsquedas específicas (por ID, por teléfono)

**Ejecutar tests**:
```bash
flutter test test/clients_repository_test.dart
```

### Uso del Módulo

#### Crear un Cliente
1. Clic en "Nuevo Cliente"
2. Llenar el formulario (solo nombre es obligatorio)
3. Activar switches de "Activo" y "Tiene Crédito" si aplica
4. Guardar

#### Buscar y Filtrar
1. Usar barra de búsqueda para filtro rápido por nombre o teléfono
2. Clic en botón de filtros para opciones avanzadas
3. Seleccionar estado, crédito, rango de fechas y orden
4. Aplicar filtros

#### Editar / Eliminar
1. Clic en menú de opciones (⋮) en la tarjeta del cliente
2. Seleccionar acción deseada
3. Confirmar eliminación si aplica (soft delete, se puede restaurar)

#### Activar/Desactivar Cliente
- Desde el menú de opciones: "Activar" / "Desactivar"
- Útil para clientes temporales o suspendidos

#### Gestión de Crédito
- Desde el menú de opciones: "Dar crédito" / "Quitar crédito"
- Aparece badge dorado "CRÉDITO" en clientes habilitados

## �📄 Licencia

© 2025 LOS NILKAS - Sistema POS Local v1.0.0

  
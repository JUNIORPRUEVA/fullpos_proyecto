# FULLPOS Owner

Aplicación Flutter para dueños/clientes que consultan reportes y cierres de caja del backend FULLPOS.

## Requisitos
- Flutter 3.10+
- Backend FULLPOS corriendo (`fullpos_backend`) con los endpoints `/api/auth/*`, `/api/reports/*`, `/api/downloads/owner-app`.

## Configuración de entorno
La app lee la URL base del backend con `--dart-define`:

```bash
flutter run --dart-define=BASE_URL=http://localhost:4000
```

Para Android (emulador físico/virtual) cambia el host según aplique.

## Comandos útiles
- `flutter pub get`
- `dart run build_runner build --delete-conflicting-outputs` (genera modelos Freezed/JSON)
- `flutter run --dart-define=BASE_URL=...`
- `flutter build apk --dart-define=BASE_URL=...`

## Funcionalidades
- Login (usuario/correo + password) con almacenamiento seguro de token.
- Dashboard con resumen y ventas por día.
- Listado paginado de ventas por rango.
- Listado de cierres de caja y detalle de cierre (ventas y movimientos).

## Estructura
- `lib/app`: router y tema.
- `lib/core`: red, storage seguro, widgets base.
- `lib/features/auth`: login + estado.
- `lib/features/reports`: modelos y pantallas de reportes.
- `lib/features/cash`: cierres de caja.

## Credenciales demo
Después de correr `npm run seed` en el backend:
- usuario: `owner`
- password: `fullpos123`

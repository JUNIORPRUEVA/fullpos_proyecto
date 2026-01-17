# Prueba manual: pantalla negra (Windows)

Objetivo: validar que la app no quede en negro y que el watchdog deje evidencia en `logs/app.log`.

## Pasos
- Cierra la app si está abierta y limpia overlays pendientes (cerrar diálogos, loaders).
- Abre y cierra la app **30 veces seguidas**. Alterna entre:
  - Abrir maximizada (modo POS).
  - Abrir después de un cierre con Alt+F4.
- (Opcional) Reinicia la PC una vez y repite 5 aperturas.
- Si aparece pantalla negra:
  - Espera 2 segundos para ver si el banner “Reiniciando vista…” aparece y recupera la UI.
  - Si entra en “Modo seguro”, presiona “Reintentar”.
  - Revisa `AppData/…/logs/app.log` y verifica eventos en orden: `runApp_called` → `first_frame_painted` o `BLACK_SCREEN_DETECTED` → `render_recovery` → `safe_mode_*` (si aplica).
- Valida que la navegación/login siga funcionando después de la recuperación.

## Resultados esperados
- En 30 aperturas: 0 pantallas negras, o si ocurre se recupera en < 2 s.
- El log muestra `ttff_ms`, `BLACK_SCREEN_DETECTED` (si ocurrió), y `render_recovery` o `safe_mode_exit`.

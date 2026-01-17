# INTEGRIDAD_TESTS (manual)

Este documento valida que **ventas/stock** y **préstamos/cuotas** no dejen datos a medias y que la app se recupere de cierres inesperados.

## 1) Ventas atómicas (todo o nada)
- Crear una venta con 2 productos (cantidades > 0).
- Verificar en “Ventas” que existe 1 venta con 2 items.
- Verificar que el stock se descontó correctamente.

## 2) Bloqueo por stock insuficiente
- Preparar un producto con stock = 1.
- Intentar vender qty = 2.
- Resultado esperado:
  - La app muestra confirmación de “Stock insuficiente”.
  - Si cancelas: no se crea venta, no se modifica stock.
  - Si continúas: se crea la venta y el movimiento queda marcado “(sin stock)” en la nota del movimiento.

## 3) Cierre inesperado y “recovery”
- Crear un ticket pendiente (carrito) y dejarlo sin terminar.
- Cerrar la app de forma abrupta (kill / cerrar ventana sin finalizar venta).
- Esperar más de 10 minutos.
- Abrir la app.
- Resultado esperado: el sistema limpia tickets pendientes muy viejos para evitar “basura” (recovery).

## 4) Préstamos: crear + pagar cuota
- Crear un préstamo válido (monto > 0, cuotas > 0, etc.).
- Registrar un pago parcial y verificar:
  - La cuota cambia a `PARTIAL` o `PAID` según corresponda.
  - El balance baja exactamente por el monto pagado.

## 5) Préstamos: bloqueo por sobrepago
- Con un préstamo que tenga balance pendiente, intentar pagar un monto mayor al balance.
- Resultado esperado:
  - El sistema bloquea el pago con mensaje amigable.
  - No debe insertarse pago ni cambiar cuotas/balance.


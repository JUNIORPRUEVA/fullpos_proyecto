# Guía Rápida: Nuevo Módulo de Cotizaciones

## Para Probar

1. Ejecuta la app normalmente
2. Ve al módulo de Cotizaciones
3. Verás una **lista compacta tipo tabla** en lugar de tarjetas grandes

## Nuevas Funcionalidades

### 🔍 Búsqueda
- Escribe en el campo de búsqueda
- Busca automáticamente mientras tipeas (debounce 300ms)
- Busca en: cliente, teléfono, código (COT-xxxxx), total

### 🎯 Filtros (barra gris bajo la búsqueda)

| Botón | Función |
|-------|---------|
| 📅 Fecha | Selecciona una fecha exacta |
| 📊 Rango | Selecciona rango de fechas |
| 📋 Estado | Filtra por Abierta/Enviada/Vendida/Cancelada |
| ⬆️⬇️ Orden | Ordena por fecha o total |
| ❌ Limpiar | Borra todos los filtros de una |

### ⚡ Acciones (iconos en cada fila)
| Icono | Acción |
|-------|--------|
| 💳 | Vender (convertir a venta) |
| 💬 | WhatsApp |
| 📄 | Ver/Descargar PDF |
| 📋 | Duplicar cotización |
| 🗑️ | Eliminar |

## Cambios Técnicos

### Archivos Nuevos
- `lib/features/sales/ui/widgets/compact_quote_row.dart` - Widget de fila compacta
- `lib/features/sales/ui/widgets/quotes_filter_bar.dart` - Barra de filtros
- `lib/features/sales/ui/utils/quotes_filter_util.dart` - Lógica de filtrado

### Archivos Modificados
- `lib/features/sales/ui/quotes_page.dart` - Integración de nuevos widgets

### Lo que NO cambió
- Toda la lógica de negocio (`_convertToSale`, `_deleteQuote`, etc.)
- Métodos de impresión (PDF)
- Integración con base de datos
- Diálogos de detalles

---

## Solución de Problemas

**¿Las acciones no funcionan?**  
→ Verifica que no haya errores en la consola. Todos los métodos siguen siendo los mismos.

**¿El rendimiento es lento?**  
→ La lista está optimizada para 1000+ cotizaciones. Si tienes muchas, intenta:
- Usar filtros para reducir los resultados
- Ordenar por fecha más reciente primero

**¿No aparecen los iconos?**  
→ Verifica que `flutter pub get` esté actualizado

---

## Referencia de Estado

Los estados de color son:
- 🔵 **Abierta**: Azul (sin vender)
- 🟠 **Enviada**: Naranja (espera respuesta)
- 🟢 **Vendida**: Verde (convertida a venta)
- 🔴 **Cancelada**: Rojo (rechazada)

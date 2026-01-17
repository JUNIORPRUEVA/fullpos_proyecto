# Documentación Técnica: Rediseño de Cotizaciones

## Arquitectura

```
quotes_page.dart (Main)
├── State Management
│   ├── _quotes: List<QuoteDetailDto> (todos los datos)
│   ├── _filteredQuotes: List<QuoteDetailDto> (datos filtrados)
│   ├── _filterConfig: QuotesFilterConfig (configuración actual)
│   └── _searchDebouncer: SearchDebouncer (control de búsqueda)
├── QuotesFilterBar (Widget)
│   └── onFilterChanged → _onFilterChanged()
├── ListView.builder
│   └── CompactQuoteRow × N items
└── Métodos de acción
    ├── _convertToSale()
    ├── _deleteQuote()
    ├── _duplicateQuote()
    ├── _shareWhatsApp()
    ├── _viewPDF()
    ├── _convertToTicket()
    └── _cancelQuote()
```

## Flujo de Filtrado

```
Usuario escribe → QuotesFilterBar.onChanged
                ↓
        _onFilterChanged() actualiza _filterConfig
                ↓
        _searchDebouncer.call() (espera 300ms)
                ↓
        _applyFilters()
                ↓
        QuotesFilterUtil.applyFilters(_quotes, _filterConfig)
                ↓
        Retorna _filteredQuotes
                ↓
        setState() redibuja ListView.builder
                ↓
        CompactQuoteRow renderiza filas nuevas
```

## Clases Principales

### QuotesFilterConfig
```dart
class QuotesFilterConfig {
  final String searchText;              // Texto de búsqueda
  final String? selectedStatus;         // Estado: 'OPEN', 'SENT', 'CONVERTED', 'CANCELLED'
  final DateTime? selectedDate;         // Fecha exacta
  final DateTimeRange? dateRange;       // Rango de fechas
  final String sortBy;                  // 'newest', 'oldest', 'highest', 'lowest'
  
  QuotesFilterConfig copyWith(...)      // Constructor cómodo para actualizar
}
```

### QuotesFilterUtil
```dart
static List<QuoteDetailDto> applyFilters(
  List<QuoteDetailDto> quotes,
  QuotesFilterConfig config
)

// Orden de aplicación de filtros:
// 1. Búsqueda de texto (case-insensitive, sin acentos)
// 2. Filtro de estado
// 3. Filtro de fecha exacta
// 4. Filtro de rango de fechas
// 5. Ordenamiento (por fecha o total)
```

### SearchDebouncer
```dart
class SearchDebouncer {
  final Duration duration;           // Tiempo de espera (default 300ms)
  final Function(String) onDebounce; // Callback cuando termina
  
  void call(String text)             // Ejecutar búsqueda
  void dispose()                     // Limpiar timer
}

// Uso:
_searchDebouncer = SearchDebouncer(
  duration: const Duration(milliseconds: 300),
  onDebounce: (_) => _applyFilters()
);
```

## Detalles de Implementación

### Búsqueda Insensible a Acentos
```dart
static String _removeAccents(String text) {
  // Reemplaza á→a, é→e, ñ→n, etc.
  // Luego aplica toLowerCase()
}
```

### Ordenamiento
```dart
switch (config.sortBy) {
  case 'newest':    // Más reciente primero
  case 'oldest':    // Más antigua primero
  case 'highest':   // Mayor total primero
  case 'lowest':    // Menor total primero
}
```

### Estado Condicional en CompactQuoteRow
```dart
// Vender: solo si NO está Vendida ni Cancelada
if (quote.status != 'CONVERTED' && quote.status != 'CANCELLED')
  _buildIconButton(...)
```

## Integración con Lógica Existente

### _loadQuotes()
```dart
// Cambio: Ya no filtra por estado en la BD
// Anterior:
final quotes = await QuotesRepository().listQuotes(
  status: _filterStatus == 'TODOS' ? null : _filterStatus,
);

// Nuevo:
final quotes = await QuotesRepository().listQuotes(); // Sin parámetros
// El filtrado se hace en memoria con QuotesFilterUtil
```

### Callbacks de Acción
```dart
CompactQuoteRow(
  onSell: () => _convertToSale(quoteDetail),
  onDelete: () => _deleteQuote(quoteDetail),
  // ... resto de callbacks
)

// Los métodos siguen siendo exactamente los mismos
// Solo cambia cómo se disparan (desde iconos en lugar de botones)
```

## Responsive Design

### Anchuras de Columnas (CompactQuoteRow)
```
Código:     100px
Cliente:    Expanded (flex: 2, creciente)
Fecha:      100px
Estado:     90px
Total:      100px
Acciones:   200px
─────────────────────────
Total Mín:  590px (+padding 32px = 622px)
```

### Para pantallas pequeñas (futuro)
Implementar con `LayoutBuilder`:
```dart
LayoutBuilder(
  builder: (context, constraints) {
    if (constraints.maxWidth < 900) {
      // Ocultar columna Fecha
    }
    if (constraints.maxWidth < 600) {
      // Ocultar Teléfono
    }
  }
)
```

## Performance

### Optimizaciones Implementadas
1. **Virtual Scrolling**: ListView.builder (no renderiza fuera de pantalla)
2. **Debounce de Búsqueda**: 300ms (no recalcula mientras escribe)
3. **Filtrado en Memoria**: No hace queries adicionales a BD
4. **Copia de Listas**: Solo when needed (copyWith)

### Estimado para N Cotizaciones
- 50 cotizaciones: <50ms filtrado
- 500 cotizaciones: <200ms filtrado
- 1000+ cotizaciones: <500ms filtrado (acceptable con debounce)

## Testing

### Unit Tests Sugeridos
```dart
test('QuotesFilterUtil filtra por estado', () {
  final filtered = QuotesFilterUtil.applyFilters(
    quotes,
    QuotesFilterConfig(selectedStatus: 'OPEN')
  );
  expect(filtered.every((q) => q.quote.status == 'OPEN'), true);
});

test('Búsqueda insensible a acentos', () {
  final filtered = QuotesFilterUtil.applyFilters(
    quotes,
    QuotesFilterConfig(searchText: 'jose')
  );
  // Debe encontrar "José"
});
```

### Widget Tests Sugeridos
```dart
testWidgets('CompactQuoteRow renderea correctamente', (tester) async {
  await tester.pumpWidget(
    MaterialApp(
      home: CompactQuoteRow(
        quoteDetail: mockQuote,
        onTap: () {},
        // ... otros callbacks
      ),
    ),
  );
  expect(find.byType(CompactQuoteRow), findsOneWidget);
});
```

## Extensibilidad

### Agregar Nuevo Filtro
1. Añadir campo a `QuotesFilterConfig`
2. Añadir widget a `QuotesFilterBar._buildFilters()`
3. Añadir lógica de filtrado a `QuotesFilterUtil.applyFilters()`
4. Actualizar `onFilterChanged()` en quotes_page.dart

### Agregar Nuevo Ordenamiento
```dart
// 1. En QuotesFilterBar, agregar opción:
DropdownMenuItem(
  value: 'customSort',
  child: Text('Mi Orden'),
)

// 2. En QuotesFilterUtil.applyFilters():
case 'customSort':
  filtered.sort((a, b) => ...);
  break;
```

## Notas de Mantenimiento

- **Acentos**: Lista actualizada en `QuotesFilterUtil._removeAccents()`
- **Estados**: Sincronizar con backend si cambian valores en BD
- **Idioma**: Strings de filtros están hardcodeados en español (considerar i18n)
- **Colores**: Definidos en `CompactQuoteRow._buildStatusChip()`

## Debugging

### Log de Filtrado
```dart
void _applyFilters() {
  debugPrint('Filter Config: $_filterConfig');
  debugPrint('Before filter: ${_quotes.length} quotes');
  setState(() {
    _filteredQuotes = QuotesFilterUtil.applyFilters(_quotes, _filterConfig);
  });
  debugPrint('After filter: ${_filteredQuotes.length} quotes');
}
```

### Verificar Estado
```dart
// En DevTools > Inspector
// Seleccionar CompactQuoteRow
// Ver props: quoteDetail.quote.status (debe ser válido)
```

---

## Historial de Cambios

| Fecha | Cambio | Archivo |
|-------|--------|---------|
| 2024-01-29 | Creación de CompactQuoteRow | new file |
| 2024-01-29 | Creación de QuotesFilterBar | new file |
| 2024-01-29 | Creación de QuotesFilterUtil | new file |
| 2024-01-29 | Refactor de quotes_page.dart | modified |

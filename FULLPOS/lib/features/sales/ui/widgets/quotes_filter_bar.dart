import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

/// Configuración para los filtros y búsqueda
class QuotesFilterConfig {
  final String searchText;
  final String? selectedStatus;
  final DateTime? selectedDate;
  final DateTimeRange? dateRange;
  final String sortBy; // 'newest', 'oldest', 'highest', 'lowest'

  const QuotesFilterConfig({
    this.searchText = '',
    this.selectedStatus,
    this.selectedDate,
    this.dateRange,
    this.sortBy = 'newest',
  });

  QuotesFilterConfig copyWith({
    String? searchText,
    String? selectedStatus,
    DateTime? selectedDate,
    DateTimeRange? dateRange,
    String? sortBy,
  }) {
    return QuotesFilterConfig(
      searchText: searchText ?? this.searchText,
      selectedStatus: selectedStatus ?? this.selectedStatus,
      selectedDate: selectedDate ?? this.selectedDate,
      dateRange: dateRange ?? this.dateRange,
      sortBy: sortBy ?? this.sortBy,
    );
  }
}

/// Barra de filtros y búsqueda para las cotizaciones
class QuotesFilterBar extends StatefulWidget {
  final QuotesFilterConfig initialConfig;
  final Function(QuotesFilterConfig) onFilterChanged;

  const QuotesFilterBar({
    required this.initialConfig,
    required this.onFilterChanged,
  });

  @override
  State<QuotesFilterBar> createState() => _QuotesFilterBarState();
}

class _QuotesFilterBarState extends State<QuotesFilterBar> {
  late QuotesFilterConfig _config;
  late TextEditingController _searchController;

  @override
  void initState() {
    super.initState();
    _config = widget.initialConfig;
    _searchController = TextEditingController(text: _config.searchText);
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  void _updateConfig(QuotesFilterConfig newConfig) {
    setState(() {
      _config = newConfig;
    });
    widget.onFilterChanged(_config);
  }

  Future<void> _pickDate() async {
    final picked = await showDatePicker(
      context: context,
      initialDate: _config.selectedDate ?? DateTime.now(),
      firstDate: DateTime(2020),
      lastDate: DateTime.now(),
    );
    if (picked != null) {
      _updateConfig(_config.copyWith(selectedDate: picked));
    }
  }

  Future<void> _pickDateRange() async {
    final picked = await showDateRangePicker(
      context: context,
      firstDate: DateTime(2020),
      lastDate: DateTime.now(),
      initialDateRange: _config.dateRange,
      saveText: 'Aceptar',
      cancelText: 'Cancelar',
    );
    if (picked != null) {
      _updateConfig(_config.copyWith(dateRange: picked));
    }
  }

  void _clearFilters() {
    _searchController.clear();
    _updateConfig(const QuotesFilterConfig());
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      color: Colors.grey.shade50,
      padding: const EdgeInsets.all(16),
      child: Column(
        spacing: 12,
        children: [
          // Fila 1: Búsqueda
          TextField(
            controller: _searchController,
            onChanged: (text) {
              _updateConfig(_config.copyWith(searchText: text));
            },
            decoration: InputDecoration(
              hintText: 'Buscar por cliente, teléfono, código o total...',
              prefixIcon: const Icon(Icons.search, color: Colors.teal),
              suffixIcon: _searchController.text.isNotEmpty
                  ? IconButton(
                      icon: const Icon(Icons.clear),
                      onPressed: () {
                        _searchController.clear();
                        _updateConfig(_config.copyWith(searchText: ''));
                      },
                    )
                  : null,
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: BorderSide(color: Colors.grey.shade300),
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: BorderSide(color: Colors.grey.shade300),
              ),
              contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            ),
          ),

          // Fila 2: Filtros (Fecha, DateRange, Estado, Orden)
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              spacing: 8,
              children: [
                // Botón: Fecha única
                _buildFilterButton(
                  icon: Icons.calendar_today,
                  label: _config.selectedDate != null
                      ? DateFormat('dd/MM/yy').format(_config.selectedDate!)
                      : 'Fecha',
                  onPressed: _pickDate,
                  isActive: _config.selectedDate != null,
                ),

                // Botón: Rango de fechas
                _buildFilterButton(
                  icon: Icons.date_range,
                  label: _config.dateRange != null
                      ? '${DateFormat('dd/MM').format(_config.dateRange!.start)} - ${DateFormat('dd/MM').format(_config.dateRange!.end)}'
                      : 'Rango',
                  onPressed: _pickDateRange,
                  isActive: _config.dateRange != null,
                ),

                // Dropdown: Estado
                _buildStatusDropdown(),

                // Dropdown: Ordenamiento
                _buildSortDropdown(),

                // Botón: Limpiar filtros
                if (_config.selectedDate != null ||
                    _config.dateRange != null ||
                    _config.selectedStatus != null ||
                    _config.searchText.isNotEmpty)
                  ElevatedButton(
                    onPressed: _clearFilters,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.red.shade100,
                      foregroundColor: Colors.red.shade700,
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(6),
                      ),
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                    ),
                    child: const Row(
                      spacing: 4,
                      children: [
                        Icon(Icons.clear, size: 16),
                        Text('Limpiar', style: TextStyle(fontSize: 12)),
                      ],
                    ),
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFilterButton({
    required IconData icon,
    required String label,
    required VoidCallback onPressed,
    required bool isActive,
  }) {
    return ElevatedButton(
      onPressed: onPressed,
      style: ElevatedButton.styleFrom(
        backgroundColor: isActive ? Colors.teal.shade100 : Colors.white,
        foregroundColor: isActive ? Colors.teal : Colors.grey.shade600,
        side: BorderSide(
          color: isActive ? Colors.teal : Colors.grey.shade300,
        ),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(6),
        ),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      ),
      child: Row(
        spacing: 4,
        children: [
          Icon(icon, size: 16),
          Text(label, style: const TextStyle(fontSize: 12)),
        ],
      ),
    );
  }

  Widget _buildStatusDropdown() {
    return Container(
      decoration: BoxDecoration(
        border: Border.all(color: Colors.grey.shade300),
        borderRadius: BorderRadius.circular(6),
      ),
      padding: const EdgeInsets.symmetric(horizontal: 8),
      child: DropdownButton<String?>(
        value: _config.selectedStatus,
        underline: const SizedBox(),
        icon: const Icon(Icons.expand_more, size: 20),
        items: [
          const DropdownMenuItem(value: null, child: Text('Estado')),
          const DropdownMenuItem(value: 'OPEN', child: Text('Abierta')),
          const DropdownMenuItem(value: 'SENT', child: Text('Enviada')),
          const DropdownMenuItem(value: 'CONVERTED', child: Text('Vendida')),
          const DropdownMenuItem(value: 'CANCELLED', child: Text('Cancelada')),
        ],
        onChanged: (value) {
          _updateConfig(_config.copyWith(selectedStatus: value));
        },
      ),
    );
  }

  Widget _buildSortDropdown() {
    final sortLabels = {
      'newest': 'Más reciente',
      'oldest': 'Más antigua',
      'highest': 'Mayor total',
      'lowest': 'Menor total',
    };

    return Container(
      decoration: BoxDecoration(
        border: Border.all(color: Colors.grey.shade300),
        borderRadius: BorderRadius.circular(6),
      ),
      padding: const EdgeInsets.symmetric(horizontal: 8),
      child: DropdownButton<String>(
        value: _config.sortBy,
        underline: const SizedBox(),
        icon: const Icon(Icons.expand_more, size: 20),
        items: [
          DropdownMenuItem(
            value: 'newest',
            child: Text(sortLabels['newest']!),
          ),
          DropdownMenuItem(
            value: 'oldest',
            child: Text(sortLabels['oldest']!),
          ),
          DropdownMenuItem(
            value: 'highest',
            child: Text(sortLabels['highest']!),
          ),
          DropdownMenuItem(
            value: 'lowest',
            child: Text(sortLabels['lowest']!),
          ),
        ],
        onChanged: (value) {
          if (value != null) {
            _updateConfig(_config.copyWith(sortBy: value));
          }
        },
      ),
    );
  }
}

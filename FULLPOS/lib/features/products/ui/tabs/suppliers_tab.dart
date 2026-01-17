import 'package:flutter/material.dart';

import '../../data/suppliers_repository.dart';
import '../../models/supplier_model.dart';
import '../dialogs/supplier_form_dialog.dart';

/// Tab de Suplidores
class SuppliersTab extends StatefulWidget {
  const SuppliersTab({super.key});

  @override
  State<SuppliersTab> createState() => _SuppliersTabState();
}

class _SuppliersTabState extends State<SuppliersTab> {
  final SuppliersRepository _suppliersRepo = SuppliersRepository();
  final TextEditingController _searchController = TextEditingController();

  List<SupplierModel> _suppliers = [];
  List<SupplierModel> _filteredSuppliers = [];
  bool _isLoading = false;

  @override
  void initState() {
    super.initState();
    _loadSuppliers();
    _searchController.addListener(_filterSuppliers);
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  Future<void> _loadSuppliers() async {
    setState(() => _isLoading = true);
    try {
      final suppliers = await _suppliersRepo.getAll(includeInactive: true);
      if (mounted) {
        setState(() {
          _suppliers = suppliers;
          _filteredSuppliers = suppliers;
        });
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error al cargar suplidores: $e')),
        );
      }
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  void _filterSuppliers() {
    final query = _searchController.text.toLowerCase();
    setState(() {
      _filteredSuppliers = query.isEmpty
          ? _suppliers
          : _suppliers
              .where((s) =>
                  s.name.toLowerCase().contains(query) ||
                  (s.phone?.toLowerCase().contains(query) ?? false))
              .toList();
    });
  }

  Future<void> _showSupplierForm([SupplierModel? supplier]) async {
    final result = await showDialog<bool>(
      context: context,
      builder: (context) => SupplierFormDialog(supplier: supplier),
    );

    if (result == true) {
      _loadSuppliers();
    }
  }

  Future<void> _toggleActive(SupplierModel supplier) async {
    try {
      await _suppliersRepo.toggleActive(supplier.id!, !supplier.isActive);
      _loadSuppliers();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              supplier.isActive
                  ? 'Suplidor desactivado'
                  : 'Suplidor activado',
            ),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error: $e')),
        );
      }
    }
  }

  Future<void> _softDelete(SupplierModel supplier) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(supplier.isDeleted
            ? 'Restaurar Suplidor'
            : 'Eliminar Suplidor'),
        content: Text(
          supplier.isDeleted
              ? '¿Desea restaurar "${supplier.name}"?'
              : '¿Está seguro de eliminar "${supplier.name}"?',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancelar'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(supplier.isDeleted ? 'Restaurar' : 'Eliminar'),
          ),
        ],
      ),
    );

    if (confirm == true) {
      try {
        if (supplier.isDeleted) {
          await _suppliersRepo.restore(supplier.id!);
        } else {
          await _suppliersRepo.softDelete(supplier.id!);
        }
        _loadSuppliers();
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(
                supplier.isDeleted
                    ? 'Suplidor restaurado'
                    : 'Suplidor eliminado',
              ),
            ),
          );
        }
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Error: $e')),
          );
        }
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        // Barra de búsqueda y acciones
        Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _searchController,
                  decoration: InputDecoration(
                    hintText: 'Buscar por nombre o teléfono...',
                    prefixIcon: const Icon(Icons.search),
                    suffixIcon: _searchController.text.isNotEmpty
                        ? IconButton(
                            icon: const Icon(Icons.clear),
                            onPressed: () {
                              _searchController.clear();
                              _filterSuppliers();
                            },
                          )
                        : null,
                    border: const OutlineInputBorder(),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              IconButton(
                icon: const Icon(Icons.add),
                onPressed: () => _showSupplierForm(),
                tooltip: 'Nuevo Suplidor',
              ),
            ],
          ),
        ),

        // Lista de suplidores
        Expanded(
          child: _isLoading
              ? const Center(child: CircularProgressIndicator())
              : _filteredSuppliers.isEmpty
                  ? Center(
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Icon(Icons.business_outlined,
                              size: 64, color: Colors.grey[400]),
                          const SizedBox(height: 16),
                          Text(
                            _searchController.text.isNotEmpty
                                ? 'No se encontraron suplidores'
                                : 'No hay suplidores registrados',
                            style: TextStyle(
                              fontSize: 18,
                              color: Colors.grey[600],
                            ),
                          ),
                          const SizedBox(height: 8),
                          ElevatedButton.icon(
                            onPressed: () => _showSupplierForm(),
                            icon: const Icon(Icons.add),
                            label: const Text('Crear Primer Suplidor'),
                          ),
                        ],
                      ),
                    )
                  : RefreshIndicator(
                      onRefresh: _loadSuppliers,
                      child: ListView.builder(
                        itemCount: _filteredSuppliers.length,
                        itemBuilder: (context, index) {
                          final supplier = _filteredSuppliers[index];
                          return Card(
                            margin: const EdgeInsets.symmetric(
                                horizontal: 16, vertical: 4),
                            elevation: 1,
                            child: Padding(
                              padding: const EdgeInsets.symmetric(
                                  horizontal: 12, vertical: 10),
                              child: Row(
                                children: [
                                  // Icono
                                  CircleAvatar(
                                    radius: 16,
                                    backgroundColor:
                                        supplier.isActive && !supplier.isDeleted
                                            ? Colors.blue
                                            : Colors.grey,
                                    child: const Icon(Icons.business,
                                        color: Colors.white, size: 18),
                                  ),
                                  const SizedBox(width: 12),
                                  // Nombre
                                  Expanded(
                                    flex: 2,
                                    child: Column(
                                      crossAxisAlignment: CrossAxisAlignment.start,
                                      mainAxisSize: MainAxisSize.min,
                                      children: [
                                        Text(
                                          supplier.name,
                                          style: TextStyle(
                                            fontSize: 14,
                                            fontWeight: FontWeight.w600,
                                            decoration: supplier.isDeleted
                                                ? TextDecoration.lineThrough
                                                : null,
                                          ),
                                          overflow: TextOverflow.ellipsis,
                                        ),
                                        if (supplier.phone != null)
                                          Text(
                                            supplier.phone!,
                                            style: TextStyle(
                                              fontSize: 11,
                                              color: Colors.grey[600],
                                            ),
                                            overflow: TextOverflow.ellipsis,
                                          ),
                                      ],
                                    ),
                                  ),
                                  const SizedBox(width: 8),
                                  // Nota (si existe)
                                  if (supplier.note != null)
                                    Expanded(
                                      child: Text(
                                        supplier.note!,
                                        style: TextStyle(
                                          fontSize: 11,
                                          color: Colors.grey[600],
                                        ),
                                        maxLines: 1,
                                        overflow: TextOverflow.ellipsis,
                                      ),
                                    ),
                                  const SizedBox(width: 8),
                                  // Badge de estado
                                  if (supplier.isDeleted)
                                    Container(
                                      padding: const EdgeInsets.symmetric(
                                          horizontal: 6, vertical: 3),
                                      decoration: BoxDecoration(
                                        color: Colors.red.withOpacity(0.15),
                                        borderRadius: BorderRadius.circular(3),
                                      ),
                                      child: const Text(
                                        'DEL',
                                        style: TextStyle(
                                          fontSize: 9,
                                          fontWeight: FontWeight.bold,
                                          color: Colors.red,
                                        ),
                                      ),
                                    )
                                  else if (!supplier.isActive)
                                    Container(
                                      padding: const EdgeInsets.symmetric(
                                          horizontal: 6, vertical: 3),
                                      decoration: BoxDecoration(
                                        color: Colors.orange.withOpacity(0.15),
                                        borderRadius: BorderRadius.circular(3),
                                      ),
                                      child: const Text(
                                        'INA',
                                        style: TextStyle(
                                          fontSize: 9,
                                          fontWeight: FontWeight.bold,
                                          color: Colors.orange,
                                        ),
                                      ),
                                    ),
                                  const SizedBox(width: 8),
                                  // Botones de acción
                                  IconButton(
                                    icon: Icon(
                                      supplier.isActive
                                          ? Icons.toggle_on
                                          : Icons.toggle_off,
                                      size: 20,
                                      color: supplier.isActive
                                          ? Colors.green
                                          : Colors.grey,
                                    ),
                                    onPressed: () => _toggleActive(supplier),
                                    padding: const EdgeInsets.all(4),
                                    constraints: const BoxConstraints(),
                                    tooltip: supplier.isActive
                                        ? 'Desactivar'
                                        : 'Activar',
                                  ),
                                  IconButton(
                                    icon: const Icon(Icons.edit,
                                        size: 18, color: Colors.blue),
                                    onPressed: () => _showSupplierForm(supplier),
                                    padding: const EdgeInsets.all(4),
                                    constraints: const BoxConstraints(),
                                    tooltip: 'Editar',
                                  ),
                                  IconButton(
                                    icon: Icon(
                                      supplier.isDeleted
                                          ? Icons.restore_from_trash
                                          : Icons.delete,
                                      size: 18,
                                      color: supplier.isDeleted
                                          ? Colors.green
                                          : Colors.red,
                                    ),
                                    onPressed: () => _softDelete(supplier),
                                    padding: const EdgeInsets.all(4),
                                    constraints: const BoxConstraints(),
                                    tooltip: supplier.isDeleted
                                        ? 'Restaurar'
                                        : 'Eliminar',
                                  ),
                                ],
                              ),
                            ),
                          );
                        },
                      ),
                    ),
        ),
      ],
    );
  }
}

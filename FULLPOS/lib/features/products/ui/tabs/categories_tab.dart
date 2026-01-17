import 'package:flutter/material.dart';

import '../../data/categories_repository.dart';
import '../../models/category_model.dart';
import '../dialogs/category_form_dialog.dart';

/// Tab de Categorías
class CategoriesTab extends StatefulWidget {
  const CategoriesTab({super.key});

  @override
  State<CategoriesTab> createState() => _CategoriesTabState();
}

class _CategoriesTabState extends State<CategoriesTab> {
  final CategoriesRepository _categoriesRepo = CategoriesRepository();

  List<CategoryModel> _categories = [];
  bool _isLoading = false;

  @override
  void initState() {
    super.initState();
    _loadCategories();
  }

  Future<void> _loadCategories() async {
    setState(() => _isLoading = true);
    try {
      final categories = await _categoriesRepo.getAll(includeInactive: true);
      if (mounted) {
        setState(() => _categories = categories);
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error al cargar categorías: $e')),
        );
      }
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  Future<void> _showCategoryForm([CategoryModel? category]) async {
    final result = await showDialog<bool>(
      context: context,
      builder: (context) => CategoryFormDialog(category: category),
    );

    if (result == true) {
      _loadCategories();
    }
  }

  Future<void> _toggleActive(CategoryModel category) async {
    try {
      await _categoriesRepo.toggleActive(category.id!, !category.isActive);
      _loadCategories();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              category.isActive
                  ? 'Categoría desactivada'
                  : 'Categoría activada',
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

  Future<void> _softDelete(CategoryModel category) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(category.isDeleted
            ? 'Restaurar Categoría'
            : 'Eliminar Categoría'),
        content: Text(
          category.isDeleted
              ? '¿Desea restaurar "${category.name}"?'
              : '¿Está seguro de eliminar "${category.name}"?',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancelar'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(category.isDeleted ? 'Restaurar' : 'Eliminar'),
          ),
        ],
      ),
    );

    if (confirm == true) {
      try {
        if (category.isDeleted) {
          await _categoriesRepo.restore(category.id!);
        } else {
          await _categoriesRepo.softDelete(category.id!);
        }
        _loadCategories();
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(
                category.isDeleted
                    ? 'Categoría restaurada'
                    : 'Categoría eliminada',
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
        // Barra de acciones
        Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            children: [
              Text(
                '${_categories.length} categorías',
                style: const TextStyle(
                  fontSize: 16,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const Spacer(),
              ElevatedButton.icon(
                onPressed: () => _showCategoryForm(),
                icon: const Icon(Icons.add),
                label: const Text('Nueva Categoría'),
              ),
            ],
          ),
        ),

        // Lista de categorías
        Expanded(
          child: _isLoading
              ? const Center(child: CircularProgressIndicator())
              : _categories.isEmpty
                  ? Center(
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Icon(Icons.category_outlined,
                              size: 64, color: Colors.grey[400]),
                          const SizedBox(height: 16),
                          Text(
                            'No hay categorías registradas',
                            style: TextStyle(
                              fontSize: 18,
                              color: Colors.grey[600],
                            ),
                          ),
                          const SizedBox(height: 8),
                          ElevatedButton.icon(
                            onPressed: () => _showCategoryForm(),
                            icon: const Icon(Icons.add),
                            label: const Text('Crear Primera Categoría'),
                          ),
                        ],
                      ),
                    )
                  : RefreshIndicator(
                      onRefresh: _loadCategories,
                      child: ListView.builder(
                        itemCount: _categories.length,
                        itemBuilder: (context, index) {
                          final category = _categories[index];
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
                                        category.isActive && !category.isDeleted
                                            ? Colors.blue
                                            : Colors.grey,
                                    child: const Icon(Icons.category,
                                        color: Colors.white, size: 18),
                                  ),
                                  const SizedBox(width: 12),
                                  // Nombre
                                  Expanded(
                                    child: Text(
                                      category.name,
                                      style: TextStyle(
                                        fontSize: 14,
                                        fontWeight: FontWeight.w600,
                                        decoration: category.isDeleted
                                            ? TextDecoration.lineThrough
                                            : null,
                                      ),
                                      overflow: TextOverflow.ellipsis,
                                    ),
                                  ),
                                  const SizedBox(width: 8),
                                  // Badge de estado
                                  if (category.isDeleted)
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
                                  else if (!category.isActive)
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
                                      category.isActive
                                          ? Icons.toggle_on
                                          : Icons.toggle_off,
                                      size: 20,
                                      color: category.isActive
                                          ? Colors.green
                                          : Colors.grey,
                                    ),
                                    onPressed: () => _toggleActive(category),
                                    padding: const EdgeInsets.all(4),
                                    constraints: const BoxConstraints(),
                                    tooltip: category.isActive
                                        ? 'Desactivar'
                                        : 'Activar',
                                  ),
                                  IconButton(
                                    icon: const Icon(Icons.edit,
                                        size: 18, color: Colors.blue),
                                    onPressed: () => _showCategoryForm(category),
                                    padding: const EdgeInsets.all(4),
                                    constraints: const BoxConstraints(),
                                    tooltip: 'Editar',
                                  ),
                                  IconButton(
                                    icon: Icon(
                                      category.isDeleted
                                          ? Icons.restore_from_trash
                                          : Icons.delete,
                                      size: 18,
                                      color: category.isDeleted
                                          ? Colors.green
                                          : Colors.red,
                                    ),
                                    onPressed: () => _softDelete(category),
                                    padding: const EdgeInsets.all(4),
                                    constraints: const BoxConstraints(),
                                    tooltip: category.isDeleted
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

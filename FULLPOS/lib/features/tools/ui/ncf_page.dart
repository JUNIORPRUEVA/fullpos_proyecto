import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../../core/constants/app_colors.dart';
import '../../../core/constants/app_sizes.dart';
import '../../../core/errors/error_handler.dart';
import '../data/models/ncf_book_model.dart';
import '../data/ncf_repository.dart';
import 'dialogs/ncf_form_dialog.dart';

/// Página de gestión de NCF (Comprobantes Fiscales)
class NcfPage extends StatefulWidget {
  const NcfPage({super.key});

  @override
  State<NcfPage> createState() => _NcfPageState();
}

class _NcfPageState extends State<NcfPage> {
  final _ncfRepo = NcfRepository();
  List<NcfBookModel> _books = [];
  bool _isLoading = true;
  String _filter = 'all'; // all, active, inactive

  @override
  void initState() {
    super.initState();
    _loadBooks();
  }

  Future<void> _loadBooks() async {
    setState(() => _isLoading = true);

    try {
      final books = await _ncfRepo.getAll(
        activeOnly: _filter == 'active'
            ? true
            : _filter == 'inactive'
            ? false
            : null,
      );
      setState(() {
        _books = books;
        _isLoading = false;
      });
    } catch (e, st) {
      setState(() => _isLoading = false);
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: _loadBooks,
          module: 'tools/ncf/load',
        );
      }
    }
  }

  Future<void> _showForm([NcfBookModel? book]) async {
    final result = await showDialog<NcfBookModel>(
      context: context,
      builder: (context) => NcfFormDialog(ncfBook: book),
    );

    if (result == null) return;

    try {
      if (book == null) {
        await _ncfRepo.create(result);
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('NCF creado exitosamente'),
              backgroundColor: AppColors.success,
            ),
          );
        }
      } else {
        await _ncfRepo.update(result);
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('NCF actualizado exitosamente'),
              backgroundColor: AppColors.success,
            ),
          );
        }
      }
      _loadBooks();
    } catch (e, st) {
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: () => _showForm(book),
          module: 'tools/ncf/save',
        );
      }
    }
  }

  Future<void> _toggleActive(NcfBookModel book) async {
    try {
      await _ncfRepo.toggleActive(book.id!);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(book.isActive ? 'NCF desactivado' : 'NCF activado'),
            backgroundColor: AppColors.success,
          ),
        );
      }
      _loadBooks();
    } catch (e, st) {
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: () => _toggleActive(book),
          module: 'tools/ncf/toggle',
        );
      }
    }
  }

  Future<void> _delete(NcfBookModel book) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Confirmar Eliminación'),
        content: Text(
          '¿Eliminar el talonario ${book.type}${book.series ?? ''} '
          '(${book.fromN}-${book.toN})?\n\n'
          'Esta acción no se puede deshacer si ya se han emitido NCF de este talonario.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancelar'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(backgroundColor: AppColors.error),
            child: const Text('Eliminar'),
          ),
        ],
      ),
    );

    if (confirm != true) return;

    try {
      await _ncfRepo.delete(book.id!);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('NCF eliminado exitosamente'),
            backgroundColor: AppColors.success,
          ),
        );
      }
      _loadBooks();
    } catch (e, st) {
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: () => _delete(book),
          module: 'tools/ncf/delete',
        );
      }
    }
  }

  Color _getStatusColor(NcfBookModel book) {
    if (!book.isActive) return Colors.grey;
    if (book.isExhausted) return AppColors.error;
    if (book.expiresAt != null && book.expiresAt!.isBefore(DateTime.now())) {
      return Colors.orange;
    }
    return AppColors.success;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.bgLight,
      body: Column(
        children: [
          // Header
          Container(
            padding: const EdgeInsets.all(AppSizes.paddingL),
            decoration: BoxDecoration(
              color: Colors.white,
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.05),
                  blurRadius: 4,
                  offset: const Offset(0, 2),
                ),
              ],
            ),
            child: Column(
              children: [
                Row(
                  children: [
                    IconButton(
                      icon: Icon(Icons.arrow_back, color: AppColors.textDark),
                      onPressed: () => context.go('/tools'),
                    ),
                    const SizedBox(width: AppSizes.paddingM),
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: AppColors.teal.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Icon(
                        Icons.description,
                        size: 28,
                        color: AppColors.teal,
                      ),
                    ),
                    const SizedBox(width: AppSizes.paddingM),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'NCF (Comprobantes Fiscales)',
                            style: TextStyle(
                              fontSize: 20,
                              fontWeight: FontWeight.bold,
                              color: AppColors.textDark,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            'Gestión de talonarios de comprobantes',
                            style: TextStyle(
                              fontSize: 14,
                              color: AppColors.textDark.withOpacity(0.6),
                            ),
                          ),
                        ],
                      ),
                    ),
                    ElevatedButton.icon(
                      onPressed: () => _showForm(),
                      icon: const Icon(Icons.add),
                      label: const Text('Nuevo NCF'),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: AppColors.gold,
                        padding: const EdgeInsets.symmetric(
                          horizontal: AppSizes.paddingL,
                          vertical: AppSizes.paddingM,
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: AppSizes.paddingM),

                // Filtros
                Row(
                  children: [
                    _FilterChip(
                      label: 'Todos',
                      isSelected: _filter == 'all',
                      onTap: () {
                        setState(() => _filter = 'all');
                        _loadBooks();
                      },
                    ),
                    const SizedBox(width: AppSizes.paddingS),
                    _FilterChip(
                      label: 'Activos',
                      isSelected: _filter == 'active',
                      onTap: () {
                        setState(() => _filter = 'active');
                        _loadBooks();
                      },
                    ),
                    const SizedBox(width: AppSizes.paddingS),
                    _FilterChip(
                      label: 'Inactivos',
                      isSelected: _filter == 'inactive',
                      onTap: () {
                        setState(() => _filter = 'inactive');
                        _loadBooks();
                      },
                    ),
                  ],
                ),
              ],
            ),
          ),

          // Lista de NCF
          Expanded(
            child: _isLoading
                ? const Center(child: CircularProgressIndicator())
                : _books.isEmpty
                ? Center(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(
                          Icons.description_outlined,
                          size: 64,
                          color: AppColors.textDark.withOpacity(0.3),
                        ),
                        const SizedBox(height: AppSizes.paddingM),
                        Text(
                          'No hay talonarios de NCF',
                          style: TextStyle(
                            fontSize: 16,
                            color: AppColors.textDark.withOpacity(0.6),
                          ),
                        ),
                        const SizedBox(height: AppSizes.paddingS),
                        TextButton.icon(
                          onPressed: () => _showForm(),
                          icon: const Icon(Icons.add),
                          label: const Text('Crear primer NCF'),
                        ),
                      ],
                    ),
                  )
                : ListView.builder(
                    padding: const EdgeInsets.all(AppSizes.paddingL),
                    itemCount: _books.length,
                    itemBuilder: (context, index) {
                      final book = _books[index];
                      return _NcfCard(
                        book: book,
                        statusColor: _getStatusColor(book),
                        onEdit: () => _showForm(book),
                        onToggleActive: () => _toggleActive(book),
                        onDelete: () => _delete(book),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }
}

class _FilterChip extends StatelessWidget {
  final String label;
  final bool isSelected;
  final VoidCallback onTap;

  const _FilterChip({
    required this.label,
    required this.isSelected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(20),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        decoration: BoxDecoration(
          color: isSelected ? AppColors.teal : Colors.grey[100],
          borderRadius: BorderRadius.circular(20),
        ),
        child: Text(
          label,
          style: TextStyle(
            fontSize: 14,
            fontWeight: FontWeight.w600,
            color: isSelected ? Colors.white : AppColors.textDark,
          ),
        ),
      ),
    );
  }
}

class _NcfCard extends StatelessWidget {
  final NcfBookModel book;
  final Color statusColor;
  final VoidCallback onEdit;
  final VoidCallback onToggleActive;
  final VoidCallback onDelete;

  const _NcfCard({
    required this.book,
    required this.statusColor,
    required this.onEdit,
    required this.onToggleActive,
    required this.onDelete,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: AppSizes.paddingM),
      child: Padding(
        padding: const EdgeInsets.all(AppSizes.paddingM),
        child: Row(
          children: [
            // Indicador de estado
            Container(
              width: 4,
              height: 60,
              decoration: BoxDecoration(
                color: statusColor,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
            const SizedBox(width: AppSizes.paddingM),

            // Información principal
            Expanded(
              flex: 2,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 8,
                          vertical: 4,
                        ),
                        decoration: BoxDecoration(
                          color: AppColors.teal.withOpacity(0.1),
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: Text(
                          '${book.type}${book.series ?? ''}',
                          style: TextStyle(
                            fontSize: 12,
                            fontWeight: FontWeight.bold,
                            color: AppColors.teal,
                          ),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        NcfTypes.getDescription(book.type),
                        style: TextStyle(
                          fontSize: 14,
                          fontWeight: FontWeight.w600,
                          color: AppColors.textDark,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Rango: ${book.fromN} - ${book.toN}',
                    style: TextStyle(
                      fontSize: 13,
                      color: AppColors.textDark.withOpacity(0.7),
                    ),
                  ),
                ],
              ),
            ),

            // Próximo número
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Próximo',
                    style: TextStyle(
                      fontSize: 11,
                      color: AppColors.textDark.withOpacity(0.5),
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    book.nextN.toString(),
                    style: TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                      color: AppColors.textDark,
                    ),
                  ),
                ],
              ),
            ),

            // Disponibles
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Disponibles',
                    style: TextStyle(
                      fontSize: 11,
                      color: AppColors.textDark.withOpacity(0.5),
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    book.availableCount.toString(),
                    style: TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                      color: statusColor,
                    ),
                  ),
                ],
              ),
            ),

            // Estado
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 4,
                    ),
                    decoration: BoxDecoration(
                      color: statusColor.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: Text(
                      book.statusLabel,
                      style: TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                        color: statusColor,
                      ),
                    ),
                  ),
                ],
              ),
            ),

            // Acciones
            PopupMenuButton<String>(
              icon: Icon(Icons.more_vert, color: AppColors.textDark),
              onSelected: (value) {
                switch (value) {
                  case 'edit':
                    onEdit();
                    break;
                  case 'toggle':
                    onToggleActive();
                    break;
                  case 'delete':
                    onDelete();
                    break;
                }
              },
              itemBuilder: (context) => [
                const PopupMenuItem(
                  value: 'edit',
                  child: Row(
                    children: [
                      Icon(Icons.edit, size: 18),
                      SizedBox(width: 8),
                      Text('Editar'),
                    ],
                  ),
                ),
                PopupMenuItem(
                  value: 'toggle',
                  child: Row(
                    children: [
                      Icon(
                        book.isActive ? Icons.block : Icons.check_circle,
                        size: 18,
                      ),
                      const SizedBox(width: 8),
                      Text(book.isActive ? 'Desactivar' : 'Activar'),
                    ],
                  ),
                ),
                const PopupMenuItem(
                  value: 'delete',
                  child: Row(
                    children: [
                      Icon(Icons.delete, size: 18, color: AppColors.error),
                      SizedBox(width: 8),
                      Text(
                        'Eliminar',
                        style: TextStyle(color: AppColors.error),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

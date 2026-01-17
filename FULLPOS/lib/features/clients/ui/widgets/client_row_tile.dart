import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../../../../core/constants/app_colors.dart';
import '../../../../core/constants/app_sizes.dart';
import '../../data/client_model.dart';

/// Widget compacto para mostrar un cliente en una sola línea (tipo tabla)
class ClientRowTile extends StatelessWidget {
  final ClientModel client;
  final VoidCallback onViewDetails;
  final VoidCallback onEdit;
  final VoidCallback onToggleActive;
  final VoidCallback onToggleCredit;
  final VoidCallback onDelete;

  const ClientRowTile({
    super.key,
    required this.client,
    required this.onViewDetails,
    required this.onEdit,
    required this.onToggleActive,
    required this.onToggleCredit,
    required this.onDelete,
  });

  @override
  Widget build(BuildContext context) {
    final dateFormat = DateFormat('dd/MM/yyyy');
    final createdDate = dateFormat.format(
      DateTime.fromMillisecondsSinceEpoch(client.createdAtMs),
    );

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      elevation: 1,
      child: InkWell(
        onTap: onViewDetails,
        borderRadius: BorderRadius.circular(8),
        child: Padding(
          padding: const EdgeInsets.symmetric(
            horizontal: AppSizes.paddingM,
            vertical: 10,
          ),
          child: Row(
            children: [
              // Nombre (flex 2)
              Expanded(
                flex: 2,
                child: Row(
                  children: [
                    Container(
                      width: 8,
                      height: 8,
                      decoration: BoxDecoration(
                        color: client.isActive
                            ? AppColors.success
                            : Colors.grey,
                        shape: BoxShape.circle,
                      ),
                    ),
                    const SizedBox(width: AppSizes.paddingS),
                    Expanded(
                      child: Text(
                        client.nombre,
                        style: TextStyle(
                          fontSize: 14,
                          fontWeight: FontWeight.w600,
                          color: AppColors.textDark,
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(width: AppSizes.paddingM),

              // Teléfono (flex 1)
              Expanded(
                flex: 1,
                child: Text(
                  client.telefono?.isNotEmpty == true
                      ? client.telefono!
                      : '-',
                  style: TextStyle(
                    fontSize: 13,
                    color: AppColors.textDark.withOpacity(0.7),
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ),

              const SizedBox(width: AppSizes.paddingS),

              // RNC (flex 1)
              Expanded(
                flex: 1,
                child: Text(
                  client.rnc?.isNotEmpty == true ? client.rnc! : '-',
                  style: TextStyle(
                    fontSize: 13,
                    color: AppColors.textDark.withOpacity(0.7),
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ),

              const SizedBox(width: AppSizes.paddingS),

              // Cédula (flex 1)
              Expanded(
                flex: 1,
                child: Text(
                  client.cedula?.isNotEmpty == true ? client.cedula! : '-',
                  style: TextStyle(
                    fontSize: 13,
                    color: AppColors.textDark.withOpacity(0.7),
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ),

              const SizedBox(width: AppSizes.paddingS),

              // Estado (activo/inactivo)
              Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 8,
                  vertical: 4,
                ),
                decoration: BoxDecoration(
                  color: client.isActive
                      ? AppColors.success.withOpacity(0.1)
                      : Colors.grey.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Text(
                  client.isActive ? 'Activo' : 'Inactivo',
                  style: TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                    color: client.isActive ? AppColors.success : Colors.grey,
                  ),
                ),
              ),

              const SizedBox(width: AppSizes.paddingS),

              // Crédito
              Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 8,
                  vertical: 4,
                ),
                decoration: BoxDecoration(
                  color: client.hasCredit
                      ? AppColors.gold.withOpacity(0.1)
                      : Colors.transparent,
                  borderRadius: BorderRadius.circular(4),
                  border: Border.all(
                    color: client.hasCredit
                        ? AppColors.gold
                        : Colors.grey.withOpacity(0.3),
                  ),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(
                      client.hasCredit ? Icons.credit_card : Icons.block,
                      size: 14,
                      color: client.hasCredit ? AppColors.gold : Colors.grey,
                    ),
                    const SizedBox(width: 4),
                    Text(
                      client.hasCredit ? 'Crédito' : 'Sin crédito',
                      style: TextStyle(
                        fontSize: 11,
                        fontWeight: FontWeight.w600,
                        color: client.hasCredit ? AppColors.gold : Colors.grey,
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(width: AppSizes.paddingS),

              // Fecha de creación
              SizedBox(
                width: 80,
                child: Text(
                  createdDate,
                  style: TextStyle(
                    fontSize: 12,
                    color: AppColors.textDark.withOpacity(0.5),
                  ),
                  textAlign: TextAlign.center,
                ),
              ),

              const SizedBox(width: AppSizes.paddingS),

              // Menú de acciones
              PopupMenuButton<String>(
                icon: Icon(
                  Icons.more_vert,
                  color: AppColors.textDark,
                  size: 20,
                ),
                padding: EdgeInsets.zero,
                onSelected: (value) {
                  switch (value) {
                    case 'edit':
                      onEdit();
                      break;
                    case 'toggle_active':
                      onToggleActive();
                      break;
                    case 'toggle_credit':
                      onToggleCredit();
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
                        Icon(Icons.edit, size: 16),
                        SizedBox(width: 8),
                        Text('Editar', style: TextStyle(fontSize: 13)),
                      ],
                    ),
                  ),
                  PopupMenuItem(
                    value: 'toggle_active',
                    child: Row(
                      children: [
                        Icon(
                          client.isActive ? Icons.block : Icons.check_circle,
                          size: 16,
                        ),
                        const SizedBox(width: 8),
                        Text(
                          client.isActive ? 'Desactivar' : 'Activar',
                          style: const TextStyle(fontSize: 13),
                        ),
                      ],
                    ),
                  ),
                  PopupMenuItem(
                    value: 'toggle_credit',
                    child: Row(
                      children: [
                        Icon(
                          client.hasCredit
                              ? Icons.credit_card_off
                              : Icons.credit_card,
                          size: 16,
                        ),
                        const SizedBox(width: 8),
                        Text(
                          client.hasCredit
                              ? 'Quitar Crédito'
                              : 'Dar Crédito',
                          style: const TextStyle(fontSize: 13),
                        ),
                      ],
                    ),
                  ),
                  const PopupMenuDivider(),
                  const PopupMenuItem(
                    value: 'delete',
                    child: Row(
                      children: [
                        Icon(Icons.delete, size: 16, color: AppColors.error),
                        SizedBox(width: 8),
                        Text(
                          'Eliminar',
                          style: TextStyle(
                            fontSize: 13,
                            color: AppColors.error,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}

import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../../data/quote_model.dart';

/// Widget que renderiza una cotización en una fila compacta (estilo tabla)
class CompactQuoteRow extends StatelessWidget {
  final QuoteDetailDto quoteDetail;
  final VoidCallback onTap;
  final VoidCallback onSell;
  final VoidCallback onWhatsApp;
  final VoidCallback onPdf;
  final VoidCallback onDuplicate;
  final VoidCallback onDelete;
  final VoidCallback? onConvertToTicket;
  final VoidCallback? onDownload;

  const CompactQuoteRow({
    required this.quoteDetail,
    required this.onTap,
    required this.onSell,
    required this.onWhatsApp,
    required this.onPdf,
    required this.onDuplicate,
    required this.onDelete,
    this.onConvertToTicket,
    this.onDownload,
  });

  @override
  Widget build(BuildContext context) {
    final quote = quoteDetail.quote;
    final dateFormatter = DateFormat('dd/MM/yy HH:mm');
    final createdDate = dateFormatter.format(
      DateTime.fromMillisecondsSinceEpoch(quote.createdAtMs),
    );

    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        child: Container(
          height: 60,
          decoration: BoxDecoration(
            border: Border(
              bottom: BorderSide(color: Colors.grey.shade200, width: 1),
            ),
          ),
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
          child: Row(
            children: [
              // CÓDIGO
              SizedBox(
                width: 100,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Text(
                      'COT-${quote.id!.toString().padLeft(5, '0')}',
                      style: const TextStyle(
                        fontSize: 13,
                        fontWeight: FontWeight.bold,
                        color: Colors.teal,
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(width: 8),

              // CLIENTE (expandible, con prioridad)
              Expanded(
                flex: 4,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Text(
                      quoteDetail.clientName,
                      style: const TextStyle(
                        fontSize: 13,
                        fontWeight: FontWeight.w600,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    if ((quoteDetail.clientPhone ?? '').trim().isNotEmpty)
                      Text(
                        quoteDetail.clientPhone!,
                        style: TextStyle(
                          fontSize: 11,
                          color: Colors.grey.shade600,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                  ],
                ),
              ),

              const SizedBox(width: 8),

              // FECHA + ESTADO
              Flexible(
                flex: 2,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Text(
                      createdDate,
                      style: TextStyle(
                        fontSize: 11,
                        color: Colors.grey.shade600,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    _buildStatusChip(quote.status),
                  ],
                ),
              ),

              const SizedBox(width: 8),

              // TOTAL
              SizedBox(
                width: 100,
                child: Text(
                  '\$${quote.total.toStringAsFixed(2)}',
                  style: const TextStyle(
                    fontSize: 13,
                    fontWeight: FontWeight.bold,
                    color: Colors.teal,
                  ),
                  textAlign: TextAlign.right,
                ),
              ),

              const SizedBox(width: 8),

              // ACCIONES (flexible, escalable)
              Flexible(
                flex: 2,
                child: Align(
                  alignment: Alignment.centerRight,
                  child: SingleChildScrollView(
                    scrollDirection: Axis.horizontal,
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        if (quote.status != 'CONVERTED' &&
                            quote.status != 'CANCELLED' &&
                            quote.status != 'PASSED_TO_TICKET')
                          _buildIconButton(
                            icon: Icons.point_of_sale,
                            tooltip: 'Vender',
                            color: Colors.green,
                            onPressed: onSell,
                          ),
                        if (quote.status != 'CONVERTED' &&
                            quote.status != 'CANCELLED' &&
                            quote.status != 'PASSED_TO_TICKET' &&
                            onConvertToTicket != null)
                          _buildIconButton(
                            icon: Icons.receipt_long,
                            tooltip: 'Pasar a ticket',
                            color: Colors.orange,
                            onPressed: onConvertToTicket!,
                          ),
                        _buildIconButton(
                          icon: Icons.chat,
                          tooltip: 'WhatsApp',
                          color: Colors.green.shade700,
                          onPressed: onWhatsApp,
                        ),
                        _buildIconButton(
                          icon: Icons.picture_as_pdf,
                          tooltip: 'PDF',
                          color: Colors.red.shade700,
                          onPressed: onPdf,
                        ),
                        if (onDownload != null)
                          _buildIconButton(
                            icon: Icons.download,
                            tooltip: 'Descargar',
                            color: Colors.purple,
                            onPressed: onDownload!,
                          ),
                        if (quote.status != 'CONVERTED' &&
                            quote.status != 'CANCELLED')
                          _buildIconButton(
                            icon: Icons.copy,
                            tooltip: 'Duplicar',
                            color: Colors.blue,
                            onPressed: onDuplicate,
                          ),
                        _buildIconButton(
                          icon: Icons.delete_outline,
                          tooltip: 'Eliminar',
                          color: Colors.red,
                          onPressed: onDelete,
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildStatusChip(String status) {
    Color color;
    String label;

    switch (status) {
      case 'OPEN':
        color = Colors.blue;
        label = 'Abierta';
        break;
      case 'SENT':
        color = Colors.orange;
        label = 'Enviada';
        break;
      case 'CONVERTED':
        color = Colors.green;
        label = 'Vendida';
        break;
      case 'CANCELLED':
        color = Colors.red;
        label = 'Cancelada';
        break;
      default:
        color = Colors.grey;
        label = status;
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withOpacity(0.15),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: color, width: 1),
      ),
      child: Text(
        label,
        style: TextStyle(
          color: color,
          fontWeight: FontWeight.w600,
          fontSize: 11,
        ),
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),
    );
  }

  Widget _buildIconButton({
    required IconData icon,
    required String tooltip,
    required Color color,
    required VoidCallback onPressed,
  }) {
    return Tooltip(
      message: tooltip,
      child: SizedBox(
        width: 36,
        height: 36,
        child: IconButton(
          icon: Icon(icon, size: 18, color: color),
          onPressed: onPressed,
          padding: EdgeInsets.zero,
          constraints: const BoxConstraints.tightFor(width: 36, height: 36),
          visualDensity: VisualDensity.compact,
          tooltip: '',
        ),
      ),
    );
  }
}

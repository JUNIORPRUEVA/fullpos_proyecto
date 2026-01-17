import 'package:flutter/material.dart';
import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../../data/quote_model.dart';

/// Tarjeta compacta y elevada para listar cotizaciones
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
    super.key,
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
    final createdDate = DateFormat('dd/MM/yy HH:mm').format(
      DateTime.fromMillisecondsSinceEpoch(quote.createdAtMs),
    );

    return Material(
      color: Colors.white,
      elevation: 2,
      shadowColor: Colors.black26,
      borderRadius: BorderRadius.circular(8),
      child: InkWell(
        borderRadius: BorderRadius.circular(8),
        onTap: onTap,
        child: Container(
          margin: const EdgeInsets.only(bottom: 6),
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: Colors.grey.shade200, width: 1),
          ),
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
                      color: Colors.teal.withOpacity(0.08),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Text(
                      'COT-${quote.id!.toString().padLeft(5, '0')}',
                      style: const TextStyle(
                        fontSize: 11,
                        fontWeight: FontWeight.w700,
                        color: Colors.teal,
                        letterSpacing: 0.2,
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  _buildStatusChip(quote.status),
                  const Spacer(),
                  Row(
                    children: [
                      const Icon(
                        Icons.schedule,
                        size: 13,
                        color: Colors.grey,
                      ),
                      const SizedBox(width: 4),
                      Text(
                        createdDate,
                        style: TextStyle(
                          fontSize: 10,
                          color: Colors.grey.shade600,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
              const SizedBox(height: 6),
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          quoteDetail.clientName,
                          style: const TextStyle(
                            fontSize: 13,
                            fontWeight: FontWeight.w700,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                        if ((quoteDetail.clientPhone ?? '')
                            .trim()
                            .isNotEmpty)
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
                  const SizedBox(width: 10),
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.end,
                    children: [
                      const Text(
                        'Total',
                        style: TextStyle(
                          fontSize: 10,
                          color: Colors.grey,
                        ),
                      ),
                      Text(
                        '\$${quote.total.toStringAsFixed(2)}',
                        style: const TextStyle(
                          fontSize: 15,
                          fontWeight: FontWeight.bold,
                          color: Colors.teal,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
              const SizedBox(height: 6),
              SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: Row(
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
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: color, width: 1),
      ),
      child: Text(
        label,
        style: TextStyle(
          color: color,
          fontWeight: FontWeight.w700,
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
      child: Container(
        margin: const EdgeInsets.only(right: 4),
        decoration: BoxDecoration(
          color: color.withOpacity(0.08),
          borderRadius: BorderRadius.circular(8),
        ),
        child: IconButton(
          icon: Icon(icon, size: 16, color: color),
          onPressed: onPressed,
          padding: const EdgeInsets.all(6),
          constraints: const BoxConstraints(),
          visualDensity: VisualDensity.compact,
          tooltip: '',
        ),
      ),
    );
  }
}

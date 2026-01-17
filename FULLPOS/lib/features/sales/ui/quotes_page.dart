import 'dart:io';
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';
import 'package:path_provider/path_provider.dart';
import 'package:printing/printing.dart';
import '../data/quotes_repository.dart';
import '../data/quote_model.dart';
import '../data/quote_to_ticket_converter.dart';
import '../data/sales_repository.dart';
import '../data/settings_repository.dart';
import '../data/tickets_repository.dart';
import '../data/ticket_model.dart';
import '../../../core/printing/unified_ticket_printer.dart';
import '../../../core/printing/quote_printer.dart';
import '../../../core/session/session_manager.dart';
import '../../../core/errors/error_handler.dart';
import '../../../core/errors/app_exception.dart';
import '../../settings/data/printer_settings_repository.dart';
import 'widgets/compact_quote_row.dart';
import 'widgets/quotes_filter_bar.dart';
import 'utils/quotes_filter_util.dart';

class QuotesPage extends StatefulWidget {
  const QuotesPage({super.key});

  @override
  State<QuotesPage> createState() => _QuotesPageState();
}

class _QuotesPageState extends State<QuotesPage> {
  List<QuoteDetailDto> _quotes = [];
  List<QuoteDetailDto> _filteredQuotes = [];
  bool _isLoading = false;
  late QuotesFilterConfig _filterConfig;
  late SearchDebouncer _searchDebouncer;

  @override
  void initState() {
    super.initState();
    _filterConfig = const QuotesFilterConfig();
    _searchDebouncer = SearchDebouncer(
      duration: const Duration(milliseconds: 300),
      onDebounce: (_) {
        _applyFilters();
      },
    );
    _loadQuotes();
  }

  @override
  void dispose() {
    _searchDebouncer.dispose();
    super.dispose();
  }

  Future<void> _loadQuotes() async {
    setState(() => _isLoading = true);
    try {
      final quotes = await QuotesRepository().listQuotes();
      setState(() {
        _quotes = quotes;
        _isLoading = false;
        _applyFilters();
      });
    } catch (e, st) {
      setState(() => _isLoading = false);
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: _loadQuotes,
          module: 'sales/quotes/load',
        );
      }
    }
  }

  void _applyFilters() {
    setState(() {
      _filteredQuotes = QuotesFilterUtil.applyFilters(_quotes, _filterConfig);
    });
  }

  void _onFilterChanged(QuotesFilterConfig newConfig) {
    setState(() {
      _filterConfig = newConfig;
    });
    _searchDebouncer(_filterConfig.searchText);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Cotizaciones'),
        backgroundColor: Colors.teal,
        elevation: 0,
      ),
      body: Column(
        children: [
          // Barra de filtros
          QuotesFilterBar(
            initialConfig: _filterConfig,
            onFilterChanged: _onFilterChanged,
          ),

          // Lista de cotizaciones
          Expanded(
            child: _isLoading
                ? const Center(child: CircularProgressIndicator())
                : _filteredQuotes.isEmpty
                ? Center(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(
                          Icons.description_outlined,
                          size: 80,
                          color: Colors.grey.shade300,
                        ),
                        const SizedBox(height: 16),
                        Text(
                          _quotes.isEmpty
                              ? 'No hay cotizaciones'
                              : 'No hay resultados',
                          style: TextStyle(
                            fontSize: 18,
                            color: Colors.grey.shade600,
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                        const SizedBox(height: 8),
                        Text(
                          _quotes.isEmpty
                              ? 'Crea una cotización desde la página de ventas'
                              : 'Ajusta los filtros e intenta de nuevo',
                          style: TextStyle(
                            fontSize: 14,
                            color: Colors.grey.shade400,
                          ),
                        ),
                      ],
                    ),
                  )
                : ListView.builder(
                    padding: const EdgeInsets.only(top: 8),
                    itemCount: _filteredQuotes.length,
                    itemBuilder: (context, index) {
                      final quoteDetail = _filteredQuotes[index];
                      return CompactQuoteRow(
                        quoteDetail: quoteDetail,
                        onTap: () => _showQuoteDetails(quoteDetail),
                        onSell: () => _convertToSale(quoteDetail),
                        onWhatsApp: () => _shareWhatsApp(quoteDetail),
                        onPdf: () => _viewPDF(quoteDetail),
                        onDownload: () => _downloadPDF(quoteDetail),
                        onDuplicate: () => _duplicateQuote(quoteDetail),
                        onDelete: () => _deleteQuote(quoteDetail),
                        onConvertToTicket: () => _convertToTicket(quoteDetail),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }

  String _getStatusLabel(String status) {
    switch (status) {
      case 'OPEN':
        return 'Abiertas';
      case 'SENT':
        return 'Enviadas';
      case 'CONVERTED':
        return 'Vendidas';
      case 'CANCELLED':
        return 'Canceladas';
      case 'TODOS':
        return 'Todas';
      default:
        return status;
    }
  }

  Future<void> _showQuoteDetails(QuoteDetailDto quoteDetail) async {
    final changed = await showDialog<bool>(
      context: context,
      builder: (context) => _QuoteDetailsDialog(quoteDetail: quoteDetail),
    );

    // Si algo cambió en el diálogo, recargar la lista
    if (changed == true && mounted) {
      await _loadQuotes();
    }
  }

  Future<void> _convertToSale(QuoteDetailDto quoteDetail) async {
    // Validación: Verificar si la cotización ya fue convertida
    if (quoteDetail.quote.status == 'CONVERTED') {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('❌ Esta cotización ya fue convertida a venta'),
            backgroundColor: Colors.orange,
            duration: Duration(seconds: 3),
          ),
        );
      }
      return;
    }

    // Validación: Verificar que hay items en la cotización
    if (quoteDetail.items.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text(
              '❌ No se puede convertir una cotización sin productos',
            ),
            backgroundColor: Colors.red,
            duration: Duration(seconds: 3),
          ),
        );
      }
      return;
    }

    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        icon: const Icon(Icons.point_of_sale, color: Colors.green, size: 48),
        title: const Text('CONVERTIR A VENTA'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              '¿Convertir la cotización COT-${quoteDetail.quote.id!.toString().padLeft(5, '0')} en venta?',
            ),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.amber.shade50,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: Colors.amber),
              ),
              child: const Row(
                children: [
                  Icon(Icons.warning, color: Colors.amber),
                  SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'Esto descontará el stock de los productos automáticamente',
                      style: TextStyle(fontSize: 13),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('CANCELAR'),
          ),
          ElevatedButton.icon(
            onPressed: () => Navigator.pop(context, true),
            icon: const Icon(Icons.check),
            label: const Text('CONVERTIR A VENTA'),
            style: ElevatedButton.styleFrom(backgroundColor: Colors.green),
          ),
        ],
      ),
    );

    if (confirm == true) {
      try {
        final quote = quoteDetail.quote;

        // Generar código de venta
        final localCode = await SalesRepository.generateNextLocalCode('sale');

        // Convertir items de cotización a mapas para createSale
        final saleItems = quoteDetail.items
            .map(
              (item) => <String, dynamic>{
                'product_id': item.productId,
                'code': item.productCode ?? 'N/A',
                'description': item.description,
                'qty': item.qty,
                'price': item.price,
                'cost': item.cost,
                'discount': item.discountLine,
              },
            )
            .toList();

        // Crear la venta (atómica). Si el stock quedaría en negativo, pedir confirmación.
        int saleId;
        try {
          saleId = await SalesRepository.createSale(
            localCode: localCode,
            kind: 'sale',
            items: saleItems,
            itbisEnabled: quote.itbisEnabled,
            itbisRate: quote.itbisRate,
            discountTotal: quote.discountTotal,
            paymentMethod: 'cash', // Por defecto efectivo
            customerId: quote.clientId,
            customerName: quoteDetail.clientName,
            customerPhone: quoteDetail.clientPhone,
            customerRnc: quoteDetail.clientRnc,
            paidAmount: quote.total,
            changeAmount: 0,
          );
        } on AppException catch (e, st) {
          if (e.code != 'stock_negative') {
            await ErrorHandler.instance.handle(
              e,
              stackTrace: st,
              context: context,
              module: 'quotes',
            );
            return;
          }

          final proceed = await showDialog<bool>(
            context: context,
            builder: (context) => AlertDialog(
              title: const Text('Stock insuficiente'),
              content: Text(e.messageUser),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context, false),
                  child: const Text('CANCELAR'),
                ),
                ElevatedButton(
                  onPressed: () => Navigator.pop(context, true),
                  child: const Text('CONTINUAR'),
                ),
              ],
            ),
          );
          if (proceed != true) return;

          final retry = await ErrorHandler.instance.runSafe<int>(
            () => SalesRepository.createSale(
              localCode: localCode,
              kind: 'sale',
              items: saleItems,
              allowNegativeStock: true,
              itbisEnabled: quote.itbisEnabled,
              itbisRate: quote.itbisRate,
              discountTotal: quote.discountTotal,
              paymentMethod: 'cash',
              customerId: quote.clientId,
              customerName: quoteDetail.clientName,
              customerPhone: quoteDetail.clientPhone,
              customerRnc: quoteDetail.clientRnc,
              paidAmount: quote.total,
              changeAmount: 0,
            ),
            context: context,
            module: 'quotes',
          );
          if (retry == null) return;
          saleId = retry;
        }

        // Actualizar estado de la cotización
        await QuotesRepository().updateQuoteStatus(quote.id!, 'CONVERTED');

        await _loadQuotes();

        if (mounted) {
          // Preguntar si desea imprimir
          final printTicket = await showDialog<bool>(
            context: context,
            builder: (context) => AlertDialog(
              icon: const Icon(
                Icons.check_circle,
                color: Colors.green,
                size: 48,
              ),
              title: const Text('¡VENTA CREADA!'),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text('Código: $localCode'),
                  Text('Total: \$${quote.total.toStringAsFixed(2)}'),
                  const SizedBox(height: 16),
                  const Text('¿Desea imprimir el ticket?'),
                ],
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context, false),
                  child: const Text('NO'),
                ),
                ElevatedButton.icon(
                  onPressed: () => Navigator.pop(context, true),
                  icon: const Icon(Icons.print),
                  label: const Text('IMPRIMIR'),
                ),
              ],
            ),
          );

          if (printTicket == true) {
            final sale = await SalesRepository.getSaleById(saleId);
            final items = await SalesRepository.getItemsBySaleId(saleId);
            if (sale != null) {
              // Obtener nombre del cajero desde la sesión
              final cashierName =
                  await SessionManager.displayName() ?? 'Cajero';
              await UnifiedTicketPrinter.reprintSale(
                sale: sale,
                items: items,
                cashierName: cashierName,
              );
            }
          }

          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('✅ Venta creada: $localCode'),
              backgroundColor: Colors.green,
            ),
          );
        }
      } catch (e, st) {
        if (mounted) {
          await ErrorHandler.instance.handle(
            e,
            stackTrace: st,
            context: context,
            onRetry: () => _convertToSale(quoteDetail),
            module: 'sales/quotes/convert',
          );
        }
      }
    }
  }

  Future<void> _cancelQuote(QuoteDetailDto quoteDetail) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        icon: const Icon(Icons.cancel, color: Colors.red, size: 48),
        title: const Text('CANCELAR COTIZACIÓN'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              '¿Está seguro de cancelar la cotización COT-${quoteDetail.quote.id!.toString().padLeft(5, '0')}?',
            ),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.red.shade50,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Text(
                'Total: \$${quoteDetail.quote.total.toStringAsFixed(2)}',
                style: const TextStyle(fontWeight: FontWeight.bold),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('NO'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(backgroundColor: Colors.red),
            child: const Text('SÍ, CANCELAR'),
          ),
        ],
      ),
    );

    if (confirm == true) {
      try {
        await QuotesRepository().updateQuoteStatus(
          quoteDetail.quote.id!,
          'CANCELLED',
        );
        await _loadQuotes();

        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('✅ Cotización cancelada'),
              backgroundColor: Colors.green,
            ),
          );
        }
      } catch (e, st) {
        if (mounted) {
          await ErrorHandler.instance.handle(
            e,
            stackTrace: st,
            context: context,
            onRetry: () => _cancelQuote(quoteDetail),
            module: 'sales/quotes/cancel',
          );
        }
      }
    }
  }

  Future<void> _shareWhatsApp(QuoteDetailDto quoteDetail) async {
    try {
      final business = await SettingsRepository.getBusinessInfo();

      // Generar PDF
      final pdfData = await QuotePrinter.generatePdf(
        quote: quoteDetail.quote,
        items: quoteDetail.items,
        clientName: quoteDetail.clientName,
        clientPhone: quoteDetail.clientPhone,
        clientRnc: quoteDetail.clientRnc,
        business: business,
        validDays: 15,
      );

      // Compartir
      await Printing.sharePdf(
        bytes: pdfData,
        filename: 'cotizacion_${quoteDetail.quote.id}.pdf',
      );
    } catch (e, st) {
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: () => _shareWhatsApp(quoteDetail),
          module: 'sales/quotes/share',
        );
      }
    }
  }

  Future<void> _viewPDF(QuoteDetailDto quoteDetail) async {
    try {
      final business = await SettingsRepository.getBusinessInfo();

      if (mounted) {
        await QuotePrinter.showPreview(
          context: context,
          quote: quoteDetail.quote,
          items: quoteDetail.items,
          clientName: quoteDetail.clientName,
          clientPhone: quoteDetail.clientPhone,
          clientRnc: quoteDetail.clientRnc,
          business: business,
          validDays: 15,
        );
      }
    } catch (e, st) {
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: () => _viewPDF(quoteDetail),
          module: 'sales/quotes/pdf_preview',
        );
      }
    }
  }

  /// Descargar cotización como PDF a la carpeta de Descargas
  Future<void> _downloadPDF(QuoteDetailDto quoteDetail) async {
    try {
      // Mostrar indicador de carga
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Row(
              children: [
                SizedBox(
                  width: 20,
                  height: 20,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: Colors.white,
                  ),
                ),
                SizedBox(width: 12),
                Text('Generando PDF...'),
              ],
            ),
            duration: Duration(seconds: 1),
            backgroundColor: Colors.purple,
          ),
        );
      }

      final business = await SettingsRepository.getBusinessInfo();

      // Generar PDF
      final pdfData = await QuotePrinter.generatePdf(
        quote: quoteDetail.quote,
        items: quoteDetail.items,
        clientName: quoteDetail.clientName,
        clientPhone: quoteDetail.clientPhone,
        clientRnc: quoteDetail.clientRnc,
        business: business,
        validDays: 15,
      );

      // Obtener carpeta de descargas
      Directory? downloadDir;
      if (Platform.isWindows) {
        // En Windows, usar la carpeta de Descargas del usuario
        final userProfile = Platform.environment['USERPROFILE'];
        if (userProfile != null) {
          downloadDir = Directory('$userProfile\\Downloads');
        }
      } else if (Platform.isAndroid) {
        downloadDir = Directory('/storage/emulated/0/Download');
      } else {
        downloadDir = await getDownloadsDirectory();
      }

      // Fallback a documentos si no existe Descargas
      downloadDir ??= await getApplicationDocumentsDirectory();

      // Crear nombre de archivo único con fecha
      final now = DateTime.now();
      final dateStr = DateFormat('yyyyMMdd_HHmmss').format(now);
      final quoteCode =
          'COT-${quoteDetail.quote.id!.toString().padLeft(5, '0')}';
      final fileName = '${quoteCode}_$dateStr.pdf';
      final filePath = '${downloadDir.path}${Platform.pathSeparator}$fileName';

      // Guardar archivo
      final file = File(filePath);
      await file.writeAsBytes(pdfData);

      if (mounted) {
        ScaffoldMessenger.of(context).hideCurrentSnackBar();
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Row(
              children: [
                const Icon(Icons.check_circle, color: Colors.white),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        '✅ PDF descargado correctamente',
                        style: TextStyle(fontWeight: FontWeight.bold),
                      ),
                      Text(fileName, style: const TextStyle(fontSize: 12)),
                    ],
                  ),
                ),
              ],
            ),
            backgroundColor: Colors.green,
            duration: const Duration(seconds: 4),
            action: SnackBarAction(
              label: 'ABRIR',
              textColor: Colors.white,
              onPressed: () async {
                // Intentar abrir el archivo
                try {
                  if (Platform.isWindows) {
                    await Process.run('explorer.exe', [filePath]);
                  }
                } catch (_) {}
              },
            ),
          ),
        );
      }
    } catch (e, st) {
      if (mounted) {
        ScaffoldMessenger.of(context).hideCurrentSnackBar();
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: () => _downloadPDF(quoteDetail),
          module: 'sales/quotes/pdf_download',
        );
      }
    }
  }

  /// Duplicar una cotización
  Future<void> _duplicateQuote(QuoteDetailDto quoteDetail) async {
    // Validación: Verificar que hay items en la cotización
    if (quoteDetail.items.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text(
              '❌ No se puede duplicar una cotización sin productos',
            ),
            backgroundColor: Colors.red,
            duration: Duration(seconds: 3),
          ),
        );
      }
      return;
    }

    // Validación: Verificar que todos los items tengan precio válido
    final hasInvalidPrices = quoteDetail.items.any((item) => item.price <= 0);
    if (hasInvalidPrices) {
      if (mounted) {
        showDialog(
          context: context,
          builder: (context) => AlertDialog(
            icon: const Icon(Icons.warning, color: Colors.amber, size: 48),
            title: const Text('ADVERTENCIA'),
            content: const Text(
              'Algunos productos en esta cotización tienen precio cero o inválido. Se duplicarán pero verifique los precios.',
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context),
                child: const Text('OK'),
              ),
            ],
          ),
        );
      }
    }

    try {
      debugPrint('📋 Duplicando cotización ID: ${quoteDetail.quote.id}...');
      await QuotesRepository().duplicateQuote(quoteDetail.quote.id!);
      if (!mounted) return;

      debugPrint('✅ Cotización duplicada. Recargando lista...');
      // ✅ IMPORTANTE: Recargar la lista ANTES de cerrar
      await _loadQuotes();

      if (!mounted) return;

      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('✅ Cotización duplicada exitosamente'),
          backgroundColor: Colors.green,
        ),
      );
    } catch (e, stack) {
      debugPrint('❌ Error al duplicar cotización: $e');
      debugPrint('Stack trace: $stack');
      if (!mounted) return;
      await ErrorHandler.instance.handle(
        e,
        stackTrace: stack,
        context: context,
        onRetry: () => _duplicateQuote(quoteDetail),
        module: 'sales/quotes/duplicate',
      );
    }
  }

  /// Eliminar una cotización con confirmación
  Future<void> _deleteQuote(QuoteDetailDto quoteDetail) async {
    // Advertencia especial si la cotización fue convertida
    final isConverted = quoteDetail.quote.status == 'CONVERTED';

    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Eliminar Cotización'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              '¿Está seguro que desea eliminar la cotización #${quoteDetail.quote.id}?\n'
              'Esta acción no se puede deshacer.',
            ),
            if (isConverted) ...[
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.red.shade50,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: Colors.red),
                ),
                child: const Row(
                  children: [
                    Icon(Icons.error, color: Colors.red),
                    SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'Esta cotización ya fue convertida a venta. Solo se eliminará el registro.',
                        style: TextStyle(fontSize: 12, color: Colors.red),
                      ),
                    ),
                  ],
                ),
              ),
            ] else ...[
              const SizedBox(height: 8),
            ],
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancelar'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Eliminar', style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );

    if (confirm != true) return;

    try {
      debugPrint('🗑️  Eliminando cotización ID: ${quoteDetail.quote.id}...');
      await QuotesRepository().deleteQuote(quoteDetail.quote.id!);
      if (!mounted) return;

      debugPrint('✅ Cotización eliminada. Recargando lista...');
      // ✅ IMPORTANTE: Recargar la lista ANTES de cualquier navegación
      await _loadQuotes();

      if (!mounted) return;

      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('✅ Cotización eliminada'),
          backgroundColor: Colors.red,
        ),
      );
    } catch (e, stack) {
      debugPrint('❌ Error al eliminar cotización: $e');
      debugPrint('Stack trace: $stack');
      if (!mounted) return;
      await ErrorHandler.instance.handle(
        e,
        stackTrace: stack,
        context: context,
        onRetry: () => _deleteQuote(quoteDetail),
        module: 'sales/quotes/delete',
      );
    }
  }

  /// Pasar cotización a ticket pendiente (caja)
  Future<void> _convertToTicket(QuoteDetailDto quoteDetail) async {
    try {
      final quote = quoteDetail.quote;

      debugPrint(
        '🎫 [UI] Iniciando conversión de cotización #${quote.id} a ticket pendiente',
      );

      if (quote.status == 'PASSED_TO_TICKET') {
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text(
              '⚠️ Esta cotización ya fue convertida a ticket pendiente',
            ),
            backgroundColor: Colors.orange,
          ),
        );
        return;
      }

      // Usar el nuevo conversor transaccional
      final ticketId = await QuoteToTicketConverter.convertQuoteToTicket(
        quoteId: quote.id!,
        userId: quote.userId,
      );

      if (!mounted) return;

      debugPrint(
        '🎉 [UI] Cotización convertida exitosamente a ticket #$ticketId',
      );

      // ✅ IMPORTANTE: Recargar la lista ANTES de mostrar mensajes
      await _loadQuotes();

      if (!mounted) return;

      // Mostrar mensaje de éxito
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            '✅ Cotización convertida a ticket pendiente #$ticketId',
          ),
          backgroundColor: Colors.green,
          duration: const Duration(seconds: 3),
        ),
      );

      // Navegar a Ventas después de 1 segundo para que vea el mensaje
      await Future.delayed(const Duration(seconds: 1));
      if (!mounted) return;
      context.go('/sales');
    } catch (e, stack) {
      debugPrint('❌ [UI] Error al convertir a ticket: $e');
      debugPrint('Stack: $stack');

      if (!mounted) return;

      await ErrorHandler.instance.handle(
        e,
        stackTrace: stack,
        context: context,
        onRetry: () => _convertToTicket(quoteDetail),
        module: 'sales/quotes/convert_ticket',
      );
    }
  }
}

// Dialog para mostrar detalles de cotización
class _QuoteDetailsDialog extends StatefulWidget {
  final QuoteDetailDto quoteDetail;

  const _QuoteDetailsDialog({required this.quoteDetail});

  @override
  State<_QuoteDetailsDialog> createState() => _QuoteDetailsDialogState();
}

class _QuoteDetailsDialogState extends State<_QuoteDetailsDialog> {
  bool _isLoading = false;

  /// Cierra el diálogo con un resultado (true = algo cambió)
  void _closeDialog([bool changed = false]) {
    Navigator.pop(context, changed);
  }

  Future<void> _viewPDF() async {
    setState(() => _isLoading = true);
    try {
      final business = await SettingsRepository.getBusinessInfo();

      if (mounted) {
        await QuotePrinter.showPreview(
          context: context,
          quote: widget.quoteDetail.quote,
          items: widget.quoteDetail.items,
          clientName: widget.quoteDetail.clientName,
          clientPhone: widget.quoteDetail.clientPhone,
          clientRnc: widget.quoteDetail.clientRnc,
          business: business,
          validDays: 15,
        );
      }
    } catch (e, st) {
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: _viewPDF,
          module: 'sales/quotes/dialog_pdf_preview',
        );
      }
    } finally {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _printQuote() async {
    setState(() => _isLoading = true);
    try {
      final business = await SettingsRepository.getBusinessInfo();
      final settings = await PrinterSettingsRepository.getOrCreate();

      final success = await QuotePrinter.printQuote(
        quote: widget.quoteDetail.quote,
        items: widget.quoteDetail.items,
        clientName: widget.quoteDetail.clientName,
        clientPhone: widget.quoteDetail.clientPhone,
        clientRnc: widget.quoteDetail.clientRnc,
        business: business,
        settings: settings,
        validDays: 15,
      );

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              success ? '✅ Cotización impresa' : '❌ Error al imprimir',
            ),
            backgroundColor: success ? Colors.green : Colors.red,
          ),
        );
      }
    } catch (e, st) {
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: _printQuote,
          module: 'sales/quotes/dialog_print',
        );
      }
    } finally {
      setState(() => _isLoading = false);
    }
  }

  /// Duplicar cotización desde el diálogo
  Future<void> _duplicateQuoteFromDialog() async {
    setState(() => _isLoading = true);
    try {
      // Validación: Verificar que hay items en la cotización
      if (widget.quoteDetail.items.isEmpty) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text(
                '❌ No se puede duplicar una cotización sin productos',
              ),
              backgroundColor: Colors.red,
              duration: Duration(seconds: 3),
            ),
          );
        }
        return;
      }

      // Validación: Verificar que todos los items tengan precio válido
      final hasInvalidPrices = widget.quoteDetail.items.any(
        (item) => item.price <= 0,
      );
      if (hasInvalidPrices) {
        if (mounted) {
          showDialog(
            context: context,
            builder: (context) => AlertDialog(
              icon: const Icon(Icons.warning, color: Colors.amber, size: 48),
              title: const Text('ADVERTENCIA'),
              content: const Text(
                'Algunos productos en esta cotización tienen precio cero o inválido. Se duplicarán pero verifique los precios.',
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: const Text('OK'),
                ),
              ],
            ),
          );
        }
      }

      // Duplicar la cotización
      await QuotesRepository().duplicateQuote(widget.quoteDetail.quote.id!);

      if (!mounted) return;

      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('✅ Cotización duplicada exitosamente'),
          backgroundColor: Colors.green,
        ),
      );

      // Cerrar el diálogo indicando que hubo un cambio
      _closeDialog(true);
    } catch (e, st) {
      if (!mounted) return;
      await ErrorHandler.instance.handle(
        e,
        stackTrace: st,
        context: context,
        onRetry: _duplicateQuoteFromDialog,
        module: 'sales/quotes/dialog_duplicate',
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }

  /// Eliminar cotización desde el diálogo
  Future<void> _deleteQuoteFromDialog() async {
    // Advertencia especial si la cotización fue convertida
    final isConverted = widget.quoteDetail.quote.status == 'CONVERTED';

    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Eliminar Cotización'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              '¿Está seguro que desea eliminar la cotización #${widget.quoteDetail.quote.id}?\n'
              'Esta acción no se puede deshacer.',
            ),
            if (isConverted) ...[
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.red.shade50,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: Colors.red),
                ),
                child: const Row(
                  children: [
                    Icon(Icons.error, color: Colors.red),
                    SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'Esta cotización ya fue convertida a venta. Solo se eliminará el registro.',
                        style: TextStyle(fontSize: 12, color: Colors.red),
                      ),
                    ),
                  ],
                ),
              ),
            ] else ...[
              const SizedBox(height: 8),
            ],
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancelar'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Eliminar', style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );

    if (confirm != true) return;

    try {
      setState(() => _isLoading = true);
      debugPrint(
        '🗑️  Eliminando cotización ID: ${widget.quoteDetail.quote.id}...',
      );
      await QuotesRepository().deleteQuote(widget.quoteDetail.quote.id!);

      if (!mounted) return;

      debugPrint('✅ Cotización eliminada');
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('✅ Cotización eliminada'),
          backgroundColor: Colors.red,
        ),
      );

      // Cerrar el diálogo indicando que hubo un cambio
      _closeDialog(true);
    } catch (e, stack) {
      debugPrint('❌ Error al eliminar cotización: $e');
      debugPrint('Stack trace: $stack');
      if (!mounted) return;
      await ErrorHandler.instance.handle(
        e,
        stackTrace: stack,
        context: context,
        onRetry: _deleteQuoteFromDialog,
        module: 'sales/quotes/dialog_delete',
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final quote = widget.quoteDetail.quote;
    final dateFormatter = DateFormat('dd/MM/yyyy HH:mm');

    return Dialog(
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      child: Container(
        constraints: const BoxConstraints(maxWidth: 600, maxHeight: 700),
        child: Column(
          children: [
            // Header
            Container(
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: Colors.teal,
                borderRadius: const BorderRadius.only(
                  topLeft: Radius.circular(16),
                  topRight: Radius.circular(16),
                ),
              ),
              child: Row(
                children: [
                  const Icon(Icons.description, color: Colors.white, size: 28),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'COT-${quote.id!.toString().padLeft(5, '0')}',
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 20,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        Text(
                          dateFormatter.format(
                            DateTime.fromMillisecondsSinceEpoch(
                              quote.createdAtMs,
                            ),
                          ),
                          style: const TextStyle(
                            color: Colors.white70,
                            fontSize: 14,
                          ),
                        ),
                      ],
                    ),
                  ),
                  IconButton(
                    icon: const Icon(Icons.close, color: Colors.white),
                    onPressed: () => _closeDialog(false),
                  ),
                ],
              ),
            ),
            // Body
            Expanded(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(20),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // Cliente
                    _buildInfoSection('Cliente', [
                      _buildInfoRow('Nombre', widget.quoteDetail.clientName),
                      if ((widget.quoteDetail.clientPhone ?? '')
                          .trim()
                          .isNotEmpty)
                        _buildInfoRow(
                          'Teléfono',
                          widget.quoteDetail.clientPhone!,
                        ),
                      if (widget.quoteDetail.clientRnc != null)
                        _buildInfoRow('RNC', widget.quoteDetail.clientRnc!),
                    ]),
                    const SizedBox(height: 20),
                    // Items
                    _buildInfoSection(
                      'Productos (${widget.quoteDetail.items.length})',
                      widget.quoteDetail.items
                          .map((item) => _buildItemRow(item))
                          .toList(),
                    ),
                    const SizedBox(height: 20),
                    // Totales
                    _buildTotalsSection(quote),
                  ],
                ),
              ),
            ),
            // Footer
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.grey.shade100,
                borderRadius: const BorderRadius.only(
                  bottomLeft: Radius.circular(16),
                  bottomRight: Radius.circular(16),
                ),
              ),
              child: SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: Row(
                  children: [
                    // Botón Ver PDF
                    OutlinedButton.icon(
                      onPressed: _isLoading ? null : _viewPDF,
                      icon: const Icon(Icons.picture_as_pdf, size: 18),
                      label: const Text('VER PDF'),
                      style: OutlinedButton.styleFrom(
                        foregroundColor: Colors.red.shade700,
                        side: BorderSide(color: Colors.red.shade700),
                      ),
                    ),
                    const SizedBox(width: 8),
                    // Botón Imprimir
                    OutlinedButton.icon(
                      onPressed: _isLoading ? null : _printQuote,
                      icon: const Icon(Icons.print, size: 18),
                      label: const Text('IMPRIMIR'),
                      style: OutlinedButton.styleFrom(
                        foregroundColor: Colors.teal,
                        side: const BorderSide(color: Colors.teal),
                      ),
                    ),
                    const SizedBox(width: 8),
                    // Botón Duplicar
                    OutlinedButton.icon(
                      onPressed: _isLoading
                          ? null
                          : () => _duplicateQuoteFromDialog(),
                      icon: const Icon(Icons.content_copy, size: 18),
                      label: const Text('DUPLICAR'),
                      style: OutlinedButton.styleFrom(
                        foregroundColor: Colors.blue,
                        side: const BorderSide(color: Colors.blue),
                      ),
                    ),
                    const SizedBox(width: 8),
                    // Botón Eliminar
                    OutlinedButton.icon(
                      onPressed: _isLoading ? null : _deleteQuoteFromDialog,
                      icon: const Icon(Icons.delete, size: 18),
                      label: const Text('ELIMINAR'),
                      style: OutlinedButton.styleFrom(
                        foregroundColor: Colors.red,
                        side: const BorderSide(color: Colors.red),
                      ),
                    ),
                    const SizedBox(width: 8),
                    ElevatedButton(
                      onPressed: () => _closeDialog(false),
                      child: const Text('Cerrar'),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildInfoSection(String title, List<Widget> children) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: const TextStyle(
            fontSize: 16,
            fontWeight: FontWeight.bold,
            color: Colors.teal,
          ),
        ),
        const SizedBox(height: 12),
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: Colors.grey.shade50,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: Colors.grey.shade300),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: children,
          ),
        ),
      ],
    );
  }

  Widget _buildInfoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Text(
            '$label: ',
            style: const TextStyle(
              fontSize: 14,
              fontWeight: FontWeight.w500,
              color: Colors.grey,
            ),
          ),
          Expanded(child: Text(value, style: const TextStyle(fontSize: 14))),
        ],
      ),
    );
  }

  Widget _buildItemRow(QuoteItemModel item) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(
            flex: 3,
            child: Text(item.description, style: const TextStyle(fontSize: 14)),
          ),
          const SizedBox(width: 12),
          Text(
            '${item.qty.toStringAsFixed(0)} x \$${item.price.toStringAsFixed(2)}',
            style: TextStyle(fontSize: 13, color: Colors.grey.shade700),
          ),
          const SizedBox(width: 12),
          Text(
            '\$${item.totalLine.toStringAsFixed(2)}',
            style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600),
          ),
        ],
      ),
    );
  }

  Widget _buildTotalsSection(QuoteModel quote) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.teal.shade50,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.teal.shade200, width: 2),
      ),
      child: Column(
        children: [
          _buildTotalRow('Subtotal', quote.subtotal),
          if (quote.discountTotal > 0)
            _buildTotalRow('Descuento', -quote.discountTotal),
          if (quote.itbisEnabled)
            _buildTotalRow(
              'ITBIS (${(quote.itbisRate * 100).toStringAsFixed(0)}%)',
              quote.itbisAmount,
            ),
          const Divider(height: 20),
          _buildTotalRow('TOTAL', quote.total, bold: true, large: true),
        ],
      ),
    );
  }

  Widget _buildTotalRow(
    String label,
    double amount, {
    bool bold = false,
    bool large = false,
  }) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: TextStyle(
              fontSize: large ? 18 : 15,
              fontWeight: bold ? FontWeight.bold : FontWeight.normal,
            ),
          ),
          Text(
            '\$${amount.toStringAsFixed(2)}',
            style: TextStyle(
              fontSize: large ? 20 : 15,
              fontWeight: bold ? FontWeight.bold : FontWeight.w600,
              color: large ? Colors.teal.shade800 : null,
            ),
          ),
        ],
      ),
    );
  }
}

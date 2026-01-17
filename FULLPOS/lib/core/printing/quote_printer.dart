import 'dart:typed_data';
import 'dart:async';
import 'package:flutter/material.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:printing/printing.dart';
import 'package:intl/intl.dart';
import '../../features/sales/data/quote_model.dart';
import '../../features/sales/data/business_info_model.dart';
import '../../features/settings/data/business_settings_model.dart';
import '../../features/settings/data/printer_settings_model.dart';
import '../services/empresa_service.dart';
import '../layout/app_shell.dart';

/// Servicio para imprimir y generar PDF de cotizaciones
///
/// ✅ IMPORTANTE: El PDF siempre usa datos REALES desde EmpresaService
/// No adivina datos. Si un campo no existe en Configuración, no lo muestra.
/// Single Source of Truth: todos los datos vienen de la Configuración del Negocio
class QuotePrinter {
  QuotePrinter._();

  static String _sanitizePdfText(String input) {
    var s = input.replaceAll('\u00A0', ' ');

    // Caracteres que suelen causar excepciones en fonts built-in (Helvetica)
    // del paquete `pdf`.
    s = s
        .replaceAll('\u2022', '-') // bullet
        .replaceAll('\u2013', '-') // en-dash
        .replaceAll('\u2014', '-') // em-dash
        .replaceAll('\u2026', '...') // ellipsis
        .replaceAll('\u00B7', '-') // middle dot
        .replaceAll('\u00AD', '') // soft hyphen
        .replaceAll('\u00B6', '') // pilcrow
        .replaceAll('¶', '')
        .replaceAll('•', '-')
        .replaceAll('–', '-')
        .replaceAll('—', '-')
        .replaceAll('…', '...');

    const map = <String, String>{
      'á': 'a',
      'é': 'e',
      'í': 'i',
      'ó': 'o',
      'ú': 'u',
      'Á': 'A',
      'É': 'E',
      'Í': 'I',
      'Ó': 'O',
      'Ú': 'U',
      'ñ': 'n',
      'Ñ': 'N',
      'ü': 'u',
      'Ü': 'U',
    };
    map.forEach((k, v) => s = s.replaceAll(k, v));

    s = s.replaceAll(RegExp(r'\\s+'), ' ').trim();
    return s;
  }

  /// Normaliza datos de negocio desde cualquier fuente a Map estándar
  /// Acepta: BusinessSettings, BusinessInfoModel, o usa EmpresaService como fallback
  static Map<String, String> _normalizeBusinessData(dynamic business) {
    final normalized = <String, String>{
      'name': 'Mi Negocio',
      'slogan': '',
      'address': '',
      'phone': '',
      'rnc': '',
    };

    if (business is BusinessSettings) {
      normalized['name'] = business.businessName;
      normalized['slogan'] = business.slogan ?? '';
      normalized['address'] = business.address ?? '';
      normalized['phone'] = business.phone ?? '';
      normalized['rnc'] = business.rnc ?? '';
    } else if (business is BusinessInfoModel) {
      normalized['name'] = business.name;
      normalized['slogan'] = business.slogan ?? '';
      normalized['address'] = business.address ?? '';
      normalized['phone'] = business.phone ?? '';
      normalized['rnc'] = business.rnc ?? '';
    }

    return normalized;
  }

  /// 📌 NUEVA: Obtener datos de empresa desde la FUENTE ÚNICA (EmpresaService)
  /// Esto garantiza que SIEMPRE lee los datos más actuales desde Configuración
  /// No debe haber nunca textos fijos como "Sistema POS Profesional" o "LOS NILKAS"
  static Future<Map<String, String>> _getEmpresaDataFromConfig() async {
    try {
      final config = await EmpresaService.getEmpresaConfig();

      return {
        'name': config.nombreEmpresa,
        'slogan': config.slogan ?? '',
        'address': config.direccion ?? '',
        'phone': config.getTelefono() ?? '',
        'rnc': config.rnc ?? '',
      };
    } catch (e) {
      debugPrint('⚠️ Error en _getEmpresaDataFromConfig: $e');
      // Retornar valores seguros por defecto
      return {
        'name': 'Mi Negocio',
        'slogan': '',
        'address': '',
        'phone': '',
        'rnc': '',
      };
    }
  }

  /// 📌 PRINCIPAL: Genera el PDF de cotización SIEMPRE con datos dinámicos
  ///
  /// ✅ GARANTÍAS:
  /// - Los datos de empresa SIEMPRE vienen de Configuración del Negocio
  /// - Si el parámetro 'business' se proporciona, se usa como fallback
  /// - Se regenera cada vez que se llama (NO usa cache)
  /// - El PDF tiene formato profesional sin textos fijos
  ///
  /// 🚫 NUNCA contendrá:
  /// - "Sistema POS Profesional"
  /// - "LOS NILKAS" (ni otro nombre hardcodeado)
  /// - Slogans o texto fijo de empresa
  /// - Cualquier información no configurada (se omite en lugar de mostrar defaults)
  static Future<Uint8List> generatePdf({
    required QuoteModel quote,
    required List<QuoteItemModel> items,
    required String clientName,
    String? clientPhone,
    String? clientRnc,
    dynamic business,
    int validDays = 15,
  }) async {
    // 1️⃣ SIEMPRE obtener datos de empresa desde la fuente única
    final empresaData = await _getEmpresaDataFromConfig();

    // 2️⃣ Si no tenemos datos reales, usar fallback de parámetro
    final businessData =
        empresaData['name']! == 'Mi Negocio' && business != null
        ? _normalizeBusinessData(business)
        : empresaData;

    final pdf = pw.Document();

    final safeBusinessData = businessData.map(
      (k, v) => MapEntry(k, _sanitizePdfText(v)),
    );
    final safeClientName = _sanitizePdfText(clientName);
    final safeClientPhone = clientPhone == null
        ? null
        : _sanitizePdfText(clientPhone);
    final safeClientRnc = clientRnc == null
        ? null
        : _sanitizePdfText(clientRnc);

    final dateFormat = DateFormat('dd/MM/yyyy HH:mm');
    final currencyFormat = NumberFormat('#,##0.00', 'en_US');
    final createdDate = DateTime.fromMillisecondsSinceEpoch(quote.createdAtMs);
    final expirationDate = createdDate.add(Duration(days: validDays));

    pdf.addPage(
      pw.Page(
        pageFormat: PdfPageFormat.letter,
        margin: const pw.EdgeInsets.all(40),
        build: (context) {
          return pw.Column(
            crossAxisAlignment: pw.CrossAxisAlignment.start,
            children: [
              // Header con datos de empresa (100% dinámicos)
              _buildHeader(safeBusinessData, quote),
              pw.SizedBox(height: 20),

              // Línea divisoria
              pw.Divider(thickness: 2, color: PdfColors.teal),
              pw.SizedBox(height: 15),

              // Datos del cliente
              _buildClientInfo(safeClientName, safeClientPhone, safeClientRnc),
              pw.SizedBox(height: 20),

              // Fechas
              pw.Row(
                mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
                children: [
                  pw.Text(
                    'Fecha: ${dateFormat.format(createdDate)}',
                    style: const pw.TextStyle(fontSize: 10),
                  ),
                  pw.Container(
                    padding: const pw.EdgeInsets.symmetric(
                      horizontal: 12,
                      vertical: 4,
                    ),
                    decoration: pw.BoxDecoration(
                      color: PdfColors.amber100,
                      borderRadius: pw.BorderRadius.circular(4),
                    ),
                    child: pw.Text(
                      'Válida hasta: ${DateFormat('dd/MM/yyyy').format(expirationDate)}',
                      style: pw.TextStyle(
                        fontSize: 10,
                        fontWeight: pw.FontWeight.bold,
                        color: PdfColors.orange900,
                      ),
                    ),
                  ),
                ],
              ),
              pw.SizedBox(height: 20),

              // Tabla de productos
              _buildProductsTable(items, currencyFormat),
              pw.SizedBox(height: 20),

              // Totales
              _buildTotals(quote, currencyFormat),
              pw.SizedBox(height: 30),

              // Notas si existen
              if (quote.notes != null && quote.notes!.isNotEmpty) ...[
                pw.Container(
                  padding: const pw.EdgeInsets.all(10),
                  decoration: pw.BoxDecoration(
                    color: PdfColors.grey100,
                    borderRadius: pw.BorderRadius.circular(4),
                  ),
                  child: pw.Column(
                    crossAxisAlignment: pw.CrossAxisAlignment.start,
                    children: [
                      pw.Text(
                        'NOTAS:',
                        style: pw.TextStyle(
                          fontSize: 10,
                          fontWeight: pw.FontWeight.bold,
                        ),
                      ),
                      pw.SizedBox(height: 4),
                      pw.Text(
                        _sanitizePdfText(quote.notes!),
                        style: const pw.TextStyle(fontSize: 9),
                      ),
                    ],
                  ),
                ),
                pw.SizedBox(height: 20),
              ],

              // Términos y condiciones
              _buildTerms(validDays),

              // Spacer
              pw.Spacer(),

              // Footer (con nombre dinámico de empresa)
              _buildFooter(safeBusinessData),
            ],
          );
        },
      ),
    );

    return pdf.save();
  }

  static pw.Widget _buildHeader(
    Map<String, String> businessData,
    QuoteModel quote,
  ) {
    final displayId = quote.id != null
        ? quote.id!.toString().padLeft(5, '0')
        : '-----';

    return pw.Row(
      crossAxisAlignment: pw.CrossAxisAlignment.start,
      children: [
        // Datos de empresa (centrado, sin iconos ni caracteres especiales)
        pw.Expanded(
          child: pw.Column(
            crossAxisAlignment: pw.CrossAxisAlignment.center,
            children: [
              // Nombre de la empresa (negrita, centrado)
              pw.Text(
                businessData['name']!,
                style: pw.TextStyle(
                  fontSize: 16,
                  fontWeight: pw.FontWeight.bold,
                  color: PdfColors.black,
                ),
                textAlign: pw.TextAlign.center,
              ),
              pw.SizedBox(height: 4),

              // RNC
              if (businessData['rnc']!.isNotEmpty)
                pw.Text(
                  'RNC: ${businessData['rnc']!}',
                  style: const pw.TextStyle(fontSize: 9),
                  textAlign: pw.TextAlign.center,
                ),

              // Teléfono
              if (businessData['phone']!.isNotEmpty)
                pw.Text(
                  'Tel: ${businessData['phone']!}',
                  style: const pw.TextStyle(fontSize: 9),
                  textAlign: pw.TextAlign.center,
                ),

              // Dirección
              if (businessData['address']!.isNotEmpty)
                pw.Text(
                  businessData['address']!,
                  style: const pw.TextStyle(fontSize: 9),
                  textAlign: pw.TextAlign.center,
                ),
            ],
          ),
        ),
        // Título de cotización (sin texto fijo adicional)
        pw.Container(
          padding: const pw.EdgeInsets.all(15),
          decoration: pw.BoxDecoration(
            color: PdfColors.teal,
            borderRadius: pw.BorderRadius.circular(8),
          ),
          child: pw.Column(
            crossAxisAlignment: pw.CrossAxisAlignment.center,
            children: [
              pw.Text(
                'COTIZACION',
                style: pw.TextStyle(
                  fontSize: 18,
                  fontWeight: pw.FontWeight.bold,
                  color: PdfColors.white,
                ),
              ),
              pw.SizedBox(height: 4),
              pw.Text(
                '#COT-$displayId',
                style: pw.TextStyle(
                  fontSize: 14,
                  fontWeight: pw.FontWeight.bold,
                  color: PdfColors.white,
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  static pw.Widget _buildClientInfo(
    String clientName,
    String? clientPhone,
    String? clientRnc,
  ) {
    return pw.Container(
      padding: const pw.EdgeInsets.all(12),
      decoration: pw.BoxDecoration(
        color: PdfColors.grey100,
        borderRadius: pw.BorderRadius.circular(6),
        border: pw.Border.all(color: PdfColors.grey300),
      ),
      child: pw.Row(
        children: [
          pw.Container(
            width: 40,
            height: 40,
            decoration: pw.BoxDecoration(
              color: PdfColors.teal100,
              borderRadius: pw.BorderRadius.circular(20),
            ),
            child: pw.Center(
              child: pw.Text(
                clientName.isNotEmpty ? clientName[0].toUpperCase() : 'C',
                style: pw.TextStyle(
                  fontSize: 18,
                  fontWeight: pw.FontWeight.bold,
                  color: PdfColors.teal800,
                ),
              ),
            ),
          ),
          pw.SizedBox(width: 12),
          pw.Column(
            crossAxisAlignment: pw.CrossAxisAlignment.start,
            children: [
              pw.Text(
                'CLIENTE',
                style: pw.TextStyle(
                  fontSize: 8,
                  fontWeight: pw.FontWeight.bold,
                  color: PdfColors.grey600,
                ),
              ),
              pw.Text(
                clientName,
                style: pw.TextStyle(
                  fontSize: 14,
                  fontWeight: pw.FontWeight.bold,
                ),
              ),
              if (clientPhone != null && clientPhone.isNotEmpty)
                pw.Text(
                  'Tel: $clientPhone',
                  style: const pw.TextStyle(fontSize: 9),
                ),
              if (clientRnc != null && clientRnc.isNotEmpty)
                pw.Text(
                  'RNC: $clientRnc',
                  style: const pw.TextStyle(fontSize: 9),
                ),
            ],
          ),
        ],
      ),
    );
  }

  static pw.Widget _buildProductsTable(
    List<QuoteItemModel> items,
    NumberFormat currencyFormat,
  ) {
    return pw.Table(
      border: pw.TableBorder.all(color: PdfColors.grey300),
      columnWidths: {
        0: const pw.FlexColumnWidth(4),
        1: const pw.FlexColumnWidth(1),
        2: const pw.FlexColumnWidth(1.5),
        3: const pw.FlexColumnWidth(1.5),
      },
      children: [
        // Header
        pw.TableRow(
          decoration: const pw.BoxDecoration(color: PdfColors.teal),
          children: [
            _tableHeaderCell('PRODUCTO'),
            _tableHeaderCell('CANT', align: pw.TextAlign.center),
            _tableHeaderCell('PRECIO', align: pw.TextAlign.right),
            _tableHeaderCell('TOTAL', align: pw.TextAlign.right),
          ],
        ),
        // Items
        ...items.map(
          (item) => pw.TableRow(
            children: [
              pw.Padding(
                padding: const pw.EdgeInsets.all(8),
                child: pw.Column(
                  crossAxisAlignment: pw.CrossAxisAlignment.start,
                  children: [
                    pw.Text(
                      _sanitizePdfText(item.description),
                      style: const pw.TextStyle(fontSize: 10),
                    ),
                  ],
                ),
              ),
              pw.Padding(
                padding: const pw.EdgeInsets.all(8),
                child: pw.Text(
                  item.qty.toStringAsFixed(
                    item.qty == item.qty.roundToDouble() ? 0 : 2,
                  ),
                  style: const pw.TextStyle(fontSize: 10),
                  textAlign: pw.TextAlign.center,
                ),
              ),
              pw.Padding(
                padding: const pw.EdgeInsets.all(8),
                child: pw.Text(
                  '\$${currencyFormat.format(item.price)}',
                  style: const pw.TextStyle(fontSize: 10),
                  textAlign: pw.TextAlign.right,
                ),
              ),
              pw.Padding(
                padding: const pw.EdgeInsets.all(8),
                child: pw.Text(
                  '\$${currencyFormat.format(item.totalLine)}',
                  style: pw.TextStyle(
                    fontSize: 10,
                    fontWeight: pw.FontWeight.bold,
                  ),
                  textAlign: pw.TextAlign.right,
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  static pw.Widget _tableHeaderCell(
    String text, {
    pw.TextAlign align = pw.TextAlign.left,
  }) {
    return pw.Padding(
      padding: const pw.EdgeInsets.all(8),
      child: pw.Text(
        text,
        style: pw.TextStyle(
          fontSize: 10,
          fontWeight: pw.FontWeight.bold,
          color: PdfColors.white,
        ),
        textAlign: align,
      ),
    );
  }

  static pw.Widget _buildTotals(QuoteModel quote, NumberFormat currencyFormat) {
    return pw.Align(
      alignment: pw.Alignment.centerRight,
      child: pw.Container(
        width: 250,
        padding: const pw.EdgeInsets.all(12),
        decoration: pw.BoxDecoration(
          color: PdfColors.teal50,
          borderRadius: pw.BorderRadius.circular(6),
          border: pw.Border.all(color: PdfColors.teal200, width: 2),
        ),
        child: pw.Column(
          children: [
            _totalRow('Subtotal', quote.subtotal, currencyFormat),
            if (quote.discountTotal > 0)
              _totalRow(
                'Descuento',
                -quote.discountTotal,
                currencyFormat,
                color: PdfColors.red,
              ),
            if (quote.itbisEnabled)
              _totalRow(
                'ITBIS (${(quote.itbisRate * 100).toInt()}%)',
                quote.itbisAmount,
                currencyFormat,
              ),
            pw.Divider(thickness: 2, color: PdfColors.teal),
            pw.SizedBox(height: 4),
            pw.Row(
              mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
              children: [
                pw.Text(
                  'TOTAL',
                  style: pw.TextStyle(
                    fontSize: 14,
                    fontWeight: pw.FontWeight.bold,
                    color: PdfColors.teal800,
                  ),
                ),
                pw.Text(
                  'RD\$ ${currencyFormat.format(quote.total)}',
                  style: pw.TextStyle(
                    fontSize: 16,
                    fontWeight: pw.FontWeight.bold,
                    color: PdfColors.teal800,
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  static pw.Widget _totalRow(
    String label,
    double amount,
    NumberFormat currencyFormat, {
    PdfColor? color,
  }) {
    return pw.Padding(
      padding: const pw.EdgeInsets.symmetric(vertical: 2),
      child: pw.Row(
        mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
        children: [
          pw.Text(label, style: const pw.TextStyle(fontSize: 10)),
          pw.Text(
            '\$${currencyFormat.format(amount)}',
            style: pw.TextStyle(fontSize: 10, color: color),
          ),
        ],
      ),
    );
  }

  static pw.Widget _buildTerms(int validDays) {
    return pw.Container(
      padding: const pw.EdgeInsets.all(10),
      decoration: pw.BoxDecoration(
        border: pw.Border.all(color: PdfColors.grey300),
        borderRadius: pw.BorderRadius.circular(4),
      ),
      child: pw.Column(
        crossAxisAlignment: pw.CrossAxisAlignment.start,
        children: [
          pw.Text(
            'TERMINOS Y CONDICIONES',
            style: pw.TextStyle(fontSize: 10, fontWeight: pw.FontWeight.bold),
          ),
          pw.SizedBox(height: 6),
          pw.Text(
            '- Esta cotizacion tiene una validez de $validDays dias a partir de la fecha de emision.',
            style: const pw.TextStyle(fontSize: 8),
          ),
          pw.Text(
            '- Los precios estan sujetos a cambios sin previo aviso despues de la fecha de vencimiento.',
            style: const pw.TextStyle(fontSize: 8),
          ),
          pw.Text(
            '- El ITBIS esta incluido segun las leyes fiscales vigentes de Republica Dominicana.',
            style: const pw.TextStyle(fontSize: 8),
          ),
          pw.Text(
            '- Para confirmar su pedido, favor comunicarse con nosotros.',
            style: const pw.TextStyle(fontSize: 8),
          ),
        ],
      ),
    );
  }

  static pw.Widget _buildFooter(Map<String, String> businessData) {
    return pw.Column(
      children: [
        pw.Divider(color: PdfColors.grey300),
        pw.SizedBox(height: 8),
        pw.Center(
          child: pw.Text(
            'Gracias por su preferencia!',
            style: pw.TextStyle(
              fontSize: 12,
              fontWeight: pw.FontWeight.bold,
              color: PdfColors.teal,
            ),
          ),
        ),
        pw.SizedBox(height: 4),
        pw.Center(
          child: pw.Text(
            'Documento generado por ${businessData['name']!}',
            style: pw.TextStyle(fontSize: 8, color: PdfColors.grey600),
          ),
        ),
      ],
    );
  }

  /// 📌 VISTA PREVIA: Muestra el PDF en un visor mejorado
  ///
  /// ✅ GARANTÍAS:
  /// - Regenera el PDF cada vez que se abre (datos siempre frescos)
  /// - No reutiliza PDFs en cache
  /// - Cada cotización tiene archivo temporal único con timestamp
  static Future<void> showPreview({
    required BuildContext context,
    required QuoteModel quote,
    required List<QuoteItemModel> items,
    required String clientName,
    String? clientPhone,
    String? clientRnc,
    dynamic business,
    int validDays = 15,
  }) async {
    final displayId = quote.id != null
        ? quote.id!.toString().padLeft(5, '0')
        : '-----';

    // 🔄 Usar timestamp único para garantizar que cada apertura regenera el PDF
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final fileId = quote.id ?? timestamp;
    final fileName = 'cotizacion_${fileId}_$timestamp.pdf';

    // ✅ Regenerar PDF siempre (datos frescos desde Configuración)
    Uint8List pdfData;
    try {
      pdfData = await generatePdf(
        quote: quote,
        items: items,
        clientName: clientName,
        clientPhone: clientPhone,
        clientRnc: clientRnc,
        business: business,
        validDays: validDays,
      );
    } catch (e) {
      debugPrint('Error generando PDF de cotización: $e');
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('No se pudo generar el PDF de la cotización.'),
          ),
        );
      }
      return;
    }

    if (context.mounted) {
      await Navigator.push(
        context,
        MaterialPageRoute(
          builder: (context) => _PdfViewerWithZoom(
            title: 'Cotización #COT-$displayId',
            pdfData: pdfData,
            fileName: fileName,
          ),
        ),
      );
    }
  }

  /// 📌 IMPRESIÓN: Imprime la cotización directamente a impresora
  ///
  /// ✅ GARANTÍAS:
  /// - Regenera PDF con datos frescos cada vez
  /// - No reutiliza PDFs en cache
  static Future<bool> printQuote({
    required QuoteModel quote,
    required List<QuoteItemModel> items,
    required String clientName,
    String? clientPhone,
    String? clientRnc,
    dynamic business,
    required PrinterSettingsModel settings,
    int validDays = 15,
  }) async {
    try {
      // ✅ Regenerar PDF siempre con datos frescos
      final pdfData = await generatePdf(
        quote: quote,
        items: items,
        clientName: clientName,
        clientPhone: clientPhone,
        clientRnc: clientRnc,
        business: business,
        validDays: validDays,
      );

      final printers = await Printing.listPrinters();
      final selectedPrinter = printers.firstWhere(
        (p) => p.name == settings.selectedPrinterName,
        orElse: () => printers.first,
      );

      return await Printing.directPrintPdf(
        printer: selectedPrinter,
        onLayout: (_) => pdfData,
      );
    } catch (e) {
      debugPrint('❌ Error en printQuote: $e');
      return false;
    }
  }
}

/// Widget para visualizar PDF con controles de zoom mejorados
class _PdfViewerWithZoom extends StatefulWidget {
  final String title;
  final Uint8List pdfData;
  final String fileName;

  const _PdfViewerWithZoom({
    required this.title,
    required this.pdfData,
    required this.fileName,
  });

  @override
  State<_PdfViewerWithZoom> createState() => _PdfViewerWithZoomState();
}

class _PdfViewerWithZoomState extends State<_PdfViewerWithZoom> {
  double _currentScale = 1.0;
  static const double _minScale = 0.5;
  static const double _maxScale = 4.0;
  static const double _scaleStep = 0.25;

  // Controla el pan/zoom para mantener el PDF centrado.
  final TransformationController _transformController = TransformationController();
  Size? _lastViewportSize;
  bool _didInitTransform = false;

  Future<Uint8List>? _firstPagePng;
  bool _didFitOnOpen = false;

  // La cotización se genera en PdfPageFormat.letter
  static const double _pageWidth = 612; // Letter en puntos
  static const double _pageHeight = 792; // Letter en puntos

  @override
  void initState() {
    super.initState();
    _transformController.addListener(_syncScaleFromTransform);
    _firstPagePng = _rasterFirstPage(widget.pdfData);
  }

  @override
  void dispose() {
    _transformController.removeListener(_syncScaleFromTransform);
    _transformController.dispose();
    super.dispose();
  }

  Future<Uint8List> _rasterFirstPage(Uint8List pdfBytes) async {
    // PdfPreview tiene su propio scroll/zoom interno. Para que el zoom sea "del PDF completo",
    // rasterizamos la página a imagen y usamos SOLO un InteractiveViewer.
    await for (final page in Printing.raster(pdfBytes, dpi: 160)) {
      return page.toPng();
    }
    throw StateError('El PDF no contiene páginas.');
  }

  void _syncScaleFromTransform() {
    final scale = _transformController.value.getMaxScaleOnAxis();
    if ((scale - _currentScale).abs() > 0.01) {
      setState(() => _currentScale = scale.clamp(_minScale, _maxScale));
    }
  }

  void _applyCenteredTransform({required Size viewport, required double scale}) {
    final dx = ((viewport.width - (_pageWidth * scale)) / 2).clamp(-_pageWidth * scale, viewport.width);
    final dy = ((viewport.height - (_pageHeight * scale)) / 2).clamp(-_pageHeight * scale, viewport.height);
    _transformController.value = Matrix4.identity()
      ..translateByDouble(dx.toDouble(), dy.toDouble(), 0.0, 1.0)
      ..scaleByDouble(scale, scale, 1.0, 1.0);
  }

  double _fitScaleForViewport(Size viewport) {
    // Queremos que el PDF se vea completo al abrir, sin que el usuario tenga que tocar zoom.
    // Dejamos un margen visual para que no quede pegado a los bordes.
    const padding = 24.0;
    final w = (viewport.width - padding).clamp(100.0, double.infinity);
    final h = (viewport.height - padding).clamp(100.0, double.infinity);
    final fit = (w / _pageWidth).clamp(0.01, double.infinity);
    final fitH = (h / _pageHeight).clamp(0.01, double.infinity);
    return (fit < fitH ? fit : fitH).clamp(_minScale, _maxScale);
  }

  void _zoomIn() {
    final next = (_currentScale + _scaleStep).clamp(_minScale, _maxScale);
    final viewport = _lastViewportSize;
    if (viewport != null) {
      _applyCenteredTransform(viewport: viewport, scale: next);
    } else {
      setState(() => _currentScale = next);
    }
  }

  void _zoomOut() {
    final next = (_currentScale - _scaleStep).clamp(_minScale, _maxScale);
    final viewport = _lastViewportSize;
    if (viewport != null) {
      _applyCenteredTransform(viewport: viewport, scale: next);
    } else {
      setState(() => _currentScale = next);
    }
  }

  void _resetZoom() {
    final viewport = _lastViewportSize;
    if (viewport != null) {
      _applyCenteredTransform(viewport: viewport, scale: 1.0);
    } else {
      setState(() => _currentScale = 1.0);
    }
  }

  @override
  Widget build(BuildContext context) {
    // Usar el layout normal de la app (Sidebar + Topbar + Footer).
    return AppShell(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Header interno (debajo del Topbar) con acciones de zoom/print/share
          Material(
            color: Colors.white.withValues(alpha: 0.92),
            borderRadius: BorderRadius.circular(12),
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
              child: Row(
                children: [
                  IconButton(
                    onPressed: () => Navigator.of(context).maybePop(),
                    icon: const Icon(Icons.arrow_back),
                    tooltip: 'Volver',
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      widget.title,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                  ),
                  IconButton(
                    icon: const Icon(Icons.zoom_out),
                    onPressed: _currentScale > _minScale ? _zoomOut : null,
                    tooltip: 'Alejar',
                  ),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                    decoration: BoxDecoration(
                      color: Colors.grey.shade100,
                      borderRadius: BorderRadius.circular(999),
                      border: Border.all(color: Colors.grey.shade300),
                    ),
                    child: Text(
                      '${(_currentScale * 100).toInt()}%',
                      style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
                    ),
                  ),
                  IconButton(
                    icon: const Icon(Icons.zoom_in),
                    onPressed: _currentScale < _maxScale ? _zoomIn : null,
                    tooltip: 'Acercar',
                  ),
                  IconButton(
                    icon: const Icon(Icons.fit_screen),
                    onPressed: () {
                      final vp = _lastViewportSize;
                      if (vp == null) return;
                      final fit = _fitScaleForViewport(vp);
                      _applyCenteredTransform(viewport: vp, scale: fit);
                    },
                    tooltip: 'Ajustar',
                  ),
                  const SizedBox(width: 8),
                  IconButton(
                    icon: const Icon(Icons.print),
                    onPressed: () async {
                      await Printing.layoutPdf(onLayout: (_) => widget.pdfData);
                    },
                    tooltip: 'Imprimir',
                  ),
                  IconButton(
                    icon: const Icon(Icons.share),
                    onPressed: () {
                      unawaited(
                        Printing.sharePdf(
                          bytes: widget.pdfData,
                          filename: widget.fileName,
                        ),
                      );
                    },
                    tooltip: 'Compartir',
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          Expanded(
            child: Container(
              decoration: BoxDecoration(
                color: Colors.grey.shade300,
                borderRadius: BorderRadius.circular(12),
              ),
              child: LayoutBuilder(
                builder: (context, constraints) {
                  final viewport = constraints.biggest;
                  final prevViewport = _lastViewportSize;
                  _lastViewportSize = viewport;

                  final viewportChanged = prevViewport == null || prevViewport != viewport;

                  return Center(
                    child: InteractiveViewer(
                      transformationController: _transformController,
                      minScale: _minScale,
                      maxScale: _maxScale,
                      panEnabled: true,
                      scaleEnabled: true,
                      constrained: true,
                      boundaryMargin: const EdgeInsets.all(200),
                      child: FutureBuilder<Uint8List>(
                        future: _firstPagePng,
                        builder: (context, snapshot) {
                          if (snapshot.connectionState != ConnectionState.done) {
                            return SizedBox(
                              width: _pageWidth,
                              height: _pageHeight,
                              child: const Center(child: CircularProgressIndicator()),
                            );
                          }
                          if (snapshot.hasError) {
                            return SizedBox(
                              width: _pageWidth,
                              height: _pageHeight,
                              child: Center(
                                child: Text(
                                  'No se pudo mostrar el PDF.\n${snapshot.error}',
                                  textAlign: TextAlign.center,
                                ),
                              ),
                            );
                          }

                          // Al abrir (y cuando cambie el tamaño), ajustar para que el PDF se vea completo.
                          if (!_didFitOnOpen || viewportChanged) {
                            _didFitOnOpen = true;
                            final fit = _fitScaleForViewport(viewport);
                            WidgetsBinding.instance.addPostFrameCallback((_) {
                              if (!mounted) return;
                              _applyCenteredTransform(viewport: viewport, scale: fit);
                            });
                          }

                          final png = snapshot.data!;
                          return Container(
                            width: _pageWidth,
                            height: _pageHeight,
                            color: Colors.white,
                            child: Image.memory(
                              png,
                              fit: BoxFit.contain,
                              filterQuality: FilterQuality.high,
                            ),
                          );
                        },
                      ),
                    ),
                  );
                },
              ),
            ),
          ),
        ],
      ),
    );
  }
}

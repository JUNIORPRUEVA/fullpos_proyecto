import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'company_info.dart';
import 'ticket_layout_config.dart';
import 'ticket_data.dart';
import 'ticket_renderer.dart';

/// Builder centralizado de tickets
/// Genera tanto texto plano para vista previa como PDF para impresión
/// Formato profesional estilo factura (80mm)
class TicketBuilder {
  final TicketLayoutConfig layout;
  final CompanyInfo company;

  TicketBuilder({required this.layout, required this.company});

  // ============================================================
  // HELPERS DE SEGURIDAD PARA ALINEACIÓN Y ANCHO
  // ============================================================

  /// Genera una línea de regla para debugging del ancho real
  /// Muestra: 0123456789012345678901234567890123456789
  /// Útil para verificar que el maxCharsPerLine es correcto
  String buildDebugRuler() {
    final w = layout.maxCharsPerLine;
    final buffer = StringBuffer();
    for (int i = 0; i < w; i++) {
      buffer.write((i % 10).toString());
    }
    return buffer.toString();
  }

  /// Trunca o rellena texto a la derecha sin exceder ancho
  String padRightSafe(String text, int width) {
    if (text.length > width) return text.substring(0, width);
    return text.padRight(width);
  }

  /// Trunca o rellena texto a la izquierda sin exceder ancho
  String padLeftSafe(String text, int width) {
    if (text.length > width) return text.substring(0, width);
    return text.padLeft(width);
  }

  /// Centra texto sin exceder ancho
  String centerSafe(String text, int width) {
    if (text.length >= width) return text.substring(0, width);
    final left = ((width - text.length) / 2).floor();
    final right = width - text.length - left;
    return ' ' * left + text + ' ' * right;
  }

  /// Repite un carácter hasta llenar el ancho
  String repeatedChar(String ch, int width) {
    return List.filled(width, ch).join('');
  }

  /// Alinea texto genéricamente respetando maxCharsPerLine
  /// align: 'left' | 'center' | 'right'
  String alignText(String text, int width, String align) {
    if (text.length > width) {
      text = text.substring(0, width);
    }
    switch (align) {
      case 'right':
        return text.padLeft(width);
      case 'center':
        final left = ((width - text.length) / 2).floor();
        final right = width - text.length - left;
        return ' ' * left + text + ' ' * right;
      case 'left':
      default:
        return text.padRight(width);
    }
  }

  /// Crea una línea separadora del ancho especificado
  String sepLine(int width, [String char = '-']) {
    return repeatedChar(char, width);
  }

  /// Alinea un total (label: value) respetando alineación configurada
  String totalsLine(String label, String value, int width, String align) {
    final text = '$label: $value';
    return alignText(text, width, align);
  }

  /// Alinea texto a la derecha con etiqueta a la izquierda (método legacy)
  String totalLine(String label, String value, int width) {
    final text = '$label: $value';
    if (text.length >= width) return text.substring(0, width);
    final pad = width - text.length;
    return ' ' * pad + text;
  }

  /// Genera ticket CON REGLA DE DEBUG para verificar el ancho real
  /// Útil para verificar que maxCharsPerLine es correcto
  /// Muestra una línea de números (0123456789...) al inicio
  String buildPlainTextWithDebugRuler(TicketData data) {
    final buffer = StringBuffer();

    // Agregar regla de debug al inicio
    buffer.writeln('DEBUG RULER - Verify width fits:');
    buffer.writeln(buildDebugRuler());
    buffer.writeln();

    // Ahora agregar el ticket normal
    buffer.write(buildPlainText(data));

    return buffer.toString();
  }

  // ============================================================
  // FORMATO PROFESIONAL DE TICKET (TEXTO PLANO)
  // ============================================================

  /// Genera el ticket en texto plano con formato profesional
  /// Estructura:
  /// ================================================
  ///        FULLTECH, SRL
  ///   RNC: 133080206 | Tel: +1(829)531-8442
  ///         Centro Balber 9
  /// ----
  ///
  /// FACTURA                 FECHA: 29/12/2025
  ///                         TICKET: #DEMO-001
  /// ----
  ///
  /// Cajero: Junior
  ///
  /// DATOS DEL CLIENTE:
  /// Nombre: Cliente Demo
  /// Teléfono: (809) 555-1234
  /// ----
  ///
  /// CANT  PRODUCTO                 PRECIO
  /// ----
  /// 2     Producto de Prueba       500.00
  /// 1     Otro producto            200.00
  /// ----
  ///
  ///              SUB-TOTAL: RDS 1,000.00
  ///              ITBIS (18%): RDS   180.00
  ///              -----
  ///              TOTAL: RDS 1,180.00
  ///
  /// Gracias por su compra
  /// No se aceptan devoluciones sin
  /// presentar este ticket.
  ///
  String buildPlainText(TicketData data) {
    // FUENTE ÚNICA DE VERDAD: Usar TicketRenderer
    final renderer = TicketRenderer(config: layout, company: company);
    final lines = renderer.buildLines(data);

    // Convertir líneas a string
    return lines.join('\n');
  }

  // ============================================================
  // GENERACIÓN DE PDF PROFESIONAL (para impresión térmica)
  // ============================================================

  /// Genera el ticket como documento PDF para impresión térmica
  /// Usa TicketRenderer.buildLines() como FUENTE ÚNICA de verdad para el layout
  pw.Document buildPdf(TicketData data) {
    final renderer = TicketRenderer(config: layout, company: company);
    final lines = renderer.buildLines(data);
    return buildPdfFromLines(lines, includeLogo: true);
  }

  /// Genera un PDF desde una lista de líneas ya alineadas (monoespaciado).
  /// Útil para tickets especiales de prueba (ej. regla de ancho).
  pw.Document buildPdfFromLines(
    List<String> lines, {
    required bool includeLogo,
  }) {
    final doc = pw.Document();

    // Fuente monoespaciada para preservar columnas.
    final pw.Font baseFont = layout.boldHeader
        ? pw.Font.courierBold()
        : pw.Font.courier();

    // Ancho real imprimible (ver `TicketLayoutConfig.printableWidthMm`).
    final double pageWidth = layout.printableWidthMm * PdfPageFormat.mm;

    // Alto del rollo: usar un valor grande FINITO.
    // En algunos drivers/spoolers (Windows) `double.infinity` puede imprimir en blanco.
    final double pageHeight = 2000 * PdfPageFormat.mm;

    // Márgenes (mm). En térmicas, márgenes grandes destruyen el ancho útil.
    // Además, algunos sliders guardan valores en “px”; por seguridad, clamp a un rango pequeño.
    final double marginLeftPts =
      (layout.leftMarginMm.clamp(0, 4)) * PdfPageFormat.mm;
    final double marginRightPts =
      (layout.rightMarginMm.clamp(0, 4)) * PdfPageFormat.mm;
    final double contentWidthPts = (pageWidth - marginLeftPts - marginRightPts)
        .clamp(10.0, pageWidth);

    // Fuente monoespaciada: aproximación Courier => ancho de carácter ~0.60 * fontSize.
    // Elegimos fontSize para que entren EXACTAMENTE `maxCharsPerLine` sin escalar.
    const double courierCharWidthFactor = 0.60;
    final double fittedFontSize =
        contentWidthPts / (layout.maxCharsPerLine * courierCharWidthFactor);

    // Mantener tamaño legible pero sin forzar escalado.
    // Asegurar legibilidad: si queda demasiado pequeño, el usuario percibe “en blanco”.
    final double fontSize = fittedFontSize.clamp(8.0, 10.0);

    final content = <pw.Widget>[];

    if (includeLogo && layout.showLogo && company.logoBytes != null) {
      final image = pw.MemoryImage(company.logoBytes!);
      content.add(
        pw.Center(
          child: pw.Image(
            image,
            width: layout.logoSizePx.toDouble(),
            height: layout.logoSizePx.toDouble(),
            fit: pw.BoxFit.contain,
          ),
        ),
      );
      content.add(pw.SizedBox(height: 2.0));
    }

    final fullText = lines.join('\n');
    content.add(
      pw.Text(
        fullText,
        style: pw.TextStyle(
          font: baseFont,
          fontSize: fontSize,
          lineSpacing: 1.0 * layout.lineSpacingFactor,
        ),
      ),
    );

    doc.addPage(
      pw.Page(
        pageFormat: PdfPageFormat(
          pageWidth,
          pageHeight,
          marginLeft: marginLeftPts,
          marginRight: marginRightPts,
          marginTop: layout.topMarginPx.toDouble(),
          marginBottom: layout.bottomMarginPx.toDouble(),
        ),
        build: (context) => pw.Column(
          crossAxisAlignment: pw.CrossAxisAlignment.stretch,
          mainAxisSize: pw.MainAxisSize.min,
          children: content,
        ),
      ),
    );

    return doc;
  }

  // ============================================================
  // HELPERS: Ahora la mayoría están en TicketRenderer
  // Estos helpers se mantienen solo si se usan en otros métodos
  // ============================================================
}

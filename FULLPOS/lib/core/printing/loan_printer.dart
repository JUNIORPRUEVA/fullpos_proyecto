import 'package:flutter/foundation.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import '../services/app_configuration_service.dart';
import '../../features/settings/data/printer_settings_model.dart';
import '../../features/settings/data/printer_settings_repository.dart';
import '../../features/loans/data/loan_models.dart';
import 'models/company_info.dart';
import 'models/receipt_text_utils.dart';
import 'models/ticket_builder.dart';
import 'models/ticket_layout_config.dart';
import 'thermal_printer_service.dart';

/// Impresora de documentos de préstamos para impresoras térmicas USB (80mm/58mm)
class LoanPrinter {
  LoanPrinter._();

  static String _resolveBusinessName(String headerBusinessName) {
    final header = headerBusinessName.trim();
    final headerUpper = header.toUpperCase();
    final business = appConfigService.getBusinessName().trim();
    final shouldFallback =
        header.isEmpty ||
      headerUpper == 'FULLTECH, SRL' ||
        headerUpper == 'MI NEGOCIO';
    if (shouldFallback && business.isNotEmpty) {
      return business;
    }
    return header.isNotEmpty ? header : business;
  }

  /// Imprime el contrato/resumen del préstamo
  static Future<bool> printLoanContract({
    required LoanDetailDto loanDetail,
    String? cashierName,
  }) async {
    try {
      final settings = await PrinterSettingsRepository.getOrCreate();
      final company = await CompanyInfoRepository.getCurrentCompanyInfo();
      final layout = TicketLayoutConfig.fromPrinterSettings(settings);
      final pdf = _generateLoanContractPdf(
        loanDetail: loanDetail,
        settings: settings,
        company: company,
        layout: layout,
        cashierName: cashierName,
      );

      final result = await ThermalPrinterService.printDocument(
        document: pdf,
        settings: settings,
      );

      if (result.success) {
        debugPrint('✅ Contrato de préstamo impreso: #${loanDetail.loan.id}');
      } else {
        debugPrint('❌ Error imprimiendo contrato: ${result.message}');
      }

      return result.success;
    } catch (e) {
      debugPrint('❌ Error en printLoanContract: $e');
      return false;
    }
  }

  /// Imprime un recibo de pago (versión completa con LoanDetailDto)
  static Future<bool> printPaymentReceiptFull({
    required LoanDetailDto loanDetail,
    required LoanPaymentModel payment,
    required double newBalance,
    String? cashierName,
  }) async {
    try {
      final settings = await PrinterSettingsRepository.getOrCreate();
      final company = await CompanyInfoRepository.getCurrentCompanyInfo();
      final layout = TicketLayoutConfig.fromPrinterSettings(settings);
      final pdf = _generatePaymentReceiptPdf(
        loanDetail: loanDetail,
        payment: payment,
        newBalance: newBalance,
        settings: settings,
        company: company,
        layout: layout,
        cashierName: cashierName,
      );

      final result = await ThermalPrinterService.printDocument(
        document: pdf,
        settings: settings,
      );

      if (result.success) {
        debugPrint('✅ Recibo de pago impreso: #${payment.id}');
      } else {
        debugPrint('❌ Error imprimiendo recibo: ${result.message}');
      }

      return result.success;
    } catch (e) {
      debugPrint('❌ Error en printPaymentReceiptFull: $e');
      return false;
    }
  }

  /// Imprime un recibo de pago (versión simplificada)
  static Future<bool> printPaymentReceipt({
    required int loanId,
    required String clientName,
    required double amount,
    required String method,
    required double newBalance,
    required DateTime date,
    String? cashierName,
  }) async {
    try {
      final settings = await PrinterSettingsRepository.getOrCreate();
      final company = await CompanyInfoRepository.getCurrentCompanyInfo();
      final layout = TicketLayoutConfig.fromPrinterSettings(settings);
      final pdf = _generateSimplePaymentReceiptPdf(
        loanId: loanId,
        clientName: clientName,
        amount: amount,
        method: method,
        newBalance: newBalance,
        date: date,
        settings: settings,
        company: company,
        layout: layout,
        cashierName: cashierName,
      );

      final result = await ThermalPrinterService.printDocument(
        document: pdf,
        settings: settings,
      );

      if (result.success) {
        debugPrint('✅ Recibo de pago impreso para préstamo #$loanId');
      } else {
        debugPrint('❌ Error imprimiendo recibo: ${result.message}');
      }

      return result.success;
    } catch (e) {
      debugPrint('❌ Error en printPaymentReceipt simple: $e');
      return false;
    }
  }

  /// Imprime el estado de cuenta del préstamo
  static Future<bool> printLoanStatement({
    required LoanDetailDto loanDetail,
    String? cashierName,
  }) async {
    try {
      final settings = await PrinterSettingsRepository.getOrCreate();
      final company = await CompanyInfoRepository.getCurrentCompanyInfo();
      final layout = TicketLayoutConfig.fromPrinterSettings(settings);
      final pdf = _generateLoanStatementPdf(
        loanDetail: loanDetail,
        settings: settings,
        company: company,
        layout: layout,
        cashierName: cashierName,
      );

      final result = await ThermalPrinterService.printDocument(
        document: pdf,
        settings: settings,
      );

      if (result.success) {
        debugPrint('✅ Estado de cuenta impreso: #${loanDetail.loan.id}');
      } else {
        debugPrint('❌ Error imprimiendo estado: ${result.message}');
      }

      return result.success;
    } catch (e) {
      debugPrint('❌ Error en printLoanStatement: $e');
      return false;
    }
  }

  /// Genera PDF del contrato de préstamo
  static pw.Document _generateLoanContractPdf({
    required LoanDetailDto loanDetail,
    required PrinterSettingsModel settings,
    required CompanyInfo company,
    required TicketLayoutConfig layout,
    String? cashierName,
  }) {
    final loan = loanDetail.loan;
    final w = layout.maxCharsPerLine;
    final sep = ReceiptText.line(width: w);

    void addSectionGap(List<String> lines) {
      final n = layout.sectionEmptyLines;
      for (var i = 0; i < n; i++) {
        lines.add('');
      }
    }

    String center(String text) => _centerLine(text, w);
    String twoCol(String label, String value) => _twoCol(label, value, w);
    String arrowTotal(String label, String value) => _arrowTotal(label, value, w);

    final lines = <String>[];

    // Header
    final businessName = company.name.trim().isNotEmpty
        ? company.name.trim()
        : _resolveBusinessName(settings.headerBusinessName);
    lines.add(center(businessName.toUpperCase()));
    final phone = company.primaryPhone ?? settings.headerPhone;
    if ((phone ?? '').trim().isNotEmpty) {
      lines.add(center('Tel: ${phone!.trim()}'));
    }
    lines.add(sep);
    addSectionGap(lines);

    lines.add(center('*** CONTRATO DE PRESTAMO ***'));
    lines.add(center('Prestamo #${loan.id}'));
    lines.add(sep);
    addSectionGap(lines);

    final createdDate = DateTime.fromMillisecondsSinceEpoch(loan.createdAtMs);
    lines.add(center(_formatDate(createdDate)));
    lines.add(sep);
    addSectionGap(lines);

    lines.add('CLIENTE:');
    lines.add(ReceiptText.fitText(loanDetail.clientName, w));
    lines.add(sep);
    addSectionGap(lines);

    lines.add('DETALLES DEL PRESTAMO:');
    lines.add(twoCol('Tipo', _translateLoanType(loan.type)));
    lines.add(arrowTotal('Capital', _formatCurrency(loan.principal)));
    lines.add(twoCol('Tasa interes', '${loan.interestRate}%'));
    lines.add(twoCol('Modo', _translateInterestMode(loan.interestMode)));
    lines.add(twoCol('Frecuencia', _translateFrequency(loan.frequency)));
    lines.add(twoCol('Cuotas', '${loan.installmentsCount}'));
    final startDate = DateTime.fromMillisecondsSinceEpoch(loan.startDateMs);
    lines.add(twoCol('Fecha inicio', _formatDateShort(startDate)));
    lines.add(sep);
    addSectionGap(lines);

    lines.add(arrowTotal('Total a pagar', _formatCurrency(loan.totalDue)));
    if (loanDetail.installments.isNotEmpty && loan.installmentsCount > 0) {
      final cuotaAmount = loan.totalDue / loan.installmentsCount;
      lines.add(arrowTotal('Cuota', _formatCurrency(cuotaAmount)));
    }
    lines.add(sep);
    addSectionGap(lines);

    if (loanDetail.collateral != null) {
      final col = loanDetail.collateral!;
      lines.add('GARANTIA:');
      for (final wrapped in _wrapToWidth(col.description, w)) {
        lines.add(wrapped);
      }
      if (col.serial != null && col.serial!.trim().isNotEmpty) {
        lines.add(ReceiptText.fitText('Serial: ${col.serial!.trim()}', w));
      }
      if (col.estimatedValue != null) {
        lines.add(arrowTotal('Valor est.', _formatCurrency(col.estimatedValue!)));
      }
      lines.add(sep);
      addSectionGap(lines);
    }

    lines.add('CALENDARIO DE PAGOS:');
    final numW = 3;
    var dateW = 10;
    final amtMinW = 10;
    var amtW = (w - numW - dateW - 2).clamp(amtMinW, w);
    if (numW + dateW + amtW + 2 > w) {
      dateW = (w - numW - amtMinW - 2).clamp(6, 10);
      amtW = (w - numW - dateW - 2).clamp(amtMinW, w);
    }
    lines.add(
      '${ReceiptText.padRight('#', numW)} '
      '${ReceiptText.padRight('FECHA', dateW)} '
      '${ReceiptText.padLeft('MONTO', amtW)}',
    );
    for (final inst in loanDetail.installments) {
      final dueDate = DateTime.fromMillisecondsSinceEpoch(inst.dueDateMs);
      lines.add(
        '${ReceiptText.padRight('${inst.number}', numW)} '
        '${ReceiptText.padRight(_formatDateShort(dueDate), dateW)} '
        '${ReceiptText.padLeft(_formatCurrency(inst.amountDue), amtW)}',
      );
    }
    lines.add(sep);
    addSectionGap(lines);

    if (loan.note != null && loan.note!.trim().isNotEmpty) {
      lines.add('Nota:');
      for (final wrapped in _wrapToWidth(loan.note!.trim(), w)) {
        lines.add(wrapped);
      }
      lines.add(sep);
      addSectionGap(lines);
    }

    if (cashierName != null && cashierName.trim().isNotEmpty) {
      lines.add(ReceiptText.fitText('Atendido por: ${cashierName.trim()}', w));
    }

    addSectionGap(lines);
    if (settings.footerMessage.trim().isNotEmpty) {
      for (final wrapped in _wrapToWidth(settings.footerMessage.trim(), w)) {
        lines.add(center(wrapped));
      }
    }
    addSectionGap(lines);
    lines.add(ReceiptText.fitText('CLIENTE: ___________________________', w));
    lines.add(ReceiptText.fitText('NEGOCIO: ___________________________', w));

    if (settings.autoCut == 1) {
      lines.add('');
      lines.add('');
      lines.add('');
      lines.add('');
    }

    final builder = TicketBuilder(layout: layout, company: company);
    return builder.buildPdfFromLines(lines, includeLogo: true);
  }

  /// Genera PDF del recibo de pago
  static pw.Document _generatePaymentReceiptPdf({
    required LoanDetailDto loanDetail,
    required LoanPaymentModel payment,
    required double newBalance,
    required PrinterSettingsModel settings,
    required CompanyInfo company,
    required TicketLayoutConfig layout,
    String? cashierName,
  }) {
    final loan = loanDetail.loan;
    final w = layout.maxCharsPerLine;
    final sep = ReceiptText.line(width: w);

    void addSectionGap(List<String> lines) {
      final n = layout.sectionEmptyLines;
      for (var i = 0; i < n; i++) {
        lines.add('');
      }
    }

    String center(String text) => _centerLine(text, w);
    String twoCol(String label, String value) => _twoCol(label, value, w);
    String arrowTotal(String label, String value) => _arrowTotal(label, value, w);

    final lines = <String>[];

    final businessName = company.name.trim().isNotEmpty
        ? company.name.trim()
        : _resolveBusinessName(settings.headerBusinessName);
    lines.add(center(businessName.toUpperCase()));
    final phone = company.primaryPhone ?? settings.headerPhone;
    if ((phone ?? '').trim().isNotEmpty) {
      lines.add(center('Tel: ${phone!.trim()}'));
    }
    lines.add(sep);
    addSectionGap(lines);

    lines.add(center('*** RECIBO DE PAGO ***'));
    lines.add(center('Pago #${payment.id ?? "---"}'));
    lines.add(sep);
    addSectionGap(lines);

    final paymentDate = DateTime.fromMillisecondsSinceEpoch(payment.paidAtMs);
    lines.add(center(_formatDate(paymentDate)));
    lines.add(sep);
    addSectionGap(lines);

    lines.add(twoCol('Cliente', loanDetail.clientName));
    lines.add(twoCol('Prestamo #', '${loan.id}'));
    lines.add(sep);
    addSectionGap(lines);

    lines.add('DETALLE DEL PAGO:');
    lines.add(twoCol('Metodo', _translatePaymentMethod(payment.method)));
    lines.add(arrowTotal('MONTO PAGADO', _formatCurrency(payment.amount)));
    lines.add(sep);
    addSectionGap(lines);

    lines.add('ESTADO DEL PRESTAMO:');
    lines.add(arrowTotal('Total prestamo', _formatCurrency(loan.totalDue)));
    lines.add(arrowTotal('Pagado antes', _formatCurrency(loan.totalDue - loan.balance)));
    lines.add(arrowTotal('Este pago', _formatCurrency(payment.amount)));
    lines.add(arrowTotal('Nuevo balance', _formatCurrency(newBalance)));

    if (newBalance <= 0) {
      lines.add('');
      lines.add(center('*** PRESTAMO PAGADO ***'));
    }

    lines.add(sep);
    addSectionGap(lines);

    if (payment.note != null && payment.note!.trim().isNotEmpty) {
      lines.add('Nota:');
      for (final wrapped in _wrapToWidth(payment.note!.trim(), w)) {
        lines.add(wrapped);
      }
      lines.add(sep);
      addSectionGap(lines);
    }

    if (cashierName != null && cashierName.trim().isNotEmpty) {
      lines.add(ReceiptText.fitText('Recibido por: ${cashierName.trim()}', w));
    }

    addSectionGap(lines);
    if (settings.footerMessage.trim().isNotEmpty) {
      for (final wrapped in _wrapToWidth(settings.footerMessage.trim(), w)) {
        lines.add(center(wrapped));
      }
    }
    lines.add(center('Conserve este recibo'));

    if (settings.autoCut == 1) {
      lines.add('');
      lines.add('');
      lines.add('');
      lines.add('');
    }

    final builder = TicketBuilder(layout: layout, company: company);
    return builder.buildPdfFromLines(lines, includeLogo: true);
  }

  /// Genera PDF del recibo de pago (versión simplificada)
  static pw.Document _generateSimplePaymentReceiptPdf({
    required int loanId,
    required String clientName,
    required double amount,
    required String method,
    required double newBalance,
    required DateTime date,
    required PrinterSettingsModel settings,
    required CompanyInfo company,
    required TicketLayoutConfig layout,
    String? cashierName,
  }) {
    final w = layout.maxCharsPerLine;
    final sep = ReceiptText.line(width: w);

    void addSectionGap(List<String> lines) {
      final n = layout.sectionEmptyLines;
      for (var i = 0; i < n; i++) {
        lines.add('');
      }
    }

    String center(String text) => _centerLine(text, w);
    String twoCol(String label, String value) => _twoCol(label, value, w);
    String arrowTotal(String label, String value) => _arrowTotal(label, value, w);

    final lines = <String>[];

    final businessName = company.name.trim().isNotEmpty
        ? company.name.trim()
        : _resolveBusinessName(settings.headerBusinessName);
    lines.add(center(businessName.toUpperCase()));
    final phone = company.primaryPhone ?? settings.headerPhone;
    if ((phone ?? '').trim().isNotEmpty) {
      lines.add(center('Tel: ${phone!.trim()}'));
    }
    lines.add(sep);
    addSectionGap(lines);

    lines.add(center('*** RECIBO DE PAGO ***'));
    lines.add(sep);
    addSectionGap(lines);
    lines.add(center(_formatDate(date)));
    lines.add(sep);
    addSectionGap(lines);

    lines.add(twoCol('Cliente', clientName));
    lines.add(twoCol('Prestamo #', '$loanId'));
    lines.add(sep);
    addSectionGap(lines);

    lines.add('DETALLE DEL PAGO:');
    lines.add(twoCol('Metodo', _translatePaymentMethod(method)));
    lines.add(arrowTotal('MONTO PAGADO', _formatCurrency(amount)));
    lines.add(sep);
    addSectionGap(lines);

    lines.add(arrowTotal('NUEVO SALDO', _formatCurrency(newBalance)));
    if (newBalance <= 0) {
      lines.add('');
      lines.add(center('*** PRESTAMO PAGADO ***'));
    }
    lines.add(sep);
    addSectionGap(lines);

    if (cashierName != null && cashierName.trim().isNotEmpty) {
      lines.add(ReceiptText.fitText('Recibido por: ${cashierName.trim()}', w));
    }

    addSectionGap(lines);
    if (settings.footerMessage.trim().isNotEmpty) {
      for (final wrapped in _wrapToWidth(settings.footerMessage.trim(), w)) {
        lines.add(center(wrapped));
      }
    }
    lines.add(center('Gracias por su pago'));

    if (settings.autoCut == 1) {
      lines.add('');
      lines.add('');
      lines.add('');
      lines.add('');
    }

    final builder = TicketBuilder(layout: layout, company: company);
    return builder.buildPdfFromLines(lines, includeLogo: true);
  }

  /// Genera PDF del estado de cuenta
  static pw.Document _generateLoanStatementPdf({
    required LoanDetailDto loanDetail,
    required PrinterSettingsModel settings,
    required CompanyInfo company,
    required TicketLayoutConfig layout,
    String? cashierName,
  }) {
    final loan = loanDetail.loan;
    final w = layout.maxCharsPerLine;
    final sep = ReceiptText.line(width: w);

    void addSectionGap(List<String> lines) {
      final n = layout.sectionEmptyLines;
      for (var i = 0; i < n; i++) {
        lines.add('');
      }
    }

    String center(String text) => _centerLine(text, w);
    String twoCol(String label, String value) => _twoCol(label, value, w);
    String arrowTotal(String label, String value) => _arrowTotal(label, value, w);

    final lines = <String>[];

    final businessName = company.name.trim().isNotEmpty
        ? company.name.trim()
        : _resolveBusinessName(settings.headerBusinessName);
    lines.add(center(businessName.toUpperCase()));
    lines.add(sep);
    addSectionGap(lines);
    lines.add(center('*** ESTADO DE CUENTA ***'));
    lines.add(center('Prestamo #${loan.id}'));
    lines.add(sep);
    addSectionGap(lines);
    lines.add(center('Fecha: ${_formatDate(DateTime.now())}'));
    lines.add(sep);
    addSectionGap(lines);

    lines.add(twoCol('Cliente', loanDetail.clientName));
    lines.add(sep);
    addSectionGap(lines);

    lines.add('RESUMEN:');
    lines.add(arrowTotal('Capital', _formatCurrency(loan.principal)));
    lines.add(twoCol('Interes', '${loan.interestRate}%'));
    lines.add(arrowTotal('Total deuda', _formatCurrency(loan.totalDue)));
    lines.add(arrowTotal('Total pagado', _formatCurrency(loan.totalDue - loan.balance)));
    lines.add(arrowTotal('Balance', _formatCurrency(loan.balance)));
    lines.add(twoCol('Estado', _translateStatus(loan.status)));
    lines.add(sep);
    addSectionGap(lines);

    lines.add('CUOTAS:');

    final numW = 3;
    var dateW = 10;
    final statusW = 1;
    final amtMinW = 10;
    var amtW = (w - numW - dateW - statusW - 3).clamp(amtMinW, w);
    if (numW + dateW + amtW + statusW + 3 > w) {
      dateW = (w - numW - statusW - amtMinW - 3).clamp(6, 10);
      amtW = (w - numW - dateW - statusW - 3).clamp(amtMinW, w);
    }
    lines.add(
      '${ReceiptText.padRight('#', numW)} '
      '${ReceiptText.padRight('FECHA', dateW)} '
      '${ReceiptText.padLeft('DEBE', amtW)} '
      '${ReceiptText.padRight('E', statusW)}',
    );
    for (final inst in loanDetail.installments) {
      final dueDate = DateTime.fromMillisecondsSinceEpoch(inst.dueDateMs);
      final statusIcon = inst.isPaid
          ? '✓'
          : (inst.isPartial ? '~' : (inst.isOverdue ? '!' : ' '));
      lines.add(
        '${ReceiptText.padRight('${inst.number}', numW)} '
        '${ReceiptText.padRight(_formatDateShort(dueDate), dateW)} '
        '${ReceiptText.padLeft(_formatCurrency(inst.remainingAmount), amtW)} '
        '${ReceiptText.padRight(statusIcon, statusW)}',
      );
    }

    lines.add(sep);
    addSectionGap(lines);

    if (loanDetail.payments.isNotEmpty) {
      lines.add('HISTORIAL DE PAGOS:');
      final pDateW = 10;
      final pAmtW = 12.clamp(8, w);
      final pMethW = 3;
      final spacer = 2;
      final total = pDateW + pAmtW + pMethW + spacer;
      if (total <= w) {
        lines.add(
          '${ReceiptText.padRight('FECHA', pDateW)} '
          '${ReceiptText.padLeft('MONTO', pAmtW)} '
          '${ReceiptText.padRight('MET', pMethW)}',
        );
        for (final pay in loanDetail.payments) {
          final payDate = DateTime.fromMillisecondsSinceEpoch(pay.paidAtMs);
          final method = _translatePaymentMethod(pay.method);
          final meth3 = method.length >= 3
              ? method.substring(0, 3).toUpperCase()
              : method.toUpperCase().padRight(3);
          lines.add(
            '${ReceiptText.padRight(_formatDateShort(payDate), pDateW)} '
            '${ReceiptText.padLeft(_formatCurrency(pay.amount), pAmtW)} '
            '${ReceiptText.padRight(meth3, pMethW)}',
          );
        }
      } else {
        for (final pay in loanDetail.payments) {
          final payDate = DateTime.fromMillisecondsSinceEpoch(pay.paidAtMs);
          final method = _translatePaymentMethod(pay.method);
          lines.add(
            '${_formatDateShort(payDate)}  ${_formatCurrency(pay.amount)}  ${method}',
          );
        }
      }
      lines.add(sep);
      addSectionGap(lines);
    }

    if (cashierName != null && cashierName.trim().isNotEmpty) {
      lines.add(ReceiptText.fitText('Impreso por: ${cashierName.trim()}', w));
    }

    addSectionGap(lines);
    if (settings.footerMessage.trim().isNotEmpty) {
      for (final wrapped in _wrapToWidth(settings.footerMessage.trim(), w)) {
        lines.add(center(wrapped));
      }
    }

    if (settings.autoCut == 1) {
      lines.add('');
      lines.add('');
      lines.add('');
      lines.add('');
    }

    final builder = TicketBuilder(layout: layout, company: company);
    return builder.buildPdfFromLines(lines, includeLogo: true);
  }

  // ============================================================
  // HELPERS DE TEXTO (monoespaciado, ancho fijo)
  // ============================================================

  static String _centerLine(String text, int width) {
    final t = text.trim();
    if (width <= 0) return '';
    if (t.length >= width) return t.substring(0, width);
    final left = ((width - t.length) / 2).floor();
    final right = width - t.length - left;
    return ' ' * left + t + ' ' * right;
  }

  static String _twoCol(String label, String value, int width) {
    final v = value.trim();
    if (width <= 0) return '';
    if (v.length >= width) return v.substring(v.length - width);

    final space = width - v.length;
    final labelMax = (space - 1).clamp(0, width);
    final l = label.trim();
    final lFit = l.length > labelMax ? l.substring(0, labelMax) : l;
    return lFit.padRight(labelMax) + ' ' + v;
  }

  static String _arrowTotal(String label, String value, int width) {
    const arrow = ' --> ';
    final l = label.trim();
    final v = value.trim();
    final left = '$l$arrow';
    if (width <= 0) return '';
    if (left.length >= width) return left.substring(0, width);

    final availableForValue = width - left.length;
    if (availableForValue <= 0) return left.substring(0, width);

    if (v.length <= availableForValue) {
      return left + v.padLeft(availableForValue);
    }
    return left + v.substring(v.length - availableForValue);
  }

  static List<String> _wrapToWidth(String text, int width) {
    if (width <= 0) return const [''];
    final cleaned = text.replaceAll(RegExp(r'\s+'), ' ').trim();
    if (cleaned.isEmpty) return const [''];

    final words = cleaned.split(' ');
    final out = <String>[];
    var current = '';

    for (final word in words) {
      if (word.length > width) {
        if (current.isNotEmpty) {
          out.add(ReceiptText.fitText(current, width));
          current = '';
        }
        for (var i = 0; i < word.length; i += width) {
          final end = (i + width) > word.length ? word.length : (i + width);
          out.add(ReceiptText.fitText(word.substring(i, end), width));
        }
        continue;
      }

      if (current.isEmpty) {
        current = word;
      } else if (current.length + 1 + word.length <= width) {
        current = '$current $word';
      } else {
        out.add(ReceiptText.fitText(current, width));
        current = word;
      }
    }

    if (current.isNotEmpty) out.add(ReceiptText.fitText(current, width));
    return out;
  }

  // === HELPERS ===
  static pw.Widget _buildRow(
    String label,
    String value,
    pw.Font font,
    double fontSize,
  ) {
    return pw.Row(
      mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
      children: [
        pw.Text(
          label,
          style: pw.TextStyle(font: font, fontSize: fontSize),
        ),
        pw.Text(
          value,
          style: pw.TextStyle(font: font, fontSize: fontSize),
        ),
      ],
    );
  }

  static String _formatDate(DateTime date) {
    final d = date.day.toString().padLeft(2, '0');
    final m = date.month.toString().padLeft(2, '0');
    final y = date.year;
    final h = date.hour.toString().padLeft(2, '0');
    final min = date.minute.toString().padLeft(2, '0');
    final s = date.second.toString().padLeft(2, '0');
    return '$d/$m/$y $h:$min:$s';
  }

  static String _formatDateShort(DateTime date) {
    final d = date.day.toString().padLeft(2, '0');
    final m = date.month.toString().padLeft(2, '0');
    final y = date.year;
    return '$d/$m/$y';
  }

  static String _formatCurrency(double value) {
    return '\$${value.toStringAsFixed(2)}';
  }

  static String _translateLoanType(String type) {
    switch (type) {
      case 'secured':
        return 'Con Garantía';
      case 'unsecured':
        return 'Sin Garantía';
      default:
        return type;
    }
  }

  static String _translateInterestMode(String mode) {
    switch (mode) {
      case 'interest_per_installment':
        return 'Por Cuota';
      case 'fixed_interest':
        return 'Fijo';
      default:
        return mode;
    }
  }

  static String _translateFrequency(String freq) {
    switch (freq) {
      case 'weekly':
        return 'Semanal';
      case 'biweekly':
        return 'Quincenal';
      case 'monthly':
        return 'Mensual';
      case 'single':
        return 'Pago Único';
      default:
        return freq;
    }
  }

  static String _translatePaymentMethod(String method) {
    switch (method.toLowerCase()) {
      case 'cash':
        return 'Efectivo';
      case 'card':
        return 'Tarjeta';
      case 'transfer':
        return 'Transferencia';
      default:
        return method;
    }
  }

  static String _translateStatus(String status) {
    switch (status) {
      case 'OPEN':
        return 'Activo';
      case 'OVERDUE':
        return 'Vencido';
      case 'PAID':
        return 'Pagado';
      case 'CANCELLED':
        return 'Cancelado';
      default:
        return status;
    }
  }
}

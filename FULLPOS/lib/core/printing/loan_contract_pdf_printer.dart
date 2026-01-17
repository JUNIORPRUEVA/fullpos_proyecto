import 'dart:typed_data';

import 'package:intl/intl.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;

import '../../features/clients/data/client_model.dart';
import '../../features/loans/data/loan_models.dart';
import 'models/company_info.dart';

class LoanContractPdfPrinter {
  LoanContractPdfPrinter._();

  /// Genera un contrato de préstamo en PDF:
  /// - Estilo formal (texto plano, sin logo ni íconos)
  /// - Incluye datos de empresa (CompanyInfo), cliente y préstamo completo
  /// - Incluye ANEXO con tabla de cuotas y próximo pago
  static Future<Uint8List> generatePdf({
    required LoanDetailDto loanDetail,
    required CompanyInfo company,
    ClientModel? client,
    String? cashierName,
    String? representativeCedula,
    DateTime? generatedAt,
  }) async {
    final pdf = pw.Document();

    String safeValue(String? value) {
      final v = (value ?? '').trim();
      return v.isEmpty ? 'N/D' : v;
    }

    final now = generatedAt ?? DateTime.now();
    final dateFormat = DateFormat('dd/MM/yyyy');
    final dateTimeFormat = DateFormat('dd/MM/yyyy HH:mm');
    final currencyFormat = NumberFormat.currency(locale: 'es_DO', symbol: 'RD\$');
    final percentFormat = NumberFormat('0.##', 'es_DO');

    final loan = loanDetail.loan;
    final createdDate = DateTime.fromMillisecondsSinceEpoch(loan.createdAtMs);
    final startDate = DateTime.fromMillisecondsSinceEpoch(loan.startDateMs);

    final companyName =
        (company.name).trim().isEmpty ? 'Mi Negocio' : company.name.trim();
    final companyRncValue = (company.rnc ?? '').trim();
    final hasCompanyRnc = companyRncValue.isNotEmpty;
    final companyAddress = safeValue(company.address);
    final companyPhone = safeValue(company.primaryPhone);

    final representativeName = safeValue(cashierName);
    final representativeId = (representativeCedula ?? '').trim();

    final clientName = safeValue(client?.nombre ?? loanDetail.clientName);
    final clientPhone = safeValue(client?.telefono);
    final clientAddress = safeValue(client?.direccion);
    final clientIdLabel = _clientIdLabel(client);
    final clientIdValue = _clientIdValue(client);

    String money(double value) => currencyFormat.format(value);
    String percent(double value) => '${percentFormat.format(value)}%';

    String sanitizeMultiline(String? value) {
      final v = (value ?? '').trim();
      if (v.isEmpty) return '';
      return v.replaceAll('\r\n', '\n').replaceAll('\r', '\n');
    }

    String amountInWordsDop(double value) {
      final abs = value.abs();
      final pesos = abs.floor();
      final centavos = ((abs - pesos) * 100).round().clamp(0, 99);
      final words = _spanishNumberToWords(pesos).toUpperCase();
      final cents = centavos.toString().padLeft(2, '0');
      return '$words PESOS DOMINICANOS CON $cents/100';
    }

    final contractNumber = loan.id?.toString().trim().isEmpty == false
        ? loan.id!.toString()
        : 'N/D';

    final installmentsSorted = [...loanDetail.installments]
      ..sort((a, b) => a.number.compareTo(b.number));

    final nextInstallment = loanDetail.nextPendingInstallment;
    final nextInstallmentText = nextInstallment == null
        ? 'N/D'
        : '${dateFormat.format(nextInstallment.dueDate)} - '
            '${money(nextInstallment.remainingAmount)}';

    final loanType = _translateLoanType(loan.type);
    final frequencyLabel = _translateFrequency(loan.frequency);
    final interestModeLabel = _translateInterestMode(loan.interestMode);

    final termText =
        '${loan.installmentsCount} cuota(s) (${frequencyLabel.toLowerCase()})';

    final notes = sanitizeMultiline(loan.note);

    String interestClauseText() {
      final rate = percent(loan.interestRate);
      if (loan.interestMode == InterestMode.interestPerInstallment) {
        return 'El PRESTAMO devengara un interes ordinario de $rate por cada '
            'cuota, calculado conforme a la modalidad "Interes por cuota".';
      }
      if (loan.interestMode == InterestMode.fixedInterest) {
        return 'El PRESTAMO devengara un interes ordinario fijo de $rate aplicado '
            'una sola vez al capital, conforme a la modalidad "Interes fijo".';
      }
      return 'El PRESTAMO devengara un interes ordinario de $rate conforme a la '
          'modalidad configurada.';
    }

    String lateFeeText() {
      final lateFee = loan.lateFee;
      if (lateFee <= 0) {
        return 'En caso de atraso, se aplicaran los cargos por mora conforme a '
            'las politicas del PRESTAMISTA.';
      }
      return 'En caso de atraso en el pago de una cuota, EL DEUDOR pagara un '
          'recargo por mora de ${money(lateFee)} por cada cuota vencida, sin '
          'perjuicio de los gastos de cobro razonables.';
    }

    String collateralText() {
      final collateral = loanDetail.collateral;
      if (loan.type != LoanType.secured || collateral == null) {
        return 'Sin garantia prendaria especifica.';
      }
      final lines = <String>[
        'Garantia prendaria sobre: ${safeValue(collateral.description)}.',
      ];
      final serial = (collateral.serial ?? '').trim();
      final condition = (collateral.condition ?? '').trim();
      if (serial.isNotEmpty) lines.add('Serie/Identificacion: $serial.');
      if (condition.isNotEmpty) lines.add('Condicion: $condition.');
      if (collateral.estimatedValue != null) {
        lines.add('Valor estimado: ${money(collateral.estimatedValue!)}.');
      }
      lines.add(
        'La garantia permanecera afectada al pago total del PRESTAMO, y podra '
        'ser ejecutada conforme a la ley y a este contrato en caso de incumplimiento.',
      );
      return lines.join(' ');
    }

    pw.Widget h1(String text) {
      return pw.Text(
        text,
        textAlign: pw.TextAlign.center,
        style: pw.TextStyle(
          fontSize: 14,
          fontWeight: pw.FontWeight.bold,
          letterSpacing: 0.8,
        ),
      );
    }

    pw.Widget h2(String text) {
      return pw.Padding(
        padding: const pw.EdgeInsets.only(top: 10, bottom: 4),
        child: pw.Text(
          text,
          style: pw.TextStyle(fontSize: 11, fontWeight: pw.FontWeight.bold),
        ),
      );
    }

    pw.Widget pText(String text) {
      return pw.Padding(
        padding: const pw.EdgeInsets.only(bottom: 6),
        child: pw.Text(
          text,
          textAlign: pw.TextAlign.justify,
          style: const pw.TextStyle(fontSize: 10, lineSpacing: 3),
        ),
      );
    }

    pw.Widget kvLine(String label, String value) {
      return pw.Padding(
        padding: const pw.EdgeInsets.only(bottom: 2),
        child: pw.Row(
          crossAxisAlignment: pw.CrossAxisAlignment.start,
          children: [
            pw.SizedBox(
              width: 155,
              child: pw.Text(
                label,
                style: pw.TextStyle(fontSize: 9, fontWeight: pw.FontWeight.bold),
              ),
            ),
            pw.Expanded(
              child: pw.Text(value, style: const pw.TextStyle(fontSize: 9)),
            ),
          ],
        ),
      );
    }

    pw.Widget annexInstallmentsTable() {
      final headers = <String>[
        'No.',
        'Vencimiento',
        'Monto',
        'Pagado',
        'Pendiente',
        'Estado',
      ];

      final rows = installmentsSorted.map((i) {
        final status = _translateInstallmentStatus(i.status);
        final due = dateFormat.format(i.dueDate);
        final remaining =
            (i.remainingAmount < 0 ? 0.0 : i.remainingAmount).toDouble();
        return <String>[
          i.number.toString(),
          due,
          money(i.amountDue),
          money(i.amountPaid),
          money(remaining),
          status,
        ];
      }).toList();

      return pw.TableHelper.fromTextArray(
        headers: headers,
        data: rows,
        headerStyle: pw.TextStyle(fontSize: 8, fontWeight: pw.FontWeight.bold),
        cellStyle: const pw.TextStyle(fontSize: 8),
        headerAlignment: pw.Alignment.centerLeft,
        cellAlignment: pw.Alignment.centerLeft,
        border: pw.TableBorder.all(color: PdfColors.grey600, width: 0.5),
        cellPadding: const pw.EdgeInsets.symmetric(horizontal: 4, vertical: 3),
      );
    }

    pdf.addPage(
      pw.MultiPage(
        pageFormat: PdfPageFormat.letter,
        margin: const pw.EdgeInsets.fromLTRB(48, 46, 48, 46),
        theme: pw.ThemeData.withFont(
          base: pw.Font.helvetica(),
          bold: pw.Font.helveticaBold(),
          italic: pw.Font.helveticaOblique(),
          boldItalic: pw.Font.helveticaBoldOblique(),
        ),
        header: (context) {
          if (context.pageNumber == 1) return pw.SizedBox();
          return pw.Container(
            alignment: pw.Alignment.centerRight,
            padding: const pw.EdgeInsets.only(bottom: 6),
            child: pw.Text(
              'Contrato No. $contractNumber - Pagina ${context.pageNumber}',
              style: const pw.TextStyle(fontSize: 8),
            ),
          );
        },
        footer: (context) {
          return pw.Container(
            padding: const pw.EdgeInsets.only(top: 8),
            child: pw.Row(
              mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
              children: [
                pw.Text(companyName, style: const pw.TextStyle(fontSize: 8)),
                pw.Text(
                  'Generado: ${dateTimeFormat.format(now)}',
                  style: const pw.TextStyle(fontSize: 8),
                ),
              ],
            ),
          );
        },
        build: (context) {
          final contractDate = dateFormat.format(now);
          final loanStart = dateFormat.format(startDate);
          final loanCreated = dateFormat.format(createdDate);

          final location =
              companyAddress == 'N/D' ? 'Republica Dominicana' : companyAddress;

          return [
            h1('CONTRATO DE PRESTAMO CON INTERES'),
            pw.SizedBox(height: 6),
            pw.Text(
              'No. $contractNumber',
              textAlign: pw.TextAlign.center,
              style: const pw.TextStyle(fontSize: 10),
            ),
            pw.SizedBox(height: 12),
            pw.Text(
              'En $location, Republica Dominicana, a la fecha $contractDate.',
              style: const pw.TextStyle(fontSize: 10),
            ),
            pw.SizedBox(height: 10),
            h2('I. PARTES CONTRATANTES'),
            pText(
              'De una parte, $companyName, sociedad/comercio organizado conforme a las '
              'leyes de la Republica Dominicana,'
              '${hasCompanyRnc ? ' con RNC No. $companyRncValue,' : ''} domicilio en '
              '$companyAddress, telefono $companyPhone, debidamente representada por '
              '$representativeName'
              '${representativeId.isNotEmpty ? ', portador(a) de la cedula No. $representativeId' : ''}, '
              'quien en lo adelante se denominara "EL PRESTAMISTA".',
            ),
            pText(
              'Y de la otra parte, $clientName, dominicano(a), mayor de edad, '
              '${clientIdLabel.isEmpty ? '' : 'portador(a) de la $clientIdLabel No. $clientIdValue, '}'
              'domiciliado(a) en $clientAddress, telefono $clientPhone, '
              'quien en lo adelante se denominara "EL DEUDOR".',
            ),
            pText(
              'Ambas partes, reconociendose capacidad legal suficiente para contratar, '
              'ACUERDAN suscribir el presente Contrato de Prestamo con Interes, el cual '
              'se regira por las siguientes clausulas:',
            ),
            h2('II. DECLARACIONES'),
            pText(
              'EL PRESTAMISTA declara que cuenta con la capacidad y disponibilidad para otorgar '
              'el prestamo objeto de este contrato, y que el mismo se realiza bajo las '
              'condiciones economicas pactadas libremente.',
            ),
            pText(
              'EL DEUDOR declara que solicita el prestamo de forma voluntaria, conoce las condiciones '
              'de pago, interes y mora, y se obliga a pagar el capital e intereses conforme al '
              'calendario establecido, declarando que la informacion suministrada es real y verificable.',
            ),
            h2('III. CLAUSULAS'),
            pText(
              'PRIMERA (Objeto). EL PRESTAMISTA otorga a EL DEUDOR un prestamo por la suma de '
              '${money(loan.principal)} (${amountInWordsDop(loan.principal)}), en lo adelante \"EL PRESTAMO\", '
              'obligandose EL DEUDOR a devolver el capital mas los intereses pactados.',
            ),
            pText(
              'SEGUNDA (Entrega del dinero). EL DEUDOR reconoce haber recibido a satisfaccion el monto '
              'del PRESTAMO, en fecha $loanCreated, salvo constancia distinta.',
            ),
            pText(
              'TERCERA (Plazo). El plazo del PRESTAMO sera de $termText, iniciando el $loanStart '
              'y finalizando con el pago total del saldo, salvo pago anticipado conforme a este contrato.',
            ),
            pText('CUARTA (Interes ordinario). ${interestClauseText()}'),
            pText(
              'QUINTA (Forma de pago). EL DEUDOR pagara el PRESTAMO mediante el plan de cuotas '
              'detallado en el ANEXO A (tabla de pagos), por un total a pagar de ${money(loan.totalDue)}. '
              'El proximo pago corresponde a: $nextInstallmentText. '
              'Los pagos podran realizarse en caja del PRESTAMISTA o por el medio acordado por las partes.',
            ),
            pText(
              'SEXTA (Pago anticipado). EL DEUDOR podra realizar pagos anticipados totales o parciales, '
              'aplicandose primero a cargos vencidos (si los hubiere) y luego a capital, salvo pacto distinto.',
            ),
            pText('SEPTIMA (Mora e interes moratorio). ${lateFeeText()}'),
            pText(
              'OCTAVA (Gastos y costos de cobro). Todo gasto razonable de cobro, notificacion y honorarios '
              'profesionales derivados del incumplimiento seran asumidos por EL DEUDOR, debidamente justificados.',
            ),
            pText('NOVENA (Garantia). ${collateralText()}'),
            pText(
              'DECIMA (Incumplimiento y vencimiento anticipado). Se considerara incumplimiento, entre otros: '
              'a) falta de pago de una o mas cuotas; b) suministro de informacion falsa relevante; '
              'c) negativa injustificada a cumplir con lo pactado. En caso de incumplimiento, EL PRESTAMISTA '
              'podra declarar el vencimiento anticipado, haciendo exigible el saldo (capital + interes + mora + gastos).',
            ),
            pText(
              'DECIMA PRIMERA (Notificaciones). Las notificaciones se realizaran a las direcciones y telefonos '
              'indicados por las partes, considerandose valida la ultima informacion registrada.',
            ),
            pText(
              'DECIMA SEGUNDA (Confidencialidad). Las partes se obligan a mantener confidencialidad sobre los '
              'terminos del prestamo, salvo requerimiento de autoridad competente o para fines de cobro.',
            ),
            pText(
              'DECIMA TERCERA (Modificaciones). Toda modificacion debera constar por escrito y firmada por '
              'ambas partes.',
            ),
            pText(
              'DECIMA CUARTA (Nulidad parcial). Si alguna clausula fuese declarada nula, ello no afectara '
              'las demas, las cuales permaneceran vigentes.',
            ),
            pText(
              'DECIMA QUINTA (Ley aplicable y jurisdiccion). El presente contrato se regira por las leyes '
              'de la Republica Dominicana. Para cualquier controversia, las partes se someten a los tribunales '
              'competentes del domicilio del PRESTAMISTA, salvo pacto distinto.',
            ),
            if (notes.isNotEmpty) ...[
              h2('IV. NOTAS / OBSERVACIONES'),
              pw.Text(
                notes,
                style: const pw.TextStyle(fontSize: 10, lineSpacing: 3),
              ),
            ],
            h2('V. FIRMAS'),
            pw.SizedBox(height: 8),
            pw.Row(
              crossAxisAlignment: pw.CrossAxisAlignment.start,
              children: [
                pw.Expanded(
                  child: _signatureBlock(
                    title: 'POR EL PRESTAMISTA (EMPRESA)',
                    name: companyName,
                    idLabel: hasCompanyRnc ? 'RNC' : '',
                    idValue: hasCompanyRnc ? companyRncValue : '',
                    extra:
                        'Representada por: $representativeName'
                        '${representativeId.isNotEmpty ? ' - Cedula: $representativeId' : ''}',
                  ),
                ),
                pw.SizedBox(width: 10),
                pw.Expanded(
                  child: _signatureBlock(
                    title: 'POR EL DEUDOR (CLIENTE)',
                    name: clientName,
                    idLabel: clientIdLabel,
                    idValue: clientIdValue,
                    extra: clientPhone == 'N/D' ? null : 'Tel: $clientPhone',
                  ),
                ),
              ],
            ),
            pw.SizedBox(height: 10),
            pw.Row(
              children: [
                pw.Expanded(child: _signatureLine(title: 'TESTIGO 1 (Opcional)')),
                pw.SizedBox(width: 10),
                pw.Expanded(child: _signatureLine(title: 'TESTIGO 2 (Opcional)')),
              ],
            ),
            pw.SizedBox(height: 14),
            h2('ANEXO A: TABLA DE PAGOS / AMORTIZACION'),
            pw.SizedBox(height: 6),
            pw.Column(
              crossAxisAlignment: pw.CrossAxisAlignment.start,
              children: [
                kvLine('Tipo de prestamo:', loanType),
                kvLine('Frecuencia:', frequencyLabel),
                kvLine('Interes (modalidad):', interestModeLabel),
                kvLine('Capital:', money(loan.principal)),
                kvLine('Interes:', percent(loan.interestRate)),
                kvLine('Total a pagar:', money(loan.totalDue)),
                kvLine('Pagado a la fecha:', money(loan.paidAmount)),
                kvLine('Balance:', money(loan.balance)),
                kvLine('Proximo pago:', nextInstallmentText),
              ],
            ),
            pw.SizedBox(height: 10),
            annexInstallmentsTable(),
          ];
        },
      ),
    );

    return pdf.save();
  }

  static pw.Widget _signatureLine({required String title}) {
    return pw.Container(
      padding: const pw.EdgeInsets.symmetric(vertical: 10, horizontal: 8),
      child: pw.Column(
        crossAxisAlignment: pw.CrossAxisAlignment.start,
        children: [
          pw.Text(title, style: pw.TextStyle(fontSize: 9, fontWeight: pw.FontWeight.bold)),
          pw.SizedBox(height: 28),
          pw.Container(height: 0.8, color: PdfColors.grey700),
          pw.SizedBox(height: 4),
          pw.Text('Firma', style: pw.TextStyle(fontSize: 8, color: PdfColors.grey700)),
        ],
      ),
    );
  }

  static pw.Widget _signatureBlock({
    required String title,
    required String name,
    required String idLabel,
    required String idValue,
    String? extra,
  }) {
    return pw.Container(
      padding: const pw.EdgeInsets.all(10),
      child: pw.Column(
        crossAxisAlignment: pw.CrossAxisAlignment.start,
        children: [
          pw.Text(title, style: pw.TextStyle(fontSize: 9, fontWeight: pw.FontWeight.bold)),
          pw.SizedBox(height: 6),
          pw.Text(name.trim().isEmpty ? 'N/D' : name.trim(), style: const pw.TextStyle(fontSize: 9)),
          if (idLabel.trim().isNotEmpty)
            pw.Text(
              '$idLabel: ${idValue.trim().isEmpty ? 'N/D' : idValue.trim()}',
              style: pw.TextStyle(fontSize: 8, color: PdfColors.grey700),
            ),
          if (extra != null && extra.trim().isNotEmpty)
            pw.Text(extra.trim(), style: pw.TextStyle(fontSize: 8, color: PdfColors.grey700)),
          pw.SizedBox(height: 22),
          pw.Container(height: 0.8, color: PdfColors.grey700),
          pw.SizedBox(height: 4),
          pw.Text('Firma', style: pw.TextStyle(fontSize: 8, color: PdfColors.grey700)),
        ],
      ),
    );
  }

  static String _translateLoanType(String type) {
    switch (type) {
      case LoanType.secured:
        return 'Prestamo con garantia (empeno)';
      case LoanType.unsecured:
        return 'Prestamo sin garantia';
      default:
        return type;
    }
  }

  static String _translateFrequency(String frequency) {
    switch (frequency) {
      case LoanFrequency.weekly:
        return 'Semanal';
      case LoanFrequency.biweekly:
        return 'Quincenal';
      case LoanFrequency.monthly:
        return 'Mensual';
      case LoanFrequency.single:
        return 'Pago unico';
      default:
        return frequency;
    }
  }

  static String _translateInterestMode(String mode) {
    switch (mode) {
      case InterestMode.interestPerInstallment:
        return 'Interes por cuota';
      case InterestMode.fixedInterest:
        return 'Interes fijo';
      default:
        return mode;
    }
  }

  static String _translateInstallmentStatus(String status) {
    switch (status) {
      case InstallmentStatus.pending:
        return 'Pendiente';
      case InstallmentStatus.paid:
        return 'Pagada';
      case InstallmentStatus.partial:
        return 'Parcial';
      case InstallmentStatus.overdue:
        return 'Vencida';
      default:
        return status;
    }
  }

  static String _clientIdLabel(ClientModel? client) {
    final cedula = (client?.cedula ?? '').trim();
    final rnc = (client?.rnc ?? '').trim();
    if (cedula.isNotEmpty) return 'Cedula';
    if (rnc.isNotEmpty) return 'RNC';
    return '';
  }

  static String _clientIdValue(ClientModel? client) {
    final cedula = (client?.cedula ?? '').trim();
    final rnc = (client?.rnc ?? '').trim();
    if (cedula.isNotEmpty) return cedula;
    if (rnc.isNotEmpty) return rnc;
    return '';
  }

  // Conversion simple de numeros a letras (espanol), suficiente para montos en DOP.
  static String _spanishNumberToWords(int number) {
    if (number == 0) return 'cero';
    if (number < 0) return 'menos ${_spanishNumberToWords(-number)}';

    String unit(int n) {
      const units = [
        '',
        'uno',
        'dos',
        'tres',
        'cuatro',
        'cinco',
        'seis',
        'siete',
        'ocho',
        'nueve',
      ];
      return units[n];
    }

    String tenToNineteen(int n) {
      const specials = {
        10: 'diez',
        11: 'once',
        12: 'doce',
        13: 'trece',
        14: 'catorce',
        15: 'quince',
        16: 'dieciseis',
        17: 'diecisiete',
        18: 'dieciocho',
        19: 'diecinueve',
      };
      return specials[n] ?? '';
    }

    String tens(int n) {
      const tensMap = {
        20: 'veinte',
        30: 'treinta',
        40: 'cuarenta',
        50: 'cincuenta',
        60: 'sesenta',
        70: 'setenta',
        80: 'ochenta',
        90: 'noventa',
      };
      return tensMap[n] ?? '';
    }

    String hundreds(int n) {
      if (n == 100) return 'cien';
      const hundredsMap = {
        100: 'ciento',
        200: 'doscientos',
        300: 'trescientos',
        400: 'cuatrocientos',
        500: 'quinientos',
        600: 'seiscientos',
        700: 'setecientos',
        800: 'ochocientos',
        900: 'novecientos',
      };
      return hundredsMap[n] ?? '';
    }

    String underHundred(int n) {
      if (n < 10) return unit(n);
      if (n < 20) return tenToNineteen(n);
      if (n < 30) {
        if (n == 20) return 'veinte';
        return 'veinti${unit(n - 20)}';
      }
      final t = (n ~/ 10) * 10;
      final u = n % 10;
      if (u == 0) return tens(t);
      return '${tens(t)} y ${unit(u)}';
    }

    String underThousand(int n) {
      if (n < 100) return underHundred(n);
      final h = (n ~/ 100) * 100;
      final rest = n % 100;
      final hText = hundreds(h == 100 ? 100 : h);
      if (rest == 0) return hText;
      return '$hText ${underHundred(rest)}'.trim();
    }

    String thousands(int n) {
      if (n < 1000) return underThousand(n);
      final k = n ~/ 1000;
      final rest = n % 1000;
      final prefix = k == 1 ? 'mil' : '${underThousand(k)} mil';
      if (rest == 0) return prefix;
      return '$prefix ${underThousand(rest)}';
    }

    String millions(int n) {
      if (n < 1000000) return thousands(n);
      final m = n ~/ 1000000;
      final rest = n % 1000000;
      final prefix = m == 1 ? 'un millon' : '${thousands(m)} millones';
      if (rest == 0) return prefix;
      return '$prefix ${thousands(rest)}';
    }

    return millions(number).trim();
  }
}

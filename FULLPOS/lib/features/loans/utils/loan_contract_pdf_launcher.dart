import 'dart:io';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:printing/printing.dart';
import 'package:share_plus/share_plus.dart';

import '../../../core/constants/app_colors.dart';
import '../../../core/constants/app_sizes.dart';
import '../../../core/printing/loan_contract_pdf_printer.dart';
import '../../../core/printing/models/company_info.dart';
import '../../../core/session/session_manager.dart';
import '../../../core/window/window_service.dart';
import '../../settings/data/business_settings_repository.dart';
import '../../clients/data/clients_repository.dart';
import '../data/loan_models.dart';

class LoanContractPdfLauncher {
  LoanContractPdfLauncher._();

  static Future<void> openPreviewDialog({
    required BuildContext context,
    required LoanDetailDto loanDetail,
  }) async {
    final company = await CompanyInfoRepository.getCurrentCompanyInfo();
    final client = await ClientsRepository.getById(loanDetail.loan.clientId);
    final cashierName = await SessionManager.displayName() ?? 'Usuario';

    final businessSettings = await BusinessSettingsRepository().loadSettings();
    final fixedRepName =
        (businessSettings.loanContractRepresentativeName ?? '').trim();
    final fixedRepCedula =
        (businessSettings.loanContractRepresentativeCedula ?? '').trim();

    final representativeName = fixedRepName.isNotEmpty ? fixedRepName : cashierName;
    final representativeCedula =
        fixedRepCedula.isNotEmpty ? fixedRepCedula : null;

    final bytes = await LoanContractPdfPrinter.generatePdf(
      loanDetail: loanDetail,
      company: company,
      client: client,
      cashierName: representativeName,
      representativeCedula: representativeCedula,
    );

    final loanId = loanDetail.loan.id ?? 0;
    final suggestedFileName = 'contrato_prestamo_$loanId.pdf';
    final shareText = 'Contrato de préstamo #$loanId';

    if (!context.mounted) return;

    await showDialog<void>(
      context: context,
      builder: (dialogContext) {
        return StatefulBuilder(
          builder: (builderContext, setState) {
            var busy = false;

            Future<T> runBusy<T>(Future<T> Function() fn) async {
              if (busy) return await fn();
              busy = true;
              setState(() {});
              try {
                return await fn();
              } finally {
                busy = false;
                setState(() {});
              }
            }

            return Dialog(
              child: SizedBox(
                width: 1040,
                height: 760,
                child: Column(
                  children: [
                    Padding(
                      padding: const EdgeInsets.all(AppSizes.paddingM),
                      child: Row(
                        children: [
                          const Expanded(
                            child: Text(
                              'Contrato de Préstamo (PDF)',
                              style: TextStyle(fontWeight: FontWeight.w600),
                            ),
                          ),
                          OutlinedButton.icon(
                            onPressed: busy
                                ? null
                                : () {
                                    runBusy(() async {
                                      final file = await _savePdf(
                                        bytes: bytes,
                                        fileName: suggestedFileName,
                                      );
                                      if (!dialogContext.mounted) return;
                                      ScaffoldMessenger.of(
                                        dialogContext,
                                      ).showSnackBar(
                                        SnackBar(
                                          content: Text(
                                            'PDF guardado: ${file.path}',
                                          ),
                                          backgroundColor: AppColors.success,
                                        ),
                                      );
                                    });
                                  },
                            icon: const Icon(Icons.download, size: 18),
                            label: const Text('Descargar'),
                          ),
                          const SizedBox(width: 8),
                          OutlinedButton.icon(
                            onPressed: busy
                                ? null
                                : () {
                                    runBusy(() async {
                                      await Printing.layoutPdf(
                                        name: suggestedFileName,
                                        onLayout: (format) async => bytes,
                                      );
                                    });
                                  },
                            icon: const Icon(Icons.print, size: 18),
                            label: const Text('Imprimir'),
                          ),
                          const SizedBox(width: 8),
                          ElevatedButton.icon(
                            onPressed: busy
                                ? null
                                : () {
                                    runBusy(() async {
                                      final file = await _writePdfToTemp(
                                        bytes: bytes,
                                        fileName: suggestedFileName,
                                      );
                                      await Share.shareXFiles([
                                        XFile(file.path),
                                      ], text: shareText);
                                    });
                                  },
                            icon: const Icon(Icons.share, size: 18),
                            label: const Text('Compartir'),
                          ),
                          const SizedBox(width: 8),
                          TextButton(
                            onPressed: busy
                                ? null
                                : () => Navigator.of(dialogContext).pop(),
                            child: const Text('Cerrar'),
                          ),
                        ],
                      ),
                    ),
                    const Divider(height: 1),
                    Expanded(
                      child: Theme(
                        data: Theme.of(dialogContext).copyWith(
                          colorScheme: Theme.of(dialogContext).colorScheme
                              .copyWith(
                                primary: AppColors.teal700,
                                secondary: AppColors.gold,
                              ),
                        ),
                        child: PdfPreview(
                          build: (format) async => bytes,
                          canChangeOrientation: false,
                          canChangePageFormat: false,
                          allowPrinting: false,
                          allowSharing: false,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            );
          },
        );
      },
    );
  }

  static Future<File> _writePdfToTemp({
    required Uint8List bytes,
    required String fileName,
  }) async {
    final dir = await Directory.systemTemp.createTemp('fullpos_pdf_');
    final file = File('${dir.path}${Platform.pathSeparator}$fileName');
    await file.writeAsBytes(bytes, flush: true);
    return file;
  }

  static Future<File> _savePdf({
    required Uint8List bytes,
    required String fileName,
  }) async {
    final outputFile = await WindowService.runWithSystemDialog(
      () => FilePicker.platform.saveFile(
        dialogTitle: 'Guardar PDF',
        fileName: fileName,
        type: FileType.custom,
        allowedExtensions: const ['pdf'],
      ),
    );

    if (outputFile == null) {
      throw Exception('Guardado cancelado');
    }

    final file = File(outputFile);
    await file.writeAsBytes(bytes, flush: true);
    return file;
  }
}

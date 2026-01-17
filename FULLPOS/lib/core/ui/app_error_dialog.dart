import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import '../constants/app_colors.dart';
import '../constants/app_sizes.dart';
import '../errors/app_exception.dart';

class AppErrorDialog extends StatefulWidget {
  const AppErrorDialog({
    super.key,
    required this.exception,
    this.onRetry,
  });

  final AppException exception;
  final VoidCallback? onRetry;

  static Future<void> show(
    BuildContext context, {
    required AppException exception,
    VoidCallback? onRetry,
  }) async {
    return showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (_) => AppErrorDialog(exception: exception, onRetry: onRetry),
    );
  }

  @override
  State<AppErrorDialog> createState() => _AppErrorDialogState();
}

class _AppErrorDialogState extends State<AppErrorDialog> {
  bool _showDetails = false;

  @override
  Widget build(BuildContext context) {
    final ex = widget.exception;
    final maxContentHeight = MediaQuery.sizeOf(context).height * 0.6;

    return AlertDialog(
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(AppSizes.radiusL),
      ),
      title: Row(
        children: [
          const Icon(Icons.error_outline, color: AppColors.error),
          const SizedBox(width: AppSizes.spaceM),
          const Expanded(
            child: Text(
              'Ups… ocurrió un problema',
              style: TextStyle(fontWeight: FontWeight.w700),
            ),
          ),
        ],
      ),
      content: ConstrainedBox(
        constraints: BoxConstraints(maxWidth: 520, maxHeight: maxContentHeight),
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                ex.messageUser,
                style: const TextStyle(height: 1.25),
              ),
              if (kDebugMode) ...[
                const SizedBox(height: AppSizes.spaceM),
                InkWell(
                  onTap: () => setState(() => _showDetails = !_showDetails),
                  child: Row(
                    children: [
                      Icon(
                        _showDetails
                            ? Icons.expand_less
                            : Icons.expand_more,
                        size: 18,
                        color: AppColors.teal900,
                      ),
                      const SizedBox(width: 6),
                      Text(
                        _showDetails ? 'Ocultar detalles' : 'Ver detalles',
                        style: const TextStyle(
                          color: AppColors.teal900,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                ),
                if (_showDetails) ...[
                  const SizedBox(height: AppSizes.spaceS),
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(AppSizes.paddingM),
                    decoration: BoxDecoration(
                      color: AppColors.surfaceLightVariant,
                      borderRadius: BorderRadius.circular(AppSizes.radiusM),
                      border: Border.all(color: AppColors.surfaceLightBorder),
                    ),
                    child: SelectableText(
                      [
                        ex.messageDev,
                        if (ex.stackTrace != null) '\n\n${ex.stackTrace}',
                      ].join(),
                      style: const TextStyle(fontSize: 12),
                    ),
                  ),
                ],
              ],
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).maybePop(),
          child: const Text('Cerrar'),
        ),
        if (widget.onRetry != null)
          FilledButton.icon(
            onPressed: () {
              Navigator.of(context).maybePop();
              widget.onRetry?.call();
            },
            icon: const Icon(Icons.refresh),
            style: FilledButton.styleFrom(
              backgroundColor: AppColors.gold,
              foregroundColor: AppColors.teal900,
            ),
            label: const Text('Reintentar'),
          ),
      ],
    );
  }
}

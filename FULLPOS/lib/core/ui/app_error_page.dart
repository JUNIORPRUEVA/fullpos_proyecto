import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import '../constants/app_colors.dart';
import '../constants/app_sizes.dart';
import '../errors/app_exception.dart';

class AppErrorPage extends StatefulWidget {
  const AppErrorPage({
    super.key,
    required this.exception,
    this.onRetry,
  });

  final AppException exception;
  final VoidCallback? onRetry;

  @override
  State<AppErrorPage> createState() => _AppErrorPageState();
}

class _AppErrorPageState extends State<AppErrorPage> {
  bool _showDetails = false;

  @override
  Widget build(BuildContext context) {
    final ex = widget.exception;

    return Scaffold(
      backgroundColor: AppColors.bgDark,
      body: LayoutBuilder(
        builder: (context, constraints) {
          return SingleChildScrollView(
            padding: const EdgeInsets.all(AppSizes.paddingXL),
            child: ConstrainedBox(
              constraints: BoxConstraints(minHeight: constraints.maxHeight),
              child: Center(
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 620),
                  child: Container(
                    padding: const EdgeInsets.all(AppSizes.paddingXL),
                    decoration: BoxDecoration(
                      color: Colors.white,
                      borderRadius: BorderRadius.circular(AppSizes.radiusL),
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withOpacity(0.25),
                          blurRadius: 30,
                          offset: const Offset(0, 18),
                        ),
                      ],
                    ),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Icon(
                          Icons.error_outline,
                          color: AppColors.error,
                          size: 52,
                        ),
                        const SizedBox(height: AppSizes.spaceM),
                        const Text(
                          'Ups… ocurrió un problema',
                          style: TextStyle(
                            fontSize: 20,
                            fontWeight: FontWeight.w800,
                          ),
                          textAlign: TextAlign.center,
                        ),
                        const SizedBox(height: AppSizes.spaceS),
                        Text(
                          ex.messageUser,
                          style: const TextStyle(fontSize: 14, height: 1.25),
                          textAlign: TextAlign.center,
                        ),
                        if (kDebugMode) ...[
                          const SizedBox(height: AppSizes.spaceM),
                          InkWell(
                            onTap: () =>
                                setState(() => _showDetails = !_showDetails),
                            child: Row(
                              mainAxisAlignment: MainAxisAlignment.center,
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
                                  _showDetails
                                      ? 'Ocultar detalles'
                                      : 'Ver detalles',
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
                              padding:
                                  const EdgeInsets.all(AppSizes.paddingM),
                              decoration: BoxDecoration(
                                color: AppColors.surfaceLightVariant,
                                borderRadius:
                                    BorderRadius.circular(AppSizes.radiusM),
                                border: Border.all(
                                  color: AppColors.surfaceLightBorder,
                                ),
                              ),
                              child: SelectableText(
                                [
                                  ex.messageDev,
                                  if (ex.stackTrace != null)
                                    '\n\n${ex.stackTrace}',
                                ].join(),
                                style: const TextStyle(fontSize: 12),
                              ),
                            ),
                          ],
                        ],
                        const SizedBox(height: AppSizes.spaceL),
                        Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            TextButton.icon(
                              onPressed: () =>
                                  Navigator.of(context).maybePop(),
                              icon: const Icon(Icons.arrow_back),
                              label: const Text('Volver'),
                            ),
                            const SizedBox(width: AppSizes.spaceM),
                            if (widget.onRetry != null)
                              FilledButton.icon(
                                onPressed: widget.onRetry,
                                icon: const Icon(Icons.refresh),
                                style: FilledButton.styleFrom(
                                  backgroundColor: AppColors.gold,
                                  foregroundColor: AppColors.teal900,
                                ),
                                label: const Text('Reintentar'),
                              ),
                          ],
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ),
          );
        },
      ),
    );
  }
}

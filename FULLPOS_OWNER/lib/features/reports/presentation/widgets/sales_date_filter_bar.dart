import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';

import '../../application/sales_date_filter_controller.dart';

class SalesDateFilterBar extends ConsumerWidget {
  const SalesDateFilterBar({super.key, this.compactBreakpoint = 700});

  final double compactBreakpoint;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(salesDateFilterProvider);
    final width = MediaQuery.sizeOf(context).width;
    final isCompact = width < compactBreakpoint;

    if (isCompact) {
      return _CompactSalesDateFilter(state: state);
    }

    return _WideSalesDateFilter(state: state);
  }
}

class _WideSalesDateFilter extends ConsumerWidget {
  const _WideSalesDateFilter({required this.state});

  final SalesDateFilterState state;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final presets = SalesDatePreset.values;

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: Wrap(
        spacing: 8,
        runSpacing: 8,
        crossAxisAlignment: WrapCrossAlignment.center,
        children: [
          for (final preset in presets)
            ChoiceChip(
              avatar: Icon(presetIcon(preset), size: 16),
              label: Text(presetLabel(preset)),
              selected: state.preset == preset,
              onSelected: (_) => unawaited(_applyPreset(context, ref, preset)),
            ),
          OutlinedButton.icon(
            onPressed: state.preset == SalesDatePreset.today
                ? null
                : () => ref.read(salesDateFilterProvider.notifier).reset(),
            icon: const Icon(Icons.restart_alt_rounded, size: 18),
            label: const Text('Restablecer'),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 8),
            child: Text(
              state.fullRangeLabel,
              style: theme.textTheme.labelMedium?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _CompactSalesDateFilter extends ConsumerWidget {
  const _CompactSalesDateFilter({required this.state});

  final SalesDateFilterState state;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.fromLTRB(10, 8, 8, 8),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: Row(
        children: [
          Icon(
            Icons.calendar_today_outlined,
            size: 18,
            color: theme.colorScheme.primary,
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              selectedSalesDateRangeLine(state),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.bodyMedium?.copyWith(
                fontWeight: FontWeight.w800,
                color: theme.colorScheme.onSurface,
              ),
            ),
          ),
          const SizedBox(width: 8),
          TextButton.icon(
            onPressed: () => unawaited(_openMobileOptions(context, ref, state)),
            icon: const Icon(Icons.tune_rounded, size: 18),
            label: const Text('Filtrar'),
          ),
          IconButton(
            tooltip: 'Restablecer',
            onPressed: state.preset == SalesDatePreset.today
                ? null
                : () => ref.read(salesDateFilterProvider.notifier).reset(),
            icon: Icon(
              Icons.restart_alt_rounded,
              color: state.preset == SalesDatePreset.today
                  ? theme.colorScheme.onSurfaceVariant.withValues(alpha: 0.45)
                  : null,
            ),
          ),
        ],
      ),
    );
  }
}

Future<void> _applyPreset(
  BuildContext context,
  WidgetRef ref,
  SalesDatePreset preset,
) async {
  if (preset == SalesDatePreset.custom) {
    await _pickCustomRange(context, ref);
    return;
  }
  ref.read(salesDateFilterProvider.notifier).applyPreset(preset);
}

Future<void> _openMobileOptions(
  BuildContext context,
  WidgetRef ref,
  SalesDateFilterState state,
) async {
  final selected = await showModalBottomSheet<SalesDatePreset>(
    context: context,
    showDragHandle: true,
    backgroundColor: Theme.of(context).colorScheme.surface,
    shape: const RoundedRectangleBorder(
      borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
    ),
    builder: (context) => _MobilePresetSheet(state: state),
  );
  if (selected == null || !context.mounted) return;
  await _applyPreset(context, ref, selected);
}

class _MobilePresetSheet extends StatelessWidget {
  const _MobilePresetSheet({required this.state});

  final SalesDateFilterState state;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return SafeArea(
      top: false,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 4, 16, 16),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Filtro de ventas',
              style: theme.textTheme.titleMedium?.copyWith(
                fontWeight: FontWeight.w900,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              state.fullRangeLabel,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
                fontWeight: FontWeight.w600,
              ),
            ),
            const SizedBox(height: 12),
            for (final preset in SalesDatePreset.values) ...[
              ListTile(
                dense: true,
                contentPadding: EdgeInsets.zero,
                leading: Icon(presetIcon(preset)),
                title: Text(presetLabel(preset)),
                trailing: state.preset == preset
                    ? Icon(
                        Icons.check_circle_rounded,
                        color: theme.colorScheme.primary,
                      )
                    : null,
                onTap: () => Navigator.of(context).pop(preset),
              ),
              if (preset != SalesDatePreset.values.last)
                const Divider(height: 1),
            ],
          ],
        ),
      ),
    );
  }
}

Future<void> _pickCustomRange(BuildContext context, WidgetRef ref) async {
  final current = ref.read(salesDateFilterProvider).range;
  final today = localDateOnly(DateTime.now());
  final firstAllowedDate = today.subtract(
    const Duration(days: maxSalesDateFilterDays - 1),
  );
  var start = clampLocalDate(current.start, firstAllowedDate, today);
  var end = clampLocalDate(current.end, firstAllowedDate, today);
  if (start.isAfter(end)) start = end;

  final picked = await showDateRangePicker(
    context: context,
    firstDate: firstAllowedDate,
    lastDate: today,
    initialDateRange: DateTimeRange(start: start, end: end),
    helpText: 'Rango personalizado',
    cancelText: 'Cancelar',
    confirmText: 'Aplicar',
    fieldStartLabelText: 'Fecha inicial',
    fieldEndLabelText: 'Fecha final',
    errorInvalidRangeText: 'La fecha inicial no puede ser mayor que la final',
  );
  if (picked == null) return;
  ref
      .read(salesDateFilterProvider.notifier)
      .applyCustomRange(picked.start, picked.end);
}

String shortRangeLabel(DateTime start, DateTime end) {
  final format = DateFormat('dd/MM/yyyy');
  return '${format.format(start)} - ${format.format(end)}';
}

String selectedSalesDateRangeLine(SalesDateFilterState state) {
  final range = state.range;
  final start = localDateOnly(range.start);
  final end = localDateOnly(range.end);
  final prefix = state.preset == SalesDatePreset.custom
      ? 'Personalizado'
      : presetLabel(state.preset);
  if (isSameLocalDate(start, end)) {
    return '$prefix · ${_friendlyDate(start)}';
  }
  final suffix = start.year == end.year
      ? '${_friendlyDateWithoutYear(start)} - ${_friendlyDate(end)}'
      : '${_friendlyDate(start)} - ${_friendlyDate(end)}';
  return '$prefix · $suffix';
}

String _friendlyDate(DateTime value) {
  return '${value.day} ${_monthAbbreviation(value.month)} ${value.year}';
}

String _friendlyDateWithoutYear(DateTime value) {
  return '${value.day} ${_monthAbbreviation(value.month)}';
}

String _monthAbbreviation(int month) {
  const months = [
    'ene',
    'feb',
    'mar',
    'abr',
    'may',
    'jun',
    'jul',
    'ago',
    'sep',
    'oct',
    'nov',
    'dic',
  ];
  if (month < 1 || month > months.length) return '';
  return months[month - 1];
}

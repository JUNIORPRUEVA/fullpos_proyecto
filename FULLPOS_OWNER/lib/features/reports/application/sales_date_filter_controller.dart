import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';

const maxSalesDateFilterDays = 365;
const _maxSalesDateFilterOffsetDays = maxSalesDateFilterDays - 1;

final salesDateFilterProvider =
    StateNotifierProvider<SalesDateFilterController, SalesDateFilterState>(
      (ref) => SalesDateFilterController(),
    );

enum SalesDatePreset {
  today,
  yesterday,
  week,
  fortnight,
  month,
  custom,
}

class SalesDateRange {
  const SalesDateRange({required this.start, required this.end});

  final DateTime start;
  final DateTime end;

  DateTime get startOfDay => DateTime(start.year, start.month, start.day);

  DateTime get endOfDay =>
      DateTime(end.year, end.month, end.day, 23, 59, 59, 999);

  String get fromQuery => DateFormat('yyyy-MM-dd').format(startOfDay);

  String get toQuery => DateFormat('yyyy-MM-dd').format(endOfDay);

  bool isSameAs(SalesDateRange other) {
    return isSameLocalDate(start, other.start) &&
        isSameLocalDate(end, other.end);
  }
}

class SalesDateFilterState {
  const SalesDateFilterState({
    required this.preset,
    required this.customStart,
    required this.customEnd,
  });

  factory SalesDateFilterState.initial() {
    return SalesDateFilterState.fromPreset(SalesDatePreset.week);
  }

  factory SalesDateFilterState.fromPreset(SalesDatePreset preset) {
    final range = rangeForPreset(preset);
    return SalesDateFilterState(
      preset: preset,
      customStart: range.start,
      customEnd: range.end,
    );
  }

  factory SalesDateFilterState.custom(DateTime start, DateTime end) {
    final normalized = normalizeSalesDateRange(start, end);
    return SalesDateFilterState(
      preset: SalesDatePreset.custom,
      customStart: normalized.start,
      customEnd: normalized.end,
    );
  }

  final SalesDatePreset preset;
  final DateTime customStart;
  final DateTime customEnd;

  SalesDateRange get range {
    if (preset == SalesDatePreset.custom) {
      return normalizeSalesDateRange(customStart, customEnd);
    }
    return rangeForPreset(preset);
  }

  String get label {
    switch (preset) {
      case SalesDatePreset.today:
        return 'Hoy';
      case SalesDatePreset.yesterday:
        return 'Ayer';
      case SalesDatePreset.week:
        return 'Semana';
      case SalesDatePreset.fortnight:
        return 'Quincena';
      case SalesDatePreset.month:
        return 'Mes';
      case SalesDatePreset.custom:
        return rangeLabel(range.start, range.end);
    }
  }

  String get fullRangeLabel => rangeLabel(range.start, range.end);

  bool hasSameRangeAs(SalesDateFilterState other) {
    return range.isSameAs(other.range) && preset == other.preset;
  }
}

class SalesDateFilterController extends StateNotifier<SalesDateFilterState> {
  SalesDateFilterController() : super(SalesDateFilterState.initial());

  void applyPreset(SalesDatePreset preset) {
    if (preset == SalesDatePreset.custom) return;
    state = SalesDateFilterState.fromPreset(preset);
  }

  void applyCustomRange(DateTime start, DateTime end) {
    state = SalesDateFilterState.custom(start, end);
  }

  void reset() {
    state = SalesDateFilterState.initial();
  }
}

SalesDateRange rangeForPreset(SalesDatePreset preset) {
  final today = localDateOnly(DateTime.now());
  switch (preset) {
    case SalesDatePreset.today:
      return SalesDateRange(start: today, end: today);
    case SalesDatePreset.yesterday:
      final day = today.subtract(const Duration(days: 1));
      return SalesDateRange(start: day, end: day);
    case SalesDatePreset.week:
      return SalesDateRange(
        start: today.subtract(const Duration(days: 6)),
        end: today,
      );
    case SalesDatePreset.fortnight:
      return SalesDateRange(
        start: today.subtract(const Duration(days: 14)),
        end: today,
      );
    case SalesDatePreset.month:
      return SalesDateRange(
        start: today.subtract(const Duration(days: 29)),
        end: today,
      );
    case SalesDatePreset.custom:
      return SalesDateRange(start: today, end: today);
  }
}

SalesDateRange normalizeSalesDateRange(DateTime start, DateTime end) {
  final today = localDateOnly(DateTime.now());
  final firstAllowedDate = today.subtract(
    const Duration(days: _maxSalesDateFilterOffsetDays),
  );
  var normalizedStart = clampLocalDate(
    localDateOnly(start),
    firstAllowedDate,
    today,
  );
  var normalizedEnd = clampLocalDate(
    localDateOnly(end),
    firstAllowedDate,
    today,
  );
  if (normalizedStart.isAfter(normalizedEnd)) {
    normalizedStart = normalizedEnd;
  }
  return SalesDateRange(start: normalizedStart, end: normalizedEnd);
}

DateTime localDateOnly(DateTime value) {
  final local = value.toLocal();
  return DateTime(local.year, local.month, local.day);
}

DateTime clampLocalDate(DateTime value, DateTime firstDate, DateTime lastDate) {
  if (value.isBefore(firstDate)) return firstDate;
  if (value.isAfter(lastDate)) return lastDate;
  return value;
}

bool isSameLocalDate(DateTime left, DateTime right) {
  final localLeft = localDateOnly(left);
  final localRight = localDateOnly(right);
  return localLeft.year == localRight.year &&
      localLeft.month == localRight.month &&
      localLeft.day == localRight.day;
}

String rangeLabel(DateTime start, DateTime end) {
  final format = DateFormat('dd/MM/yyyy');
  final startDay = localDateOnly(start);
  final endDay = localDateOnly(end);
  if (isSameLocalDate(startDay, endDay)) {
    return format.format(startDay);
  }
  return '${format.format(startDay)} - ${format.format(endDay)}';
}

String presetLabel(SalesDatePreset preset) {
  switch (preset) {
    case SalesDatePreset.today:
      return 'Hoy';
    case SalesDatePreset.yesterday:
      return 'Ayer';
    case SalesDatePreset.week:
      return 'Semana';
    case SalesDatePreset.fortnight:
      return 'Quincena';
    case SalesDatePreset.month:
      return 'Mes';
    case SalesDatePreset.custom:
      return 'Personalizado';
  }
}

IconData presetIcon(SalesDatePreset preset) {
  switch (preset) {
    case SalesDatePreset.today:
      return Icons.today_outlined;
    case SalesDatePreset.yesterday:
      return Icons.history_toggle_off_rounded;
    case SalesDatePreset.week:
      return Icons.date_range_outlined;
    case SalesDatePreset.fortnight:
      return Icons.calendar_view_week_outlined;
    case SalesDatePreset.month:
      return Icons.calendar_month_outlined;
    case SalesDatePreset.custom:
      return Icons.edit_calendar_outlined;
  }
}

import 'package:flutter_test/flutter_test.dart';
import 'package:fullpos_owner/features/reports/application/sales_date_filter_controller.dart';

void main() {
  group('SalesDateFilterController', () {
    test('presets calculate local date ranges consistently', () {
      final today = localDateOnly(DateTime.now());

      expect(rangeForPreset(SalesDatePreset.today).start, today);
      expect(rangeForPreset(SalesDatePreset.today).end, today);

      final yesterday = today.subtract(const Duration(days: 1));
      expect(rangeForPreset(SalesDatePreset.yesterday).start, yesterday);
      expect(rangeForPreset(SalesDatePreset.yesterday).end, yesterday);

      final dayBeforeYesterday = today.subtract(const Duration(days: 2));
      expect(
        rangeForPreset(SalesDatePreset.dayBeforeYesterday).start,
        dayBeforeYesterday,
      );
      expect(
        rangeForPreset(SalesDatePreset.dayBeforeYesterday).end,
        dayBeforeYesterday,
      );

      expect(
        rangeForPreset(SalesDatePreset.last5Days).start,
        today.subtract(const Duration(days: 4)),
      );
      expect(rangeForPreset(SalesDatePreset.last5Days).end, today);

      expect(
        rangeForPreset(SalesDatePreset.lastWeek).start,
        today.subtract(const Duration(days: 6)),
      );
      expect(rangeForPreset(SalesDatePreset.lastWeek).end, today);
    });

    test('custom range normalizes dates to full local days', () {
      final today = localDateOnly(DateTime.now());
      final start = today.subtract(const Duration(days: 9));
      final end = today.subtract(const Duration(days: 2));

      final state = SalesDateFilterState.custom(
        DateTime(start.year, start.month, start.day, 18, 45),
        DateTime(end.year, end.month, end.day, 3, 15),
      );

      expect(state.preset, SalesDatePreset.custom);
      expect(
        state.range.startOfDay,
        DateTime(start.year, start.month, start.day),
      );
      expect(
        state.range.endOfDay,
        DateTime(end.year, end.month, end.day, 23, 59, 59, 999),
      );
      expect(state.range.fromQuery, isNot(contains('T')));
      expect(state.range.toQuery, isNot(contains('T')));
    });

    test('custom range cannot invert start and end dates', () {
      final today = localDateOnly(DateTime.now());
      final state = SalesDateFilterState.custom(
        today,
        today.subtract(const Duration(days: 4)),
      );

      expect(state.range.start, state.range.end);
    });
  });
}

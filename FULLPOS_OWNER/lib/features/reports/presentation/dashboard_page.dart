import 'dart:async';
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../../core/theme/app_colors.dart';
import '../data/report_models.dart';
import '../data/reports_repository.dart';
import '../data/sale_realtime_service.dart';

class DashboardPage extends ConsumerStatefulWidget {
	const DashboardPage({super.key});

	@override
	ConsumerState<DashboardPage> createState() => _DashboardPageState();
}

class _DashboardPageState extends ConsumerState<DashboardPage>
		with WidgetsBindingObserver {
	static const _refreshInterval = Duration(seconds: 60);

	Timer? _autoRefreshTimer;
	StreamSubscription<SaleRealtimeMessage>? _saleRealtimeSubscription;
	bool _refreshInFlight = false;
	bool _reloadRequested = false;

	SalesSummary? _summary;
	ExpensesSummary? _expensesSummary;
	List<SalesByDay> _byDay = const [];
	bool _loading = true;
	String _warningMessage = '';
	late DateTime _from;
	late DateTime _to;

	@override
	void initState() {
		super.initState();
		final now = DateTime.now();
		_from = DateTime(now.year, now.month, now.day);
		_to = now;
		WidgetsBinding.instance.addObserver(this);
		_load(showLoading: true);
		_autoRefreshTimer = Timer.periodic(_refreshInterval, (_) {
			_load(showLoading: false);
		});
		_saleRealtimeSubscription = ref
				.read(saleRealtimeServiceProvider)
				.stream
				.listen((_) => _load(showLoading: false));
	}

	@override
	void dispose() {
		_autoRefreshTimer?.cancel();
		_saleRealtimeSubscription?.cancel();
		WidgetsBinding.instance.removeObserver(this);
		super.dispose();
	}

	@override
	void didChangeAppLifecycleState(AppLifecycleState state) {
		if (state == AppLifecycleState.resumed) {
			_load(showLoading: false);
		}
	}

	Future<void> _load({required bool showLoading}) async {
		if (_refreshInFlight) {
			_reloadRequested = true;
			return;
		}
		_refreshInFlight = true;
		_reloadRequested = false;

		if (showLoading && mounted) {
			setState(() {
				_loading = true;
				_warningMessage = '';
			});
		}

		final repo = ref.read(reportsRepositoryProvider);
		final formatter = DateFormat('yyyy-MM-dd');
		final warnings = <String>[];

		try {
			final results = await Future.wait<Object?>([
				_safeLoad<Object?>(
					loader: () => repo.salesSummary(
						formatter.format(_from),
						formatter.format(_to),
					),
					fallback: const SalesSummary(total: 0, count: 0, average: 0),
					onError: () => warnings.add('No se pudo cargar el resumen de ventas.'),
				),
				_safeLoad<Object?>(
					loader: () => repo.salesByDay(
						formatter.format(_from),
						formatter.format(_to),
					),
					fallback: const <SalesByDay>[],
					onError: () => warnings.add('No se pudo cargar la tendencia diaria.'),
				),
				_safeLoad<Object?>(
					loader: () => repo.expensesSummary(
						formatter.format(_from),
						formatter.format(_to),
					),
					fallback: null,
					onError: () => warnings.add('No se pudo cargar el resumen de gastos.'),
				),
			]);

			if (!mounted) return;
			setState(() {
				_summary = results[0] as SalesSummary;
				_byDay = results[1] as List<SalesByDay>;
				_expensesSummary = results[2] as ExpensesSummary?;
				_warningMessage = warnings.join(' ');
				_loading = false;
			});
		} catch (_) {
			if (!mounted) return;
			setState(() {
				_summary ??= const SalesSummary(total: 0, count: 0, average: 0);
				_warningMessage =
					'No se pudieron actualizar todos los datos, pero el panel sigue disponible.';
				_loading = false;
			});
		} finally {
			_refreshInFlight = false;
			if (_reloadRequested && mounted) {
				_reloadRequested = false;
				unawaited(_load(showLoading: false));
			}
		}
	}

	Future<T> _safeLoad<T>({
		required Future<T> Function() loader,
		required T fallback,
		required VoidCallback onError,
	}) async {
		try {
			return await loader();
		} catch (_) {
			onError();
			return fallback;
		}
	}

	void _updateRange(DateTime from, DateTime to) {
		setState(() {
			_from = from;
			_to = to;
		});
		_load(showLoading: true);
	}

	void _applyQuickRange(int days) {
		final now = DateTime.now();
		final start = days == 0
				? DateTime(now.year, now.month, now.day)
				: DateTime(now.year, now.month, now.day)
						.subtract(Duration(days: days - 1));
		_updateRange(start, now);
	}

	@override
	Widget build(BuildContext context) {
		final theme = Theme.of(context);
		final currency = NumberFormat.currency(locale: 'es_DO', symbol: 'RD\$');
		final integer = NumberFormat.decimalPattern('es_DO');
		final summary = _summary;
		final expensesSummary = _expensesSummary;
		final total = (summary?.total ?? 0).toDouble();
		final totalCost = (summary?.totalCost ?? 0).toDouble();
		final expensesTotal = (expensesSummary?.total ?? 0).toDouble();
		final profit = summary == null
				? 0.0
				: (summary.profit != 0 || totalCost != 0)
						? summary.profit.toDouble()
						: total - totalCost;
		final margin = total > 0 ? (profit / total) * 100 : 0.0;
		final services = summary?.count ?? 0;
		final chartData = _byDay.length > 30 ? _byDay.sublist(_byDay.length - 30) : _byDay;
		final activeDays = chartData.isEmpty ? 0 : chartData.length;
		final averageDay = activeDays == 0 ? 0.0 : total / activeDays;
		final peakDay = chartData.isEmpty
				? null
				: chartData.reduce((left, right) => right.total > left.total ? right : left);
		final formatter = DateFormat('yyyy-MM-dd');
		final fromStr = formatter.format(_from);
		final toStr = formatter.format(_to);

		return LayoutBuilder(
			builder: (context, constraints) {
				final width = constraints.maxWidth;
				final columns = width >= 1100 ? 4 : width >= 700 ? 2 : 1;
				final wideHeader = width >= 920;
				final metricRatio = width >= 1100 ? 2.35 : width >= 700 ? 2.8 : 3.1;
				final chartHeight = width >= 1100 ? 300.0 : width >= 700 ? 250.0 : 210.0;

				return SingleChildScrollView(
					padding: const EdgeInsets.all(12),
					child: Column(
						crossAxisAlignment: CrossAxisAlignment.start,
						children: [
							if (_loading)
								const Padding(
									padding: EdgeInsets.only(bottom: 10),
									child: LinearProgressIndicator(minHeight: 3),
								),
							if (_warningMessage.isNotEmpty) ...[
								_WarningBanner(
									message: _warningMessage,
									onRetry: () => _load(showLoading: true),
								),
								const SizedBox(height: 12),
							],
							_SurfaceCard(
								child: wideHeader
										? Row(
												crossAxisAlignment: CrossAxisAlignment.start,
												children: [
													Expanded(
														child: _DashboardHeader(
															fromStr: fromStr,
															toStr: toStr,
														),
													),
													const SizedBox(width: 16),
													SizedBox(
														width: 420,
														child: _FilterBar(
															from: _from,
															to: _to,
															onChange: _updateRange,
															onQuickRange: _applyQuickRange,
														),
													),
												],
										)
										: Column(
												crossAxisAlignment: CrossAxisAlignment.start,
												children: [
													_DashboardHeader(fromStr: fromStr, toStr: toStr),
													const SizedBox(height: 12),
													_FilterBar(
														from: _from,
														to: _to,
														onChange: _updateRange,
														onQuickRange: _applyQuickRange,
													),
												],
										),
							),
							const SizedBox(height: 12),
							GridView.count(
								crossAxisCount: columns,
								childAspectRatio: metricRatio,
								mainAxisSpacing: 12,
								crossAxisSpacing: 12,
								shrinkWrap: true,
								physics: const NeverScrollableScrollPhysics(),
								children: [
									_MetricCard(
										title: 'Ventas',
										value: currency.format(total),
										icon: Icons.payments_outlined,
										color: theme.colorScheme.primary,
									),
									_MetricCard(
										title: 'Gastos',
										value: currency.format(expensesTotal),
										icon: Icons.receipt_long_outlined,
										color: AppColors.warning,
									),
									_MetricCard(
										title: 'Ganancias',
										value: currency.format(profit),
										icon: Icons.trending_up_outlined,
										color: profit >= 0 ? AppColors.success : AppColors.danger,
									),
									_MetricCard(
										title: 'Servicios realizados',
										value: integer.format(services),
										icon: Icons.design_services_outlined,
										color: theme.colorScheme.secondary,
									),
								],
							),
							const SizedBox(height: 12),
							_SurfaceCard(
								child: Column(
									crossAxisAlignment: CrossAxisAlignment.start,
									children: [
										Row(
											crossAxisAlignment: CrossAxisAlignment.start,
											children: [
												Expanded(
													child: Column(
														crossAxisAlignment: CrossAxisAlignment.start,
														children: [
															Text(
																'Rendimiento de ventas',
																style: theme.textTheme.titleLarge?.copyWith(
																	fontWeight: FontWeight.w800,
																	letterSpacing: -0.3,
																),
															),
															const SizedBox(height: 4),
															Text(
																chartData.isEmpty
																		? 'Sin datos recientes'
																		: chartData.length == 1
																				? 'Ultimo dia'
																				: 'Ultimos ${chartData.length} dias',
																style: theme.textTheme.bodyMedium?.copyWith(
																	color: theme.colorScheme.onSurfaceVariant,
																	fontWeight: FontWeight.w600,
																),
															),
														],
													),
												),
												if (chartData.isNotEmpty)
													FilledButton.tonalIcon(
														onPressed: () {
															context.go('/sales/list?from=$fromStr&to=$toStr');
														},
														icon: const Icon(Icons.visibility_outlined),
														label: const Text('Detalle'),
													),
											],
										),
										const SizedBox(height: 12),
										Wrap(
											spacing: 8,
											runSpacing: 8,
											children: [
												_StatPill(
													label: 'Promedio',
													value: currency.format(averageDay),
													color: theme.colorScheme.primary,
												),
												_StatPill(
													label: 'Margen',
													value: '${margin.toStringAsFixed(1)}%',
													color: AppColors.success,
												),
												_StatPill(
													label: 'Costo',
													value: currency.format(totalCost),
													color: AppColors.warning,
												),
												_StatPill(
													label: 'Pico',
													value: peakDay == null
															? '--'
															: '${_formatDayLabel(peakDay.date)} · ${currency.format(peakDay.total)}',
													color: theme.colorScheme.secondary,
												),
											],
										),
										const SizedBox(height: 14),
										if (chartData.isEmpty)
											const _EmptyState()
										else
											SizedBox(
												height: chartHeight,
												child: _SalesTrendChart(data: chartData),
											),
									],
								),
							),
						],
					),
				);
			},
		);
	}
}

class _DashboardHeader extends StatelessWidget {
	const _DashboardHeader({required this.fromStr, required this.toStr});

	final String fromStr;
	final String toStr;

	@override
	Widget build(BuildContext context) {
		final theme = Theme.of(context);
		return Column(
			crossAxisAlignment: CrossAxisAlignment.start,
			children: [
				Text(
					'Dashboard de reportes',
					style: theme.textTheme.titleLarge?.copyWith(
						fontWeight: FontWeight.w800,
						letterSpacing: -0.35,
					),
				),
				const SizedBox(height: 4),
				Text(
					'Métricas clave y rendimiento diario en una vista compacta y profesional.',
					style: theme.textTheme.bodyMedium?.copyWith(
						color: theme.colorScheme.onSurfaceVariant,
						height: 1.35,
					),
				),
				const SizedBox(height: 10),
				Container(
					padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
					decoration: BoxDecoration(
						color: theme.colorScheme.surfaceContainerLowest,
						borderRadius: BorderRadius.circular(14),
						border: Border.all(color: theme.colorScheme.outlineVariant),
					),
					child: Row(
						mainAxisSize: MainAxisSize.min,
						children: [
							Icon(
								Icons.schedule_outlined,
								size: 18,
								color: theme.colorScheme.primary,
							),
							const SizedBox(width: 8),
							Flexible(
								child: Text(
									'Periodo activo: $fromStr -> $toStr',
									style: theme.textTheme.labelLarge?.copyWith(
										fontWeight: FontWeight.w700,
									),
								),
							),
						],
					),
				),
			],
		);
	}
}

class _FilterBar extends StatelessWidget {
	const _FilterBar({
		required this.from,
		required this.to,
		required this.onChange,
		required this.onQuickRange,
	});

	final DateTime from;
	final DateTime to;
	final void Function(DateTime, DateTime) onChange;
	final ValueChanged<int> onQuickRange;

	@override
	Widget build(BuildContext context) {
		final fmt = DateFormat('yyyy-MM-dd');
		final theme = Theme.of(context);

		return Wrap(
			spacing: 8,
			runSpacing: 8,
			children: [
				OutlinedButton.icon(
					onPressed: () async {
						final picked = await showDateRangePicker(
							context: context,
							firstDate: DateTime.now().subtract(const Duration(days: 365)),
							lastDate: DateTime.now().add(const Duration(days: 1)),
							initialDateRange: DateTimeRange(start: from, end: to),
						);
						if (picked != null) {
							onChange(picked.start, picked.end);
						}
					},
					icon: const Icon(Icons.calendar_month, size: 18),
					label: Text('${fmt.format(from)} · ${fmt.format(to)}'),
					style: OutlinedButton.styleFrom(
						padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
						backgroundColor: theme.colorScheme.surfaceContainerLowest,
						side: BorderSide(color: theme.colorScheme.outlineVariant),
						shape: RoundedRectangleBorder(
							borderRadius: BorderRadius.circular(14),
						),
					),
				),
				_QuickChip(label: 'Hoy', icon: Icons.today_outlined, onTap: () => onQuickRange(0)),
				_QuickChip(label: '7 días', icon: Icons.date_range_outlined, onTap: () => onQuickRange(7)),
				_QuickChip(label: '30 días', icon: Icons.insights_outlined, onTap: () => onQuickRange(30)),
			],
		);
	}
}

class _QuickChip extends StatelessWidget {
	const _QuickChip({
		required this.label,
		required this.icon,
		required this.onTap,
	});

	final String label;
	final IconData icon;
	final VoidCallback onTap;

	@override
	Widget build(BuildContext context) {
		final theme = Theme.of(context);
		return ActionChip(
			avatar: Icon(icon, size: 16),
			label: Text(label),
			backgroundColor: theme.colorScheme.surfaceContainerLowest,
			onPressed: onTap,
		);
	}
}

class _SurfaceCard extends StatelessWidget {
	const _SurfaceCard({required this.child});

	final Widget child;

	@override
	Widget build(BuildContext context) {
		final theme = Theme.of(context);
		return Container(
			width: double.infinity,
			padding: const EdgeInsets.all(16),
			decoration: BoxDecoration(
				gradient: LinearGradient(
					colors: [
						theme.colorScheme.surface,
						theme.colorScheme.surfaceContainerLowest,
					],
					begin: Alignment.topLeft,
					end: Alignment.bottomRight,
				),
				borderRadius: BorderRadius.circular(18),
				border: Border.all(color: theme.colorScheme.outlineVariant),
				boxShadow: [
					BoxShadow(
						color: Colors.black.withValues(alpha: 0.035),
						blurRadius: 14,
						offset: const Offset(0, 4),
					),
				],
			),
			child: child,
		);
	}
}

class _WarningBanner extends StatelessWidget {
	const _WarningBanner({required this.message, required this.onRetry});

	final String message;
	final VoidCallback onRetry;

	@override
	Widget build(BuildContext context) {
		final theme = Theme.of(context);
		return Container(
			padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
			decoration: BoxDecoration(
				color: AppColors.warning.withValues(alpha: 0.08),
				borderRadius: BorderRadius.circular(16),
				border: Border.all(color: AppColors.warning.withValues(alpha: 0.24)),
			),
			child: Row(
				children: [
					const Icon(Icons.info_outline, color: AppColors.warning, size: 20),
					const SizedBox(width: 10),
					Expanded(
						child: Text(
							message,
							style: theme.textTheme.bodyMedium?.copyWith(height: 1.35),
						),
					),
					TextButton(onPressed: onRetry, child: const Text('Reintentar')),
				],
			),
		);
	}
}

class _MetricCard extends StatelessWidget {
	const _MetricCard({
		required this.title,
		required this.value,
		required this.icon,
		required this.color,
	});

	final String title;
	final String value;
	final IconData icon;
	final Color color;

	@override
	Widget build(BuildContext context) {
		final theme = Theme.of(context);
		return Container(
			padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
			decoration: BoxDecoration(
				color: theme.colorScheme.surfaceContainerLowest,
				borderRadius: BorderRadius.circular(16),
				border: Border.all(color: color.withValues(alpha: 0.14)),
			),
			child: Column(
				crossAxisAlignment: CrossAxisAlignment.start,
				mainAxisAlignment: MainAxisAlignment.spaceBetween,
				children: [
					Row(
						children: [
							Container(
								width: 34,
								height: 34,
								decoration: BoxDecoration(
									color: color.withValues(alpha: 0.10),
									borderRadius: BorderRadius.circular(11),
								),
								child: Icon(icon, color: color, size: 18),
							),
							const SizedBox(width: 10),
							Expanded(
								child: Text(
									title,
									maxLines: 1,
									overflow: TextOverflow.ellipsis,
									style: theme.textTheme.labelLarge?.copyWith(
										color: color,
										fontWeight: FontWeight.w700,
									),
								),
							),
						],
					),
					const SizedBox(height: 12),
					Text(
						value,
						maxLines: 1,
						overflow: TextOverflow.ellipsis,
						style: theme.textTheme.headlineSmall?.copyWith(
							fontWeight: FontWeight.w800,
							letterSpacing: -0.6,
						),
					),
				],
			),
		);
	}
}

class _StatPill extends StatelessWidget {
	const _StatPill({
		required this.label,
		required this.value,
		required this.color,
	});

	final String label;
	final String value;
	final Color color;

	@override
	Widget build(BuildContext context) {
		final theme = Theme.of(context);
		return Container(
			padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
			decoration: BoxDecoration(
				color: theme.colorScheme.surfaceContainerLowest,
				borderRadius: BorderRadius.circular(14),
				border: Border.all(color: color.withValues(alpha: 0.18)),
			),
			child: Column(
				crossAxisAlignment: CrossAxisAlignment.start,
				children: [
					Text(
						label,
						style: theme.textTheme.labelMedium?.copyWith(
							color: theme.colorScheme.onSurfaceVariant,
							fontWeight: FontWeight.w700,
						),
					),
					const SizedBox(height: 4),
					Text(
						value,
						style: theme.textTheme.titleSmall?.copyWith(
							color: color,
							fontWeight: FontWeight.w800,
						),
					),
				],
			),
		);
	}
}

class _EmptyState extends StatelessWidget {
	const _EmptyState();

	@override
	Widget build(BuildContext context) {
		final theme = Theme.of(context);
		return Container(
			width: double.infinity,
			padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 28),
			decoration: BoxDecoration(
				color: theme.colorScheme.surfaceContainerLowest,
				borderRadius: BorderRadius.circular(16),
				border: Border.all(color: theme.colorScheme.outlineVariant),
			),
			child: Column(
				children: [
					Icon(
						Icons.show_chart_outlined,
						size: 28,
						color: theme.colorScheme.onSurfaceVariant,
					),
					const SizedBox(height: 10),
					Text(
						'Sin ventas en el rango seleccionado.',
						style: theme.textTheme.titleSmall?.copyWith(fontWeight: FontWeight.w700),
					),
					const SizedBox(height: 4),
					Text(
						'Prueba con otro rango para ver el rendimiento diario.',
						textAlign: TextAlign.center,
						style: theme.textTheme.bodySmall?.copyWith(
							color: theme.colorScheme.onSurfaceVariant,
						),
					),
				],
			),
		);
	}
}

class _SalesTrendChart extends StatelessWidget {
	const _SalesTrendChart({required this.data});

	final List<SalesByDay> data;

	@override
	Widget build(BuildContext context) {
		final theme = Theme.of(context);
		return Container(
			padding: const EdgeInsets.fromLTRB(10, 10, 10, 8),
			decoration: BoxDecoration(
				gradient: LinearGradient(
					colors: [
						theme.colorScheme.primary.withValues(alpha: 0.06),
						theme.colorScheme.surface,
					],
					begin: Alignment.topLeft,
					end: Alignment.bottomRight,
				),
				borderRadius: BorderRadius.circular(16),
				border: Border.all(color: theme.colorScheme.outlineVariant),
			),
			child: Column(
				children: [
					Expanded(
						child: CustomPaint(
							size: Size.infinite,
							painter: _SalesTrendPainter(
								data: data,
								lineColor: theme.colorScheme.primary,
								fillColor: theme.colorScheme.primary.withValues(alpha: 0.16),
								gridColor: theme.colorScheme.outlineVariant,
							),
						),
					),
					const SizedBox(height: 10),
					_ChartLabels(data: data),
				],
			),
		);
	}
}

class _ChartLabels extends StatelessWidget {
	const _ChartLabels({required this.data});

	final List<SalesByDay> data;

	@override
	Widget build(BuildContext context) {
		final theme = Theme.of(context);
		final visible = <int>{};
		if (data.length <= 6) {
			for (var index = 0; index < data.length; index++) {
				visible.add(index);
			}
		} else {
			visible.add(0);
			visible.add(data.length - 1);
			for (var step = 1; step <= 4; step++) {
				visible.add(((data.length - 1) * step / 5).round());
			}
		}

		return Row(
			children: data.asMap().entries.map((entry) {
				final index = entry.key;
				final item = entry.value;
				return Expanded(
					child: Text(
						visible.contains(index) ? _formatDayLabel(item.date) : '',
						textAlign: TextAlign.center,
						style: theme.textTheme.bodySmall?.copyWith(
							color: theme.colorScheme.onSurfaceVariant,
							fontWeight: FontWeight.w600,
						),
						maxLines: 1,
						overflow: TextOverflow.ellipsis,
					),
				);
			}).toList(),
		);
	}
}

class _SalesTrendPainter extends CustomPainter {
	_SalesTrendPainter({
		required this.data,
		required this.lineColor,
		required this.fillColor,
		required this.gridColor,
	});

	final List<SalesByDay> data;
	final Color lineColor;
	final Color fillColor;
	final Color gridColor;

	@override
	void paint(Canvas canvas, Size size) {
		const left = 10.0;
		const top = 12.0;
		final width = size.width - (left * 2);
		final height = size.height - (top * 2);

		final gridPaint = Paint()
			..color = gridColor.withValues(alpha: 0.45)
			..strokeWidth = 1;

		for (var step = 0; step < 4; step++) {
			final y = top + (height / 3) * step;
			canvas.drawLine(Offset(left, y), Offset(size.width - left, y), gridPaint);
		}

		if (data.isEmpty) return;

		final maxValue = math.max(
			1.0,
			data.map((item) => item.total).fold<double>(0, (a, b) => math.max(a, b)),
		);
		final dx = data.length == 1 ? 0.0 : width / (data.length - 1);
		final points = <Offset>[];

		for (var index = 0; index < data.length; index++) {
			final x = left + dx * index;
			final y = top + height - (data[index].total / maxValue) * height;
			points.add(Offset(x, y));
		}

		final linePath = Path()..moveTo(points.first.dx, points.first.dy);
		for (var index = 1; index < points.length; index++) {
			final previous = points[index - 1];
			final current = points[index];
			final controlX = (previous.dx + current.dx) / 2;
			linePath.cubicTo(controlX, previous.dy, controlX, current.dy, current.dx, current.dy);
		}

		final areaPath = Path.from(linePath)
			..lineTo(points.last.dx, size.height - top)
			..lineTo(points.first.dx, size.height - top)
			..close();

		final fillPaint = Paint()
			..shader = LinearGradient(
				colors: [fillColor, fillColor.withValues(alpha: 0.02)],
				begin: Alignment.topCenter,
				end: Alignment.bottomCenter,
			).createShader(Rect.fromLTWH(0, 0, size.width, size.height));

		canvas.drawPath(areaPath, fillPaint);

		final linePaint = Paint()
			..color = lineColor
			..strokeWidth = 3
			..style = PaintingStyle.stroke
			..strokeCap = StrokeCap.round;
		canvas.drawPath(linePath, linePaint);

		final dotPaint = Paint()..color = lineColor;
		final dotStroke = Paint()
			..color = Colors.white
			..style = PaintingStyle.stroke
			..strokeWidth = 2;
		for (final point in points) {
			canvas.drawCircle(point, 4.5, dotPaint);
			canvas.drawCircle(point, 4.5, dotStroke);
		}
	}

	@override
	bool shouldRepaint(covariant _SalesTrendPainter oldDelegate) {
		return oldDelegate.data != data ||
				oldDelegate.lineColor != lineColor ||
				oldDelegate.fillColor != fillColor ||
				oldDelegate.gridColor != gridColor;
	}
}

String _formatDayLabel(String value) {
	final parsed = DateTime.tryParse(value);
	if (parsed == null) return value;
	return DateFormat('dd/MM').format(parsed);
}

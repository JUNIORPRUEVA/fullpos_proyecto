import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/providers/theme_provider.dart';
import '../../../core/theme/app_themes.dart';
import '../../auth/data/auth_repository.dart';
import '../data/company_config.dart';
import '../data/company_config_repository.dart';

final companyConfigProvider =
    AsyncNotifierProvider<CompanyConfigNotifier, CompanyConfig?>(
      CompanyConfigNotifier.new,
    );

class CompanyConfigNotifier extends AsyncNotifier<CompanyConfig?> {
  int? _companyId;

  CompanyConfigRepository get _repository =>
      ref.read(companyConfigRepositoryProvider);

  @override
  CompanyConfig? build() => null;

  Future<void> load(int companyId) async {
    if (_companyId == companyId && state.isLoading) return;
    _companyId = companyId;
    state = const AsyncValue.loading();
    try {
      final config = await _repository.fetch();
      if (config != null) {
        state = AsyncValue.data(config);
        ref.read(appThemeProvider.notifier).setThemeByKey(config.themeKey);
        return;
      }

      final auth = ref.read(authRepositoryProvider);
      if (auth.companyId != null) {
        final fallback = CompanyConfig(
          companyId: auth.companyId!,
          companyName: auth.companyName ?? 'Empresa',
          rnc: auth.companyRnc,
          themeKey: AppThemeEnum.proPos.key,
          version: auth.ownerVersion,
        );
        state = AsyncValue.data(fallback);
        ref.read(appThemeProvider.notifier).setThemeByKey(fallback.themeKey);
        return;
      }

      state = const AsyncValue.data(null);
    } catch (error, stack) {
      state = AsyncValue.error(error, stack);
    }
  }

  Future<void> refresh() async {
    if (_companyId == null) return;
    await load(_companyId!);
  }

  Future<void> updateTheme(AppThemeEnum theme) async {
    if (_companyId == null) return;
    final previous = state.value;
    state = const AsyncValue.loading();
    try {
      final updated = await _repository.update({'themeKey': theme.key});
      if (updated == null) {
        state = AsyncValue.data(previous);
        return;
      }
      state = AsyncValue.data(updated);
      ref.read(appThemeProvider.notifier).setTheme(theme);
    } catch (error, stack) {
      state = AsyncValue.error(error, stack);
    }
  }
}

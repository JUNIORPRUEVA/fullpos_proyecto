import 'package:freezed_annotation/freezed_annotation.dart';

part 'company_config.freezed.dart';
part 'company_config.g.dart';

@freezed
class CompanyConfig with _$CompanyConfig {
  const factory CompanyConfig({
    required int companyId,
    required String companyName,
    String? rnc,
    String? logoUrl,
    String? phone,
    String? phone2,
    String? address,
    String? city,
    String? email,
    String? website,
    String? slogan,
    String? instagramUrl,
    String? facebookUrl,
    required String themeKey,
    String? primaryColor,
    String? accentColor,
    String? version,
  }) = _CompanyConfig;

  factory CompanyConfig.fromJson(Map<String, dynamic> json) => _$CompanyConfigFromJson(json);
}

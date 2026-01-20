// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'company_config.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

_$CompanyConfigImpl _$$CompanyConfigImplFromJson(Map<String, dynamic> json) =>
    _$CompanyConfigImpl(
      companyId: (json['companyId'] as num).toInt(),
      companyName: json['companyName'] as String,
      rnc: json['rnc'] as String?,
      logoUrl: json['logoUrl'] as String?,
      phone: json['phone'] as String?,
      phone2: json['phone2'] as String?,
      address: json['address'] as String?,
      city: json['city'] as String?,
      email: json['email'] as String?,
      website: json['website'] as String?,
      slogan: json['slogan'] as String?,
      instagramUrl: json['instagramUrl'] as String?,
      facebookUrl: json['facebookUrl'] as String?,
      themeKey: json['themeKey'] as String,
      primaryColor: json['primaryColor'] as String?,
      accentColor: json['accentColor'] as String?,
      version: json['version'] as String?,
    );

Map<String, dynamic> _$$CompanyConfigImplToJson(_$CompanyConfigImpl instance) =>
    <String, dynamic>{
      'companyId': instance.companyId,
      'companyName': instance.companyName,
      'rnc': instance.rnc,
      'logoUrl': instance.logoUrl,
      'phone': instance.phone,
      'phone2': instance.phone2,
      'address': instance.address,
      'city': instance.city,
      'email': instance.email,
      'website': instance.website,
      'slogan': instance.slogan,
      'instagramUrl': instance.instagramUrl,
      'facebookUrl': instance.facebookUrl,
      'themeKey': instance.themeKey,
      'primaryColor': instance.primaryColor,
      'accentColor': instance.accentColor,
      'version': instance.version,
    };

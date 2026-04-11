// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'auth_state.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

_$AuthStateImpl _$$AuthStateImplFromJson(Map<String, dynamic> json) =>
    _$AuthStateImpl(
      accessToken: json['accessToken'] as String?,
      refreshToken: json['refreshToken'] as String?,
      companyName: json['companyName'] as String?,
      companyId: (json['companyId'] as num?)?.toInt(),
      companyRnc: json['companyRnc'] as String?,
      ownerVersion: json['ownerVersion'] as String?,
      username: json['username'] as String?,
      email: json['email'] as String?,
      displayName: json['displayName'] as String?,
      loading: json['loading'] as bool? ?? false,
    );

Map<String, dynamic> _$$AuthStateImplToJson(_$AuthStateImpl instance) =>
    <String, dynamic>{
      'accessToken': instance.accessToken,
      'refreshToken': instance.refreshToken,
      'companyName': instance.companyName,
      'companyId': instance.companyId,
      'companyRnc': instance.companyRnc,
      'ownerVersion': instance.ownerVersion,
      'username': instance.username,
      'email': instance.email,
      'displayName': instance.displayName,
      'loading': instance.loading,
    };

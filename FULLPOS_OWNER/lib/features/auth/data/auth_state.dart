import 'package:freezed_annotation/freezed_annotation.dart';

part 'auth_state.freezed.dart';
part 'auth_state.g.dart';

@freezed
class AuthState with _$AuthState {
  const factory AuthState({
    String? accessToken,
    String? refreshToken,
    String? companyName,
    int? companyId,
    String? companyRnc,
    String? ownerVersion,
    String? username,
    @Default(false) bool loading,
  }) = _AuthState;

  factory AuthState.fromJson(Map<String, dynamic> json) => _$AuthStateFromJson(json);

  factory AuthState.initial() => const AuthState(loading: false);
}

// coverage:ignore-file
// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'report_models.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

T _$identity<T>(T value) => value;

final _privateConstructorUsedError = UnsupportedError(
  'It seems like you constructed your class using `MyClass._()`. This constructor is only meant to be used by freezed and you are not supposed to need it nor use it.\nPlease check the documentation here for more information: https://github.com/rrousselGit/freezed#adding-getters-and-methods-to-our-models',
);

SalesSummary _$SalesSummaryFromJson(Map<String, dynamic> json) {
  return _SalesSummary.fromJson(json);
}

/// @nodoc
mixin _$SalesSummary {
  double get total => throw _privateConstructorUsedError;
  int get count => throw _privateConstructorUsedError;
  double get average => throw _privateConstructorUsedError;

  /// Serializes this SalesSummary to a JSON map.
  Map<String, dynamic> toJson() => throw _privateConstructorUsedError;

  /// Create a copy of SalesSummary
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  $SalesSummaryCopyWith<SalesSummary> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $SalesSummaryCopyWith<$Res> {
  factory $SalesSummaryCopyWith(
    SalesSummary value,
    $Res Function(SalesSummary) then,
  ) = _$SalesSummaryCopyWithImpl<$Res, SalesSummary>;
  @useResult
  $Res call({double total, int count, double average});
}

/// @nodoc
class _$SalesSummaryCopyWithImpl<$Res, $Val extends SalesSummary>
    implements $SalesSummaryCopyWith<$Res> {
  _$SalesSummaryCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of SalesSummary
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? total = null,
    Object? count = null,
    Object? average = null,
  }) {
    return _then(
      _value.copyWith(
            total: null == total
                ? _value.total
                : total // ignore: cast_nullable_to_non_nullable
                      as double,
            count: null == count
                ? _value.count
                : count // ignore: cast_nullable_to_non_nullable
                      as int,
            average: null == average
                ? _value.average
                : average // ignore: cast_nullable_to_non_nullable
                      as double,
          )
          as $Val,
    );
  }
}

/// @nodoc
abstract class _$$SalesSummaryImplCopyWith<$Res>
    implements $SalesSummaryCopyWith<$Res> {
  factory _$$SalesSummaryImplCopyWith(
    _$SalesSummaryImpl value,
    $Res Function(_$SalesSummaryImpl) then,
  ) = __$$SalesSummaryImplCopyWithImpl<$Res>;
  @override
  @useResult
  $Res call({double total, int count, double average});
}

/// @nodoc
class __$$SalesSummaryImplCopyWithImpl<$Res>
    extends _$SalesSummaryCopyWithImpl<$Res, _$SalesSummaryImpl>
    implements _$$SalesSummaryImplCopyWith<$Res> {
  __$$SalesSummaryImplCopyWithImpl(
    _$SalesSummaryImpl _value,
    $Res Function(_$SalesSummaryImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of SalesSummary
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? total = null,
    Object? count = null,
    Object? average = null,
  }) {
    return _then(
      _$SalesSummaryImpl(
        total: null == total
            ? _value.total
            : total // ignore: cast_nullable_to_non_nullable
                  as double,
        count: null == count
            ? _value.count
            : count // ignore: cast_nullable_to_non_nullable
                  as int,
        average: null == average
            ? _value.average
            : average // ignore: cast_nullable_to_non_nullable
                  as double,
      ),
    );
  }
}

/// @nodoc
@JsonSerializable()
class _$SalesSummaryImpl implements _SalesSummary {
  const _$SalesSummaryImpl({
    required this.total,
    required this.count,
    required this.average,
  });

  factory _$SalesSummaryImpl.fromJson(Map<String, dynamic> json) =>
      _$$SalesSummaryImplFromJson(json);

  @override
  final double total;
  @override
  final int count;
  @override
  final double average;

  @override
  String toString() {
    return 'SalesSummary(total: $total, count: $count, average: $average)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SalesSummaryImpl &&
            (identical(other.total, total) || other.total == total) &&
            (identical(other.count, count) || other.count == count) &&
            (identical(other.average, average) || other.average == average));
  }

  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  int get hashCode => Object.hash(runtimeType, total, count, average);

  /// Create a copy of SalesSummary
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$SalesSummaryImplCopyWith<_$SalesSummaryImpl> get copyWith =>
      __$$SalesSummaryImplCopyWithImpl<_$SalesSummaryImpl>(this, _$identity);

  @override
  Map<String, dynamic> toJson() {
    return _$$SalesSummaryImplToJson(this);
  }
}

abstract class _SalesSummary implements SalesSummary {
  const factory _SalesSummary({
    required final double total,
    required final int count,
    required final double average,
  }) = _$SalesSummaryImpl;

  factory _SalesSummary.fromJson(Map<String, dynamic> json) =
      _$SalesSummaryImpl.fromJson;

  @override
  double get total;
  @override
  int get count;
  @override
  double get average;

  /// Create a copy of SalesSummary
  /// with the given fields replaced by the non-null parameter values.
  @override
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$SalesSummaryImplCopyWith<_$SalesSummaryImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

SalesByDay _$SalesByDayFromJson(Map<String, dynamic> json) {
  return _SalesByDay.fromJson(json);
}

/// @nodoc
mixin _$SalesByDay {
  String get date => throw _privateConstructorUsedError;
  double get total => throw _privateConstructorUsedError;
  int get count => throw _privateConstructorUsedError;

  /// Serializes this SalesByDay to a JSON map.
  Map<String, dynamic> toJson() => throw _privateConstructorUsedError;

  /// Create a copy of SalesByDay
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  $SalesByDayCopyWith<SalesByDay> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $SalesByDayCopyWith<$Res> {
  factory $SalesByDayCopyWith(
    SalesByDay value,
    $Res Function(SalesByDay) then,
  ) = _$SalesByDayCopyWithImpl<$Res, SalesByDay>;
  @useResult
  $Res call({String date, double total, int count});
}

/// @nodoc
class _$SalesByDayCopyWithImpl<$Res, $Val extends SalesByDay>
    implements $SalesByDayCopyWith<$Res> {
  _$SalesByDayCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of SalesByDay
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({Object? date = null, Object? total = null, Object? count = null}) {
    return _then(
      _value.copyWith(
            date: null == date
                ? _value.date
                : date // ignore: cast_nullable_to_non_nullable
                      as String,
            total: null == total
                ? _value.total
                : total // ignore: cast_nullable_to_non_nullable
                      as double,
            count: null == count
                ? _value.count
                : count // ignore: cast_nullable_to_non_nullable
                      as int,
          )
          as $Val,
    );
  }
}

/// @nodoc
abstract class _$$SalesByDayImplCopyWith<$Res>
    implements $SalesByDayCopyWith<$Res> {
  factory _$$SalesByDayImplCopyWith(
    _$SalesByDayImpl value,
    $Res Function(_$SalesByDayImpl) then,
  ) = __$$SalesByDayImplCopyWithImpl<$Res>;
  @override
  @useResult
  $Res call({String date, double total, int count});
}

/// @nodoc
class __$$SalesByDayImplCopyWithImpl<$Res>
    extends _$SalesByDayCopyWithImpl<$Res, _$SalesByDayImpl>
    implements _$$SalesByDayImplCopyWith<$Res> {
  __$$SalesByDayImplCopyWithImpl(
    _$SalesByDayImpl _value,
    $Res Function(_$SalesByDayImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of SalesByDay
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({Object? date = null, Object? total = null, Object? count = null}) {
    return _then(
      _$SalesByDayImpl(
        date: null == date
            ? _value.date
            : date // ignore: cast_nullable_to_non_nullable
                  as String,
        total: null == total
            ? _value.total
            : total // ignore: cast_nullable_to_non_nullable
                  as double,
        count: null == count
            ? _value.count
            : count // ignore: cast_nullable_to_non_nullable
                  as int,
      ),
    );
  }
}

/// @nodoc
@JsonSerializable()
class _$SalesByDayImpl implements _SalesByDay {
  const _$SalesByDayImpl({
    required this.date,
    required this.total,
    required this.count,
  });

  factory _$SalesByDayImpl.fromJson(Map<String, dynamic> json) =>
      _$$SalesByDayImplFromJson(json);

  @override
  final String date;
  @override
  final double total;
  @override
  final int count;

  @override
  String toString() {
    return 'SalesByDay(date: $date, total: $total, count: $count)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SalesByDayImpl &&
            (identical(other.date, date) || other.date == date) &&
            (identical(other.total, total) || other.total == total) &&
            (identical(other.count, count) || other.count == count));
  }

  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  int get hashCode => Object.hash(runtimeType, date, total, count);

  /// Create a copy of SalesByDay
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$SalesByDayImplCopyWith<_$SalesByDayImpl> get copyWith =>
      __$$SalesByDayImplCopyWithImpl<_$SalesByDayImpl>(this, _$identity);

  @override
  Map<String, dynamic> toJson() {
    return _$$SalesByDayImplToJson(this);
  }
}

abstract class _SalesByDay implements SalesByDay {
  const factory _SalesByDay({
    required final String date,
    required final double total,
    required final int count,
  }) = _$SalesByDayImpl;

  factory _SalesByDay.fromJson(Map<String, dynamic> json) =
      _$SalesByDayImpl.fromJson;

  @override
  String get date;
  @override
  double get total;
  @override
  int get count;

  /// Create a copy of SalesByDay
  /// with the given fields replaced by the non-null parameter values.
  @override
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$SalesByDayImplCopyWith<_$SalesByDayImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

SaleRow _$SaleRowFromJson(Map<String, dynamic> json) {
  return _SaleRow.fromJson(json);
}

/// @nodoc
mixin _$SaleRow {
  int get id => throw _privateConstructorUsedError;
  String get localCode => throw _privateConstructorUsedError;
  double get total => throw _privateConstructorUsedError;
  String? get paymentMethod => throw _privateConstructorUsedError;
  int? get sessionId => throw _privateConstructorUsedError;
  String? get sessionStatus => throw _privateConstructorUsedError;
  DateTime? get sessionOpenedAt => throw _privateConstructorUsedError;
  DateTime? get createdAt => throw _privateConstructorUsedError;
  UserInfo? get user => throw _privateConstructorUsedError;

  /// Serializes this SaleRow to a JSON map.
  Map<String, dynamic> toJson() => throw _privateConstructorUsedError;

  /// Create a copy of SaleRow
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  $SaleRowCopyWith<SaleRow> get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $SaleRowCopyWith<$Res> {
  factory $SaleRowCopyWith(SaleRow value, $Res Function(SaleRow) then) =
      _$SaleRowCopyWithImpl<$Res, SaleRow>;
  @useResult
  $Res call({
    int id,
    String localCode,
    double total,
    String? paymentMethod,
    int? sessionId,
    String? sessionStatus,
    DateTime? sessionOpenedAt,
    DateTime? createdAt,
    UserInfo? user,
  });

  $UserInfoCopyWith<$Res>? get user;
}

/// @nodoc
class _$SaleRowCopyWithImpl<$Res, $Val extends SaleRow>
    implements $SaleRowCopyWith<$Res> {
  _$SaleRowCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of SaleRow
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? id = null,
    Object? localCode = null,
    Object? total = null,
    Object? paymentMethod = freezed,
    Object? sessionId = freezed,
    Object? sessionStatus = freezed,
    Object? sessionOpenedAt = freezed,
    Object? createdAt = freezed,
    Object? user = freezed,
  }) {
    return _then(
      _value.copyWith(
            id: null == id
                ? _value.id
                : id // ignore: cast_nullable_to_non_nullable
                      as int,
            localCode: null == localCode
                ? _value.localCode
                : localCode // ignore: cast_nullable_to_non_nullable
                      as String,
            total: null == total
                ? _value.total
                : total // ignore: cast_nullable_to_non_nullable
                      as double,
            paymentMethod: freezed == paymentMethod
                ? _value.paymentMethod
                : paymentMethod // ignore: cast_nullable_to_non_nullable
                      as String?,
            sessionId: freezed == sessionId
                ? _value.sessionId
                : sessionId // ignore: cast_nullable_to_non_nullable
                      as int?,
            sessionStatus: freezed == sessionStatus
                ? _value.sessionStatus
                : sessionStatus // ignore: cast_nullable_to_non_nullable
                      as String?,
            sessionOpenedAt: freezed == sessionOpenedAt
                ? _value.sessionOpenedAt
                : sessionOpenedAt // ignore: cast_nullable_to_non_nullable
                      as DateTime?,
            createdAt: freezed == createdAt
                ? _value.createdAt
                : createdAt // ignore: cast_nullable_to_non_nullable
                      as DateTime?,
            user: freezed == user
                ? _value.user
                : user // ignore: cast_nullable_to_non_nullable
                      as UserInfo?,
          )
          as $Val,
    );
  }

  /// Create a copy of SaleRow
  /// with the given fields replaced by the non-null parameter values.
  @override
  @pragma('vm:prefer-inline')
  $UserInfoCopyWith<$Res>? get user {
    if (_value.user == null) {
      return null;
    }

    return $UserInfoCopyWith<$Res>(_value.user!, (value) {
      return _then(_value.copyWith(user: value) as $Val);
    });
  }
}

/// @nodoc
abstract class _$$SaleRowImplCopyWith<$Res> implements $SaleRowCopyWith<$Res> {
  factory _$$SaleRowImplCopyWith(
    _$SaleRowImpl value,
    $Res Function(_$SaleRowImpl) then,
  ) = __$$SaleRowImplCopyWithImpl<$Res>;
  @override
  @useResult
  $Res call({
    int id,
    String localCode,
    double total,
    String? paymentMethod,
    int? sessionId,
    String? sessionStatus,
    DateTime? sessionOpenedAt,
    DateTime? createdAt,
    UserInfo? user,
  });

  @override
  $UserInfoCopyWith<$Res>? get user;
}

/// @nodoc
class __$$SaleRowImplCopyWithImpl<$Res>
    extends _$SaleRowCopyWithImpl<$Res, _$SaleRowImpl>
    implements _$$SaleRowImplCopyWith<$Res> {
  __$$SaleRowImplCopyWithImpl(
    _$SaleRowImpl _value,
    $Res Function(_$SaleRowImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of SaleRow
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? id = null,
    Object? localCode = null,
    Object? total = null,
    Object? paymentMethod = freezed,
    Object? sessionId = freezed,
    Object? sessionStatus = freezed,
    Object? sessionOpenedAt = freezed,
    Object? createdAt = freezed,
    Object? user = freezed,
  }) {
    return _then(
      _$SaleRowImpl(
        id: null == id
            ? _value.id
            : id // ignore: cast_nullable_to_non_nullable
                  as int,
        localCode: null == localCode
            ? _value.localCode
            : localCode // ignore: cast_nullable_to_non_nullable
                  as String,
        total: null == total
            ? _value.total
            : total // ignore: cast_nullable_to_non_nullable
                  as double,
        paymentMethod: freezed == paymentMethod
            ? _value.paymentMethod
            : paymentMethod // ignore: cast_nullable_to_non_nullable
                  as String?,
        sessionId: freezed == sessionId
            ? _value.sessionId
            : sessionId // ignore: cast_nullable_to_non_nullable
                  as int?,
        sessionStatus: freezed == sessionStatus
            ? _value.sessionStatus
            : sessionStatus // ignore: cast_nullable_to_non_nullable
                  as String?,
        sessionOpenedAt: freezed == sessionOpenedAt
            ? _value.sessionOpenedAt
            : sessionOpenedAt // ignore: cast_nullable_to_non_nullable
                  as DateTime?,
        createdAt: freezed == createdAt
            ? _value.createdAt
            : createdAt // ignore: cast_nullable_to_non_nullable
                  as DateTime?,
        user: freezed == user
            ? _value.user
            : user // ignore: cast_nullable_to_non_nullable
                  as UserInfo?,
      ),
    );
  }
}

/// @nodoc
@JsonSerializable()
class _$SaleRowImpl implements _SaleRow {
  const _$SaleRowImpl({
    required this.id,
    required this.localCode,
    required this.total,
    this.paymentMethod,
    this.sessionId,
    this.sessionStatus,
    this.sessionOpenedAt,
    this.createdAt,
    this.user,
  });

  factory _$SaleRowImpl.fromJson(Map<String, dynamic> json) =>
      _$$SaleRowImplFromJson(json);

  @override
  final int id;
  @override
  final String localCode;
  @override
  final double total;
  @override
  final String? paymentMethod;
  @override
  final int? sessionId;
  @override
  final String? sessionStatus;
  @override
  final DateTime? sessionOpenedAt;
  @override
  final DateTime? createdAt;
  @override
  final UserInfo? user;

  @override
  String toString() {
    return 'SaleRow(id: $id, localCode: $localCode, total: $total, paymentMethod: $paymentMethod, sessionId: $sessionId, sessionStatus: $sessionStatus, sessionOpenedAt: $sessionOpenedAt, createdAt: $createdAt, user: $user)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SaleRowImpl &&
            (identical(other.id, id) || other.id == id) &&
            (identical(other.localCode, localCode) ||
                other.localCode == localCode) &&
            (identical(other.total, total) || other.total == total) &&
            (identical(other.paymentMethod, paymentMethod) ||
                other.paymentMethod == paymentMethod) &&
            (identical(other.sessionId, sessionId) ||
                other.sessionId == sessionId) &&
            (identical(other.sessionStatus, sessionStatus) ||
                other.sessionStatus == sessionStatus) &&
            (identical(other.sessionOpenedAt, sessionOpenedAt) ||
                other.sessionOpenedAt == sessionOpenedAt) &&
            (identical(other.createdAt, createdAt) ||
                other.createdAt == createdAt) &&
            (identical(other.user, user) || other.user == user));
  }

  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  int get hashCode => Object.hash(
    runtimeType,
    id,
    localCode,
    total,
    paymentMethod,
    sessionId,
    sessionStatus,
    sessionOpenedAt,
    createdAt,
    user,
  );

  /// Create a copy of SaleRow
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$SaleRowImplCopyWith<_$SaleRowImpl> get copyWith =>
      __$$SaleRowImplCopyWithImpl<_$SaleRowImpl>(this, _$identity);

  @override
  Map<String, dynamic> toJson() {
    return _$$SaleRowImplToJson(this);
  }
}

abstract class _SaleRow implements SaleRow {
  const factory _SaleRow({
    required final int id,
    required final String localCode,
    required final double total,
    final String? paymentMethod,
    final int? sessionId,
    final String? sessionStatus,
    final DateTime? sessionOpenedAt,
    final DateTime? createdAt,
    final UserInfo? user,
  }) = _$SaleRowImpl;

  factory _SaleRow.fromJson(Map<String, dynamic> json) = _$SaleRowImpl.fromJson;

  @override
  int get id;
  @override
  String get localCode;
  @override
  double get total;
  @override
  String? get paymentMethod;
  @override
  int? get sessionId;
  @override
  String? get sessionStatus;
  @override
  DateTime? get sessionOpenedAt;
  @override
  DateTime? get createdAt;
  @override
  UserInfo? get user;

  /// Create a copy of SaleRow
  /// with the given fields replaced by the non-null parameter values.
  @override
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$SaleRowImplCopyWith<_$SaleRowImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

UserInfo _$UserInfoFromJson(Map<String, dynamic> json) {
  return _UserInfo.fromJson(json);
}

/// @nodoc
mixin _$UserInfo {
  int get id => throw _privateConstructorUsedError;
  String get username => throw _privateConstructorUsedError;
  String? get displayName => throw _privateConstructorUsedError;

  /// Serializes this UserInfo to a JSON map.
  Map<String, dynamic> toJson() => throw _privateConstructorUsedError;

  /// Create a copy of UserInfo
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  $UserInfoCopyWith<UserInfo> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $UserInfoCopyWith<$Res> {
  factory $UserInfoCopyWith(UserInfo value, $Res Function(UserInfo) then) =
      _$UserInfoCopyWithImpl<$Res, UserInfo>;
  @useResult
  $Res call({int id, String username, String? displayName});
}

/// @nodoc
class _$UserInfoCopyWithImpl<$Res, $Val extends UserInfo>
    implements $UserInfoCopyWith<$Res> {
  _$UserInfoCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of UserInfo
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? id = null,
    Object? username = null,
    Object? displayName = freezed,
  }) {
    return _then(
      _value.copyWith(
            id: null == id
                ? _value.id
                : id // ignore: cast_nullable_to_non_nullable
                      as int,
            username: null == username
                ? _value.username
                : username // ignore: cast_nullable_to_non_nullable
                      as String,
            displayName: freezed == displayName
                ? _value.displayName
                : displayName // ignore: cast_nullable_to_non_nullable
                      as String?,
          )
          as $Val,
    );
  }
}

/// @nodoc
abstract class _$$UserInfoImplCopyWith<$Res>
    implements $UserInfoCopyWith<$Res> {
  factory _$$UserInfoImplCopyWith(
    _$UserInfoImpl value,
    $Res Function(_$UserInfoImpl) then,
  ) = __$$UserInfoImplCopyWithImpl<$Res>;
  @override
  @useResult
  $Res call({int id, String username, String? displayName});
}

/// @nodoc
class __$$UserInfoImplCopyWithImpl<$Res>
    extends _$UserInfoCopyWithImpl<$Res, _$UserInfoImpl>
    implements _$$UserInfoImplCopyWith<$Res> {
  __$$UserInfoImplCopyWithImpl(
    _$UserInfoImpl _value,
    $Res Function(_$UserInfoImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of UserInfo
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? id = null,
    Object? username = null,
    Object? displayName = freezed,
  }) {
    return _then(
      _$UserInfoImpl(
        id: null == id
            ? _value.id
            : id // ignore: cast_nullable_to_non_nullable
                  as int,
        username: null == username
            ? _value.username
            : username // ignore: cast_nullable_to_non_nullable
                  as String,
        displayName: freezed == displayName
            ? _value.displayName
            : displayName // ignore: cast_nullable_to_non_nullable
                  as String?,
      ),
    );
  }
}

/// @nodoc
@JsonSerializable()
class _$UserInfoImpl implements _UserInfo {
  const _$UserInfoImpl({
    required this.id,
    required this.username,
    this.displayName,
  });

  factory _$UserInfoImpl.fromJson(Map<String, dynamic> json) =>
      _$$UserInfoImplFromJson(json);

  @override
  final int id;
  @override
  final String username;
  @override
  final String? displayName;

  @override
  String toString() {
    return 'UserInfo(id: $id, username: $username, displayName: $displayName)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$UserInfoImpl &&
            (identical(other.id, id) || other.id == id) &&
            (identical(other.username, username) ||
                other.username == username) &&
            (identical(other.displayName, displayName) ||
                other.displayName == displayName));
  }

  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  int get hashCode => Object.hash(runtimeType, id, username, displayName);

  /// Create a copy of UserInfo
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$UserInfoImplCopyWith<_$UserInfoImpl> get copyWith =>
      __$$UserInfoImplCopyWithImpl<_$UserInfoImpl>(this, _$identity);

  @override
  Map<String, dynamic> toJson() {
    return _$$UserInfoImplToJson(this);
  }
}

abstract class _UserInfo implements UserInfo {
  const factory _UserInfo({
    required final int id,
    required final String username,
    final String? displayName,
  }) = _$UserInfoImpl;

  factory _UserInfo.fromJson(Map<String, dynamic> json) =
      _$UserInfoImpl.fromJson;

  @override
  int get id;
  @override
  String get username;
  @override
  String? get displayName;

  /// Create a copy of UserInfo
  /// with the given fields replaced by the non-null parameter values.
  @override
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$UserInfoImplCopyWith<_$UserInfoImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

PaginatedSales _$PaginatedSalesFromJson(Map<String, dynamic> json) {
  return _PaginatedSales.fromJson(json);
}

/// @nodoc
mixin _$PaginatedSales {
  List<SaleRow> get data => throw _privateConstructorUsedError;
  int get page => throw _privateConstructorUsedError;
  int get pageSize => throw _privateConstructorUsedError;
  int get total => throw _privateConstructorUsedError;

  /// Serializes this PaginatedSales to a JSON map.
  Map<String, dynamic> toJson() => throw _privateConstructorUsedError;

  /// Create a copy of PaginatedSales
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  $PaginatedSalesCopyWith<PaginatedSales> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $PaginatedSalesCopyWith<$Res> {
  factory $PaginatedSalesCopyWith(
    PaginatedSales value,
    $Res Function(PaginatedSales) then,
  ) = _$PaginatedSalesCopyWithImpl<$Res, PaginatedSales>;
  @useResult
  $Res call({List<SaleRow> data, int page, int pageSize, int total});
}

/// @nodoc
class _$PaginatedSalesCopyWithImpl<$Res, $Val extends PaginatedSales>
    implements $PaginatedSalesCopyWith<$Res> {
  _$PaginatedSalesCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of PaginatedSales
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? data = null,
    Object? page = null,
    Object? pageSize = null,
    Object? total = null,
  }) {
    return _then(
      _value.copyWith(
            data: null == data
                ? _value.data
                : data // ignore: cast_nullable_to_non_nullable
                      as List<SaleRow>,
            page: null == page
                ? _value.page
                : page // ignore: cast_nullable_to_non_nullable
                      as int,
            pageSize: null == pageSize
                ? _value.pageSize
                : pageSize // ignore: cast_nullable_to_non_nullable
                      as int,
            total: null == total
                ? _value.total
                : total // ignore: cast_nullable_to_non_nullable
                      as int,
          )
          as $Val,
    );
  }
}

/// @nodoc
abstract class _$$PaginatedSalesImplCopyWith<$Res>
    implements $PaginatedSalesCopyWith<$Res> {
  factory _$$PaginatedSalesImplCopyWith(
    _$PaginatedSalesImpl value,
    $Res Function(_$PaginatedSalesImpl) then,
  ) = __$$PaginatedSalesImplCopyWithImpl<$Res>;
  @override
  @useResult
  $Res call({List<SaleRow> data, int page, int pageSize, int total});
}

/// @nodoc
class __$$PaginatedSalesImplCopyWithImpl<$Res>
    extends _$PaginatedSalesCopyWithImpl<$Res, _$PaginatedSalesImpl>
    implements _$$PaginatedSalesImplCopyWith<$Res> {
  __$$PaginatedSalesImplCopyWithImpl(
    _$PaginatedSalesImpl _value,
    $Res Function(_$PaginatedSalesImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of PaginatedSales
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? data = null,
    Object? page = null,
    Object? pageSize = null,
    Object? total = null,
  }) {
    return _then(
      _$PaginatedSalesImpl(
        data: null == data
            ? _value._data
            : data // ignore: cast_nullable_to_non_nullable
                  as List<SaleRow>,
        page: null == page
            ? _value.page
            : page // ignore: cast_nullable_to_non_nullable
                  as int,
        pageSize: null == pageSize
            ? _value.pageSize
            : pageSize // ignore: cast_nullable_to_non_nullable
                  as int,
        total: null == total
            ? _value.total
            : total // ignore: cast_nullable_to_non_nullable
                  as int,
      ),
    );
  }
}

/// @nodoc
@JsonSerializable()
class _$PaginatedSalesImpl implements _PaginatedSales {
  const _$PaginatedSalesImpl({
    required final List<SaleRow> data,
    required this.page,
    required this.pageSize,
    required this.total,
  }) : _data = data;

  factory _$PaginatedSalesImpl.fromJson(Map<String, dynamic> json) =>
      _$$PaginatedSalesImplFromJson(json);

  final List<SaleRow> _data;
  @override
  List<SaleRow> get data {
    if (_data is EqualUnmodifiableListView) return _data;
    // ignore: implicit_dynamic_type
    return EqualUnmodifiableListView(_data);
  }

  @override
  final int page;
  @override
  final int pageSize;
  @override
  final int total;

  @override
  String toString() {
    return 'PaginatedSales(data: $data, page: $page, pageSize: $pageSize, total: $total)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PaginatedSalesImpl &&
            const DeepCollectionEquality().equals(other._data, _data) &&
            (identical(other.page, page) || other.page == page) &&
            (identical(other.pageSize, pageSize) ||
                other.pageSize == pageSize) &&
            (identical(other.total, total) || other.total == total));
  }

  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  int get hashCode => Object.hash(
    runtimeType,
    const DeepCollectionEquality().hash(_data),
    page,
    pageSize,
    total,
  );

  /// Create a copy of PaginatedSales
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PaginatedSalesImplCopyWith<_$PaginatedSalesImpl> get copyWith =>
      __$$PaginatedSalesImplCopyWithImpl<_$PaginatedSalesImpl>(
        this,
        _$identity,
      );

  @override
  Map<String, dynamic> toJson() {
    return _$$PaginatedSalesImplToJson(this);
  }
}

abstract class _PaginatedSales implements PaginatedSales {
  const factory _PaginatedSales({
    required final List<SaleRow> data,
    required final int page,
    required final int pageSize,
    required final int total,
  }) = _$PaginatedSalesImpl;

  factory _PaginatedSales.fromJson(Map<String, dynamic> json) =
      _$PaginatedSalesImpl.fromJson;

  @override
  List<SaleRow> get data;
  @override
  int get page;
  @override
  int get pageSize;
  @override
  int get total;

  /// Create a copy of PaginatedSales
  /// with the given fields replaced by the non-null parameter values.
  @override
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PaginatedSalesImplCopyWith<_$PaginatedSalesImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

CashClosing _$CashClosingFromJson(Map<String, dynamic> json) {
  return _CashClosing.fromJson(json);
}

/// @nodoc
mixin _$CashClosing {
  int get id => throw _privateConstructorUsedError;
  DateTime? get openedAt => throw _privateConstructorUsedError;
  DateTime? get closedAt => throw _privateConstructorUsedError;
  String get userName => throw _privateConstructorUsedError;
  UserInfo? get openedBy => throw _privateConstructorUsedError;
  UserInfo? get closedBy => throw _privateConstructorUsedError;
  double get totalSales => throw _privateConstructorUsedError;
  int get salesCount => throw _privateConstructorUsedError;
  double? get closingAmount => throw _privateConstructorUsedError;
  double? get expectedCash => throw _privateConstructorUsedError;
  double? get difference => throw _privateConstructorUsedError;

  /// Serializes this CashClosing to a JSON map.
  Map<String, dynamic> toJson() => throw _privateConstructorUsedError;

  /// Create a copy of CashClosing
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  $CashClosingCopyWith<CashClosing> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $CashClosingCopyWith<$Res> {
  factory $CashClosingCopyWith(
    CashClosing value,
    $Res Function(CashClosing) then,
  ) = _$CashClosingCopyWithImpl<$Res, CashClosing>;
  @useResult
  $Res call({
    int id,
    DateTime? openedAt,
    DateTime? closedAt,
    String userName,
    UserInfo? openedBy,
    UserInfo? closedBy,
    double totalSales,
    int salesCount,
    double? closingAmount,
    double? expectedCash,
    double? difference,
  });

  $UserInfoCopyWith<$Res>? get openedBy;
  $UserInfoCopyWith<$Res>? get closedBy;
}

/// @nodoc
class _$CashClosingCopyWithImpl<$Res, $Val extends CashClosing>
    implements $CashClosingCopyWith<$Res> {
  _$CashClosingCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of CashClosing
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? id = null,
    Object? openedAt = freezed,
    Object? closedAt = freezed,
    Object? userName = null,
    Object? openedBy = freezed,
    Object? closedBy = freezed,
    Object? totalSales = null,
    Object? salesCount = null,
    Object? closingAmount = freezed,
    Object? expectedCash = freezed,
    Object? difference = freezed,
  }) {
    return _then(
      _value.copyWith(
            id: null == id
                ? _value.id
                : id // ignore: cast_nullable_to_non_nullable
                      as int,
            openedAt: freezed == openedAt
                ? _value.openedAt
                : openedAt // ignore: cast_nullable_to_non_nullable
                      as DateTime?,
            closedAt: freezed == closedAt
                ? _value.closedAt
                : closedAt // ignore: cast_nullable_to_non_nullable
                      as DateTime?,
            userName: null == userName
                ? _value.userName
                : userName // ignore: cast_nullable_to_non_nullable
                      as String,
            openedBy: freezed == openedBy
                ? _value.openedBy
                : openedBy // ignore: cast_nullable_to_non_nullable
                      as UserInfo?,
            closedBy: freezed == closedBy
                ? _value.closedBy
                : closedBy // ignore: cast_nullable_to_non_nullable
                      as UserInfo?,
            totalSales: null == totalSales
                ? _value.totalSales
                : totalSales // ignore: cast_nullable_to_non_nullable
                      as double,
            salesCount: null == salesCount
                ? _value.salesCount
                : salesCount // ignore: cast_nullable_to_non_nullable
                      as int,
            closingAmount: freezed == closingAmount
                ? _value.closingAmount
                : closingAmount // ignore: cast_nullable_to_non_nullable
                      as double?,
            expectedCash: freezed == expectedCash
                ? _value.expectedCash
                : expectedCash // ignore: cast_nullable_to_non_nullable
                      as double?,
            difference: freezed == difference
                ? _value.difference
                : difference // ignore: cast_nullable_to_non_nullable
                      as double?,
          )
          as $Val,
    );
  }

  /// Create a copy of CashClosing
  /// with the given fields replaced by the non-null parameter values.
  @override
  @pragma('vm:prefer-inline')
  $UserInfoCopyWith<$Res>? get openedBy {
    if (_value.openedBy == null) {
      return null;
    }

    return $UserInfoCopyWith<$Res>(_value.openedBy!, (value) {
      return _then(_value.copyWith(openedBy: value) as $Val);
    });
  }

  /// Create a copy of CashClosing
  /// with the given fields replaced by the non-null parameter values.
  @override
  @pragma('vm:prefer-inline')
  $UserInfoCopyWith<$Res>? get closedBy {
    if (_value.closedBy == null) {
      return null;
    }

    return $UserInfoCopyWith<$Res>(_value.closedBy!, (value) {
      return _then(_value.copyWith(closedBy: value) as $Val);
    });
  }
}

/// @nodoc
abstract class _$$CashClosingImplCopyWith<$Res>
    implements $CashClosingCopyWith<$Res> {
  factory _$$CashClosingImplCopyWith(
    _$CashClosingImpl value,
    $Res Function(_$CashClosingImpl) then,
  ) = __$$CashClosingImplCopyWithImpl<$Res>;
  @override
  @useResult
  $Res call({
    int id,
    DateTime? openedAt,
    DateTime? closedAt,
    String userName,
    UserInfo? openedBy,
    UserInfo? closedBy,
    double totalSales,
    int salesCount,
    double? closingAmount,
    double? expectedCash,
    double? difference,
  });

  @override
  $UserInfoCopyWith<$Res>? get openedBy;
  @override
  $UserInfoCopyWith<$Res>? get closedBy;
}

/// @nodoc
class __$$CashClosingImplCopyWithImpl<$Res>
    extends _$CashClosingCopyWithImpl<$Res, _$CashClosingImpl>
    implements _$$CashClosingImplCopyWith<$Res> {
  __$$CashClosingImplCopyWithImpl(
    _$CashClosingImpl _value,
    $Res Function(_$CashClosingImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of CashClosing
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? id = null,
    Object? openedAt = freezed,
    Object? closedAt = freezed,
    Object? userName = null,
    Object? openedBy = freezed,
    Object? closedBy = freezed,
    Object? totalSales = null,
    Object? salesCount = null,
    Object? closingAmount = freezed,
    Object? expectedCash = freezed,
    Object? difference = freezed,
  }) {
    return _then(
      _$CashClosingImpl(
        id: null == id
            ? _value.id
            : id // ignore: cast_nullable_to_non_nullable
                  as int,
        openedAt: freezed == openedAt
            ? _value.openedAt
            : openedAt // ignore: cast_nullable_to_non_nullable
                  as DateTime?,
        closedAt: freezed == closedAt
            ? _value.closedAt
            : closedAt // ignore: cast_nullable_to_non_nullable
                  as DateTime?,
        userName: null == userName
            ? _value.userName
            : userName // ignore: cast_nullable_to_non_nullable
                  as String,
        openedBy: freezed == openedBy
            ? _value.openedBy
            : openedBy // ignore: cast_nullable_to_non_nullable
                  as UserInfo?,
        closedBy: freezed == closedBy
            ? _value.closedBy
            : closedBy // ignore: cast_nullable_to_non_nullable
                  as UserInfo?,
        totalSales: null == totalSales
            ? _value.totalSales
            : totalSales // ignore: cast_nullable_to_non_nullable
                  as double,
        salesCount: null == salesCount
            ? _value.salesCount
            : salesCount // ignore: cast_nullable_to_non_nullable
                  as int,
        closingAmount: freezed == closingAmount
            ? _value.closingAmount
            : closingAmount // ignore: cast_nullable_to_non_nullable
                  as double?,
        expectedCash: freezed == expectedCash
            ? _value.expectedCash
            : expectedCash // ignore: cast_nullable_to_non_nullable
                  as double?,
        difference: freezed == difference
            ? _value.difference
            : difference // ignore: cast_nullable_to_non_nullable
                  as double?,
      ),
    );
  }
}

/// @nodoc
@JsonSerializable()
class _$CashClosingImpl implements _CashClosing {
  const _$CashClosingImpl({
    required this.id,
    this.openedAt,
    this.closedAt,
    required this.userName,
    this.openedBy,
    this.closedBy,
    required this.totalSales,
    required this.salesCount,
    this.closingAmount,
    this.expectedCash,
    this.difference,
  });

  factory _$CashClosingImpl.fromJson(Map<String, dynamic> json) =>
      _$$CashClosingImplFromJson(json);

  @override
  final int id;
  @override
  final DateTime? openedAt;
  @override
  final DateTime? closedAt;
  @override
  final String userName;
  @override
  final UserInfo? openedBy;
  @override
  final UserInfo? closedBy;
  @override
  final double totalSales;
  @override
  final int salesCount;
  @override
  final double? closingAmount;
  @override
  final double? expectedCash;
  @override
  final double? difference;

  @override
  String toString() {
    return 'CashClosing(id: $id, openedAt: $openedAt, closedAt: $closedAt, userName: $userName, openedBy: $openedBy, closedBy: $closedBy, totalSales: $totalSales, salesCount: $salesCount, closingAmount: $closingAmount, expectedCash: $expectedCash, difference: $difference)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$CashClosingImpl &&
            (identical(other.id, id) || other.id == id) &&
            (identical(other.openedAt, openedAt) ||
                other.openedAt == openedAt) &&
            (identical(other.closedAt, closedAt) ||
                other.closedAt == closedAt) &&
            (identical(other.userName, userName) ||
                other.userName == userName) &&
            (identical(other.openedBy, openedBy) ||
                other.openedBy == openedBy) &&
            (identical(other.closedBy, closedBy) ||
                other.closedBy == closedBy) &&
            (identical(other.totalSales, totalSales) ||
                other.totalSales == totalSales) &&
            (identical(other.salesCount, salesCount) ||
                other.salesCount == salesCount) &&
            (identical(other.closingAmount, closingAmount) ||
                other.closingAmount == closingAmount) &&
            (identical(other.expectedCash, expectedCash) ||
                other.expectedCash == expectedCash) &&
            (identical(other.difference, difference) ||
                other.difference == difference));
  }

  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  int get hashCode => Object.hash(
    runtimeType,
    id,
    openedAt,
    closedAt,
    userName,
    openedBy,
    closedBy,
    totalSales,
    salesCount,
    closingAmount,
    expectedCash,
    difference,
  );

  /// Create a copy of CashClosing
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$CashClosingImplCopyWith<_$CashClosingImpl> get copyWith =>
      __$$CashClosingImplCopyWithImpl<_$CashClosingImpl>(this, _$identity);

  @override
  Map<String, dynamic> toJson() {
    return _$$CashClosingImplToJson(this);
  }
}

abstract class _CashClosing implements CashClosing {
  const factory _CashClosing({
    required final int id,
    final DateTime? openedAt,
    final DateTime? closedAt,
    required final String userName,
    final UserInfo? openedBy,
    final UserInfo? closedBy,
    required final double totalSales,
    required final int salesCount,
    final double? closingAmount,
    final double? expectedCash,
    final double? difference,
  }) = _$CashClosingImpl;

  factory _CashClosing.fromJson(Map<String, dynamic> json) =
      _$CashClosingImpl.fromJson;

  @override
  int get id;
  @override
  DateTime? get openedAt;
  @override
  DateTime? get closedAt;
  @override
  String get userName;
  @override
  UserInfo? get openedBy;
  @override
  UserInfo? get closedBy;
  @override
  double get totalSales;
  @override
  int get salesCount;
  @override
  double? get closingAmount;
  @override
  double? get expectedCash;
  @override
  double? get difference;

  /// Create a copy of CashClosing
  /// with the given fields replaced by the non-null parameter values.
  @override
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$CashClosingImplCopyWith<_$CashClosingImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

CashClosingDetail _$CashClosingDetailFromJson(Map<String, dynamic> json) {
  return _CashClosingDetail.fromJson(json);
}

/// @nodoc
mixin _$CashClosingDetail {
  CashClosingSession get session => throw _privateConstructorUsedError;
  CashClosingTotals get totals => throw _privateConstructorUsedError;
  List<SaleMinimal> get sales => throw _privateConstructorUsedError;
  List<CashMovementRow> get movements => throw _privateConstructorUsedError;

  /// Serializes this CashClosingDetail to a JSON map.
  Map<String, dynamic> toJson() => throw _privateConstructorUsedError;

  /// Create a copy of CashClosingDetail
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  $CashClosingDetailCopyWith<CashClosingDetail> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $CashClosingDetailCopyWith<$Res> {
  factory $CashClosingDetailCopyWith(
    CashClosingDetail value,
    $Res Function(CashClosingDetail) then,
  ) = _$CashClosingDetailCopyWithImpl<$Res, CashClosingDetail>;
  @useResult
  $Res call({
    CashClosingSession session,
    CashClosingTotals totals,
    List<SaleMinimal> sales,
    List<CashMovementRow> movements,
  });

  $CashClosingSessionCopyWith<$Res> get session;
  $CashClosingTotalsCopyWith<$Res> get totals;
}

/// @nodoc
class _$CashClosingDetailCopyWithImpl<$Res, $Val extends CashClosingDetail>
    implements $CashClosingDetailCopyWith<$Res> {
  _$CashClosingDetailCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of CashClosingDetail
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? session = null,
    Object? totals = null,
    Object? sales = null,
    Object? movements = null,
  }) {
    return _then(
      _value.copyWith(
            session: null == session
                ? _value.session
                : session // ignore: cast_nullable_to_non_nullable
                      as CashClosingSession,
            totals: null == totals
                ? _value.totals
                : totals // ignore: cast_nullable_to_non_nullable
                      as CashClosingTotals,
            sales: null == sales
                ? _value.sales
                : sales // ignore: cast_nullable_to_non_nullable
                      as List<SaleMinimal>,
            movements: null == movements
                ? _value.movements
                : movements // ignore: cast_nullable_to_non_nullable
                      as List<CashMovementRow>,
          )
          as $Val,
    );
  }

  /// Create a copy of CashClosingDetail
  /// with the given fields replaced by the non-null parameter values.
  @override
  @pragma('vm:prefer-inline')
  $CashClosingSessionCopyWith<$Res> get session {
    return $CashClosingSessionCopyWith<$Res>(_value.session, (value) {
      return _then(_value.copyWith(session: value) as $Val);
    });
  }

  /// Create a copy of CashClosingDetail
  /// with the given fields replaced by the non-null parameter values.
  @override
  @pragma('vm:prefer-inline')
  $CashClosingTotalsCopyWith<$Res> get totals {
    return $CashClosingTotalsCopyWith<$Res>(_value.totals, (value) {
      return _then(_value.copyWith(totals: value) as $Val);
    });
  }
}

/// @nodoc
abstract class _$$CashClosingDetailImplCopyWith<$Res>
    implements $CashClosingDetailCopyWith<$Res> {
  factory _$$CashClosingDetailImplCopyWith(
    _$CashClosingDetailImpl value,
    $Res Function(_$CashClosingDetailImpl) then,
  ) = __$$CashClosingDetailImplCopyWithImpl<$Res>;
  @override
  @useResult
  $Res call({
    CashClosingSession session,
    CashClosingTotals totals,
    List<SaleMinimal> sales,
    List<CashMovementRow> movements,
  });

  @override
  $CashClosingSessionCopyWith<$Res> get session;
  @override
  $CashClosingTotalsCopyWith<$Res> get totals;
}

/// @nodoc
class __$$CashClosingDetailImplCopyWithImpl<$Res>
    extends _$CashClosingDetailCopyWithImpl<$Res, _$CashClosingDetailImpl>
    implements _$$CashClosingDetailImplCopyWith<$Res> {
  __$$CashClosingDetailImplCopyWithImpl(
    _$CashClosingDetailImpl _value,
    $Res Function(_$CashClosingDetailImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of CashClosingDetail
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? session = null,
    Object? totals = null,
    Object? sales = null,
    Object? movements = null,
  }) {
    return _then(
      _$CashClosingDetailImpl(
        session: null == session
            ? _value.session
            : session // ignore: cast_nullable_to_non_nullable
                  as CashClosingSession,
        totals: null == totals
            ? _value.totals
            : totals // ignore: cast_nullable_to_non_nullable
                  as CashClosingTotals,
        sales: null == sales
            ? _value._sales
            : sales // ignore: cast_nullable_to_non_nullable
                  as List<SaleMinimal>,
        movements: null == movements
            ? _value._movements
            : movements // ignore: cast_nullable_to_non_nullable
                  as List<CashMovementRow>,
      ),
    );
  }
}

/// @nodoc
@JsonSerializable()
class _$CashClosingDetailImpl implements _CashClosingDetail {
  const _$CashClosingDetailImpl({
    required this.session,
    required this.totals,
    required final List<SaleMinimal> sales,
    required final List<CashMovementRow> movements,
  }) : _sales = sales,
       _movements = movements;

  factory _$CashClosingDetailImpl.fromJson(Map<String, dynamic> json) =>
      _$$CashClosingDetailImplFromJson(json);

  @override
  final CashClosingSession session;
  @override
  final CashClosingTotals totals;
  final List<SaleMinimal> _sales;
  @override
  List<SaleMinimal> get sales {
    if (_sales is EqualUnmodifiableListView) return _sales;
    // ignore: implicit_dynamic_type
    return EqualUnmodifiableListView(_sales);
  }

  final List<CashMovementRow> _movements;
  @override
  List<CashMovementRow> get movements {
    if (_movements is EqualUnmodifiableListView) return _movements;
    // ignore: implicit_dynamic_type
    return EqualUnmodifiableListView(_movements);
  }

  @override
  String toString() {
    return 'CashClosingDetail(session: $session, totals: $totals, sales: $sales, movements: $movements)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$CashClosingDetailImpl &&
            (identical(other.session, session) || other.session == session) &&
            (identical(other.totals, totals) || other.totals == totals) &&
            const DeepCollectionEquality().equals(other._sales, _sales) &&
            const DeepCollectionEquality().equals(
              other._movements,
              _movements,
            ));
  }

  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  int get hashCode => Object.hash(
    runtimeType,
    session,
    totals,
    const DeepCollectionEquality().hash(_sales),
    const DeepCollectionEquality().hash(_movements),
  );

  /// Create a copy of CashClosingDetail
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$CashClosingDetailImplCopyWith<_$CashClosingDetailImpl> get copyWith =>
      __$$CashClosingDetailImplCopyWithImpl<_$CashClosingDetailImpl>(
        this,
        _$identity,
      );

  @override
  Map<String, dynamic> toJson() {
    return _$$CashClosingDetailImplToJson(this);
  }
}

abstract class _CashClosingDetail implements CashClosingDetail {
  const factory _CashClosingDetail({
    required final CashClosingSession session,
    required final CashClosingTotals totals,
    required final List<SaleMinimal> sales,
    required final List<CashMovementRow> movements,
  }) = _$CashClosingDetailImpl;

  factory _CashClosingDetail.fromJson(Map<String, dynamic> json) =
      _$CashClosingDetailImpl.fromJson;

  @override
  CashClosingSession get session;
  @override
  CashClosingTotals get totals;
  @override
  List<SaleMinimal> get sales;
  @override
  List<CashMovementRow> get movements;

  /// Create a copy of CashClosingDetail
  /// with the given fields replaced by the non-null parameter values.
  @override
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$CashClosingDetailImplCopyWith<_$CashClosingDetailImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

CashClosingSession _$CashClosingSessionFromJson(Map<String, dynamic> json) {
  return _CashClosingSession.fromJson(json);
}

/// @nodoc
mixin _$CashClosingSession {
  int get id => throw _privateConstructorUsedError;
  DateTime? get openedAt => throw _privateConstructorUsedError;
  DateTime? get closedAt => throw _privateConstructorUsedError;
  double? get initialAmount => throw _privateConstructorUsedError;
  double? get closingAmount => throw _privateConstructorUsedError;
  double? get expectedCash => throw _privateConstructorUsedError;
  double? get difference => throw _privateConstructorUsedError;
  String? get status => throw _privateConstructorUsedError;
  String? get note => throw _privateConstructorUsedError;
  UserInfo? get openedBy => throw _privateConstructorUsedError;
  UserInfo? get closedBy => throw _privateConstructorUsedError;
  Map<String, dynamic>? get paymentSummary =>
      throw _privateConstructorUsedError;

  /// Serializes this CashClosingSession to a JSON map.
  Map<String, dynamic> toJson() => throw _privateConstructorUsedError;

  /// Create a copy of CashClosingSession
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  $CashClosingSessionCopyWith<CashClosingSession> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $CashClosingSessionCopyWith<$Res> {
  factory $CashClosingSessionCopyWith(
    CashClosingSession value,
    $Res Function(CashClosingSession) then,
  ) = _$CashClosingSessionCopyWithImpl<$Res, CashClosingSession>;
  @useResult
  $Res call({
    int id,
    DateTime? openedAt,
    DateTime? closedAt,
    double? initialAmount,
    double? closingAmount,
    double? expectedCash,
    double? difference,
    String? status,
    String? note,
    UserInfo? openedBy,
    UserInfo? closedBy,
    Map<String, dynamic>? paymentSummary,
  });

  $UserInfoCopyWith<$Res>? get openedBy;
  $UserInfoCopyWith<$Res>? get closedBy;
}

/// @nodoc
class _$CashClosingSessionCopyWithImpl<$Res, $Val extends CashClosingSession>
    implements $CashClosingSessionCopyWith<$Res> {
  _$CashClosingSessionCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of CashClosingSession
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? id = null,
    Object? openedAt = freezed,
    Object? closedAt = freezed,
    Object? initialAmount = freezed,
    Object? closingAmount = freezed,
    Object? expectedCash = freezed,
    Object? difference = freezed,
    Object? status = freezed,
    Object? note = freezed,
    Object? openedBy = freezed,
    Object? closedBy = freezed,
    Object? paymentSummary = freezed,
  }) {
    return _then(
      _value.copyWith(
            id: null == id
                ? _value.id
                : id // ignore: cast_nullable_to_non_nullable
                      as int,
            openedAt: freezed == openedAt
                ? _value.openedAt
                : openedAt // ignore: cast_nullable_to_non_nullable
                      as DateTime?,
            closedAt: freezed == closedAt
                ? _value.closedAt
                : closedAt // ignore: cast_nullable_to_non_nullable
                      as DateTime?,
            initialAmount: freezed == initialAmount
                ? _value.initialAmount
                : initialAmount // ignore: cast_nullable_to_non_nullable
                      as double?,
            closingAmount: freezed == closingAmount
                ? _value.closingAmount
                : closingAmount // ignore: cast_nullable_to_non_nullable
                      as double?,
            expectedCash: freezed == expectedCash
                ? _value.expectedCash
                : expectedCash // ignore: cast_nullable_to_non_nullable
                      as double?,
            difference: freezed == difference
                ? _value.difference
                : difference // ignore: cast_nullable_to_non_nullable
                      as double?,
            status: freezed == status
                ? _value.status
                : status // ignore: cast_nullable_to_non_nullable
                      as String?,
            note: freezed == note
                ? _value.note
                : note // ignore: cast_nullable_to_non_nullable
                      as String?,
            openedBy: freezed == openedBy
                ? _value.openedBy
                : openedBy // ignore: cast_nullable_to_non_nullable
                      as UserInfo?,
            closedBy: freezed == closedBy
                ? _value.closedBy
                : closedBy // ignore: cast_nullable_to_non_nullable
                      as UserInfo?,
            paymentSummary: freezed == paymentSummary
                ? _value.paymentSummary
                : paymentSummary // ignore: cast_nullable_to_non_nullable
                      as Map<String, dynamic>?,
          )
          as $Val,
    );
  }

  /// Create a copy of CashClosingSession
  /// with the given fields replaced by the non-null parameter values.
  @override
  @pragma('vm:prefer-inline')
  $UserInfoCopyWith<$Res>? get openedBy {
    if (_value.openedBy == null) {
      return null;
    }

    return $UserInfoCopyWith<$Res>(_value.openedBy!, (value) {
      return _then(_value.copyWith(openedBy: value) as $Val);
    });
  }

  /// Create a copy of CashClosingSession
  /// with the given fields replaced by the non-null parameter values.
  @override
  @pragma('vm:prefer-inline')
  $UserInfoCopyWith<$Res>? get closedBy {
    if (_value.closedBy == null) {
      return null;
    }

    return $UserInfoCopyWith<$Res>(_value.closedBy!, (value) {
      return _then(_value.copyWith(closedBy: value) as $Val);
    });
  }
}

/// @nodoc
abstract class _$$CashClosingSessionImplCopyWith<$Res>
    implements $CashClosingSessionCopyWith<$Res> {
  factory _$$CashClosingSessionImplCopyWith(
    _$CashClosingSessionImpl value,
    $Res Function(_$CashClosingSessionImpl) then,
  ) = __$$CashClosingSessionImplCopyWithImpl<$Res>;
  @override
  @useResult
  $Res call({
    int id,
    DateTime? openedAt,
    DateTime? closedAt,
    double? initialAmount,
    double? closingAmount,
    double? expectedCash,
    double? difference,
    String? status,
    String? note,
    UserInfo? openedBy,
    UserInfo? closedBy,
    Map<String, dynamic>? paymentSummary,
  });

  @override
  $UserInfoCopyWith<$Res>? get openedBy;
  @override
  $UserInfoCopyWith<$Res>? get closedBy;
}

/// @nodoc
class __$$CashClosingSessionImplCopyWithImpl<$Res>
    extends _$CashClosingSessionCopyWithImpl<$Res, _$CashClosingSessionImpl>
    implements _$$CashClosingSessionImplCopyWith<$Res> {
  __$$CashClosingSessionImplCopyWithImpl(
    _$CashClosingSessionImpl _value,
    $Res Function(_$CashClosingSessionImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of CashClosingSession
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? id = null,
    Object? openedAt = freezed,
    Object? closedAt = freezed,
    Object? initialAmount = freezed,
    Object? closingAmount = freezed,
    Object? expectedCash = freezed,
    Object? difference = freezed,
    Object? status = freezed,
    Object? note = freezed,
    Object? openedBy = freezed,
    Object? closedBy = freezed,
    Object? paymentSummary = freezed,
  }) {
    return _then(
      _$CashClosingSessionImpl(
        id: null == id
            ? _value.id
            : id // ignore: cast_nullable_to_non_nullable
                  as int,
        openedAt: freezed == openedAt
            ? _value.openedAt
            : openedAt // ignore: cast_nullable_to_non_nullable
                  as DateTime?,
        closedAt: freezed == closedAt
            ? _value.closedAt
            : closedAt // ignore: cast_nullable_to_non_nullable
                  as DateTime?,
        initialAmount: freezed == initialAmount
            ? _value.initialAmount
            : initialAmount // ignore: cast_nullable_to_non_nullable
                  as double?,
        closingAmount: freezed == closingAmount
            ? _value.closingAmount
            : closingAmount // ignore: cast_nullable_to_non_nullable
                  as double?,
        expectedCash: freezed == expectedCash
            ? _value.expectedCash
            : expectedCash // ignore: cast_nullable_to_non_nullable
                  as double?,
        difference: freezed == difference
            ? _value.difference
            : difference // ignore: cast_nullable_to_non_nullable
                  as double?,
        status: freezed == status
            ? _value.status
            : status // ignore: cast_nullable_to_non_nullable
                  as String?,
        note: freezed == note
            ? _value.note
            : note // ignore: cast_nullable_to_non_nullable
                  as String?,
        openedBy: freezed == openedBy
            ? _value.openedBy
            : openedBy // ignore: cast_nullable_to_non_nullable
                  as UserInfo?,
        closedBy: freezed == closedBy
            ? _value.closedBy
            : closedBy // ignore: cast_nullable_to_non_nullable
                  as UserInfo?,
        paymentSummary: freezed == paymentSummary
            ? _value._paymentSummary
            : paymentSummary // ignore: cast_nullable_to_non_nullable
                  as Map<String, dynamic>?,
      ),
    );
  }
}

/// @nodoc
@JsonSerializable()
class _$CashClosingSessionImpl implements _CashClosingSession {
  const _$CashClosingSessionImpl({
    required this.id,
    this.openedAt,
    this.closedAt,
    this.initialAmount,
    this.closingAmount,
    this.expectedCash,
    this.difference,
    this.status,
    this.note,
    this.openedBy,
    this.closedBy,
    final Map<String, dynamic>? paymentSummary,
  }) : _paymentSummary = paymentSummary;

  factory _$CashClosingSessionImpl.fromJson(Map<String, dynamic> json) =>
      _$$CashClosingSessionImplFromJson(json);

  @override
  final int id;
  @override
  final DateTime? openedAt;
  @override
  final DateTime? closedAt;
  @override
  final double? initialAmount;
  @override
  final double? closingAmount;
  @override
  final double? expectedCash;
  @override
  final double? difference;
  @override
  final String? status;
  @override
  final String? note;
  @override
  final UserInfo? openedBy;
  @override
  final UserInfo? closedBy;
  final Map<String, dynamic>? _paymentSummary;
  @override
  Map<String, dynamic>? get paymentSummary {
    final value = _paymentSummary;
    if (value == null) return null;
    if (_paymentSummary is EqualUnmodifiableMapView) return _paymentSummary;
    // ignore: implicit_dynamic_type
    return EqualUnmodifiableMapView(value);
  }

  @override
  String toString() {
    return 'CashClosingSession(id: $id, openedAt: $openedAt, closedAt: $closedAt, initialAmount: $initialAmount, closingAmount: $closingAmount, expectedCash: $expectedCash, difference: $difference, status: $status, note: $note, openedBy: $openedBy, closedBy: $closedBy, paymentSummary: $paymentSummary)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$CashClosingSessionImpl &&
            (identical(other.id, id) || other.id == id) &&
            (identical(other.openedAt, openedAt) ||
                other.openedAt == openedAt) &&
            (identical(other.closedAt, closedAt) ||
                other.closedAt == closedAt) &&
            (identical(other.initialAmount, initialAmount) ||
                other.initialAmount == initialAmount) &&
            (identical(other.closingAmount, closingAmount) ||
                other.closingAmount == closingAmount) &&
            (identical(other.expectedCash, expectedCash) ||
                other.expectedCash == expectedCash) &&
            (identical(other.difference, difference) ||
                other.difference == difference) &&
            (identical(other.status, status) || other.status == status) &&
            (identical(other.note, note) || other.note == note) &&
            (identical(other.openedBy, openedBy) ||
                other.openedBy == openedBy) &&
            (identical(other.closedBy, closedBy) ||
                other.closedBy == closedBy) &&
            const DeepCollectionEquality().equals(
              other._paymentSummary,
              _paymentSummary,
            ));
  }

  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  int get hashCode => Object.hash(
    runtimeType,
    id,
    openedAt,
    closedAt,
    initialAmount,
    closingAmount,
    expectedCash,
    difference,
    status,
    note,
    openedBy,
    closedBy,
    const DeepCollectionEquality().hash(_paymentSummary),
  );

  /// Create a copy of CashClosingSession
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$CashClosingSessionImplCopyWith<_$CashClosingSessionImpl> get copyWith =>
      __$$CashClosingSessionImplCopyWithImpl<_$CashClosingSessionImpl>(
        this,
        _$identity,
      );

  @override
  Map<String, dynamic> toJson() {
    return _$$CashClosingSessionImplToJson(this);
  }
}

abstract class _CashClosingSession implements CashClosingSession {
  const factory _CashClosingSession({
    required final int id,
    final DateTime? openedAt,
    final DateTime? closedAt,
    final double? initialAmount,
    final double? closingAmount,
    final double? expectedCash,
    final double? difference,
    final String? status,
    final String? note,
    final UserInfo? openedBy,
    final UserInfo? closedBy,
    final Map<String, dynamic>? paymentSummary,
  }) = _$CashClosingSessionImpl;

  factory _CashClosingSession.fromJson(Map<String, dynamic> json) =
      _$CashClosingSessionImpl.fromJson;

  @override
  int get id;
  @override
  DateTime? get openedAt;
  @override
  DateTime? get closedAt;
  @override
  double? get initialAmount;
  @override
  double? get closingAmount;
  @override
  double? get expectedCash;
  @override
  double? get difference;
  @override
  String? get status;
  @override
  String? get note;
  @override
  UserInfo? get openedBy;
  @override
  UserInfo? get closedBy;
  @override
  Map<String, dynamic>? get paymentSummary;

  /// Create a copy of CashClosingSession
  /// with the given fields replaced by the non-null parameter values.
  @override
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$CashClosingSessionImplCopyWith<_$CashClosingSessionImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

CashClosingTotals _$CashClosingTotalsFromJson(Map<String, dynamic> json) {
  return _CashClosingTotals.fromJson(json);
}

/// @nodoc
mixin _$CashClosingTotals {
  double get totalSales => throw _privateConstructorUsedError;
  Map<String, dynamic> get paymentBreakdown =>
      throw _privateConstructorUsedError;

  /// Serializes this CashClosingTotals to a JSON map.
  Map<String, dynamic> toJson() => throw _privateConstructorUsedError;

  /// Create a copy of CashClosingTotals
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  $CashClosingTotalsCopyWith<CashClosingTotals> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $CashClosingTotalsCopyWith<$Res> {
  factory $CashClosingTotalsCopyWith(
    CashClosingTotals value,
    $Res Function(CashClosingTotals) then,
  ) = _$CashClosingTotalsCopyWithImpl<$Res, CashClosingTotals>;
  @useResult
  $Res call({double totalSales, Map<String, dynamic> paymentBreakdown});
}

/// @nodoc
class _$CashClosingTotalsCopyWithImpl<$Res, $Val extends CashClosingTotals>
    implements $CashClosingTotalsCopyWith<$Res> {
  _$CashClosingTotalsCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of CashClosingTotals
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({Object? totalSales = null, Object? paymentBreakdown = null}) {
    return _then(
      _value.copyWith(
            totalSales: null == totalSales
                ? _value.totalSales
                : totalSales // ignore: cast_nullable_to_non_nullable
                      as double,
            paymentBreakdown: null == paymentBreakdown
                ? _value.paymentBreakdown
                : paymentBreakdown // ignore: cast_nullable_to_non_nullable
                      as Map<String, dynamic>,
          )
          as $Val,
    );
  }
}

/// @nodoc
abstract class _$$CashClosingTotalsImplCopyWith<$Res>
    implements $CashClosingTotalsCopyWith<$Res> {
  factory _$$CashClosingTotalsImplCopyWith(
    _$CashClosingTotalsImpl value,
    $Res Function(_$CashClosingTotalsImpl) then,
  ) = __$$CashClosingTotalsImplCopyWithImpl<$Res>;
  @override
  @useResult
  $Res call({double totalSales, Map<String, dynamic> paymentBreakdown});
}

/// @nodoc
class __$$CashClosingTotalsImplCopyWithImpl<$Res>
    extends _$CashClosingTotalsCopyWithImpl<$Res, _$CashClosingTotalsImpl>
    implements _$$CashClosingTotalsImplCopyWith<$Res> {
  __$$CashClosingTotalsImplCopyWithImpl(
    _$CashClosingTotalsImpl _value,
    $Res Function(_$CashClosingTotalsImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of CashClosingTotals
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({Object? totalSales = null, Object? paymentBreakdown = null}) {
    return _then(
      _$CashClosingTotalsImpl(
        totalSales: null == totalSales
            ? _value.totalSales
            : totalSales // ignore: cast_nullable_to_non_nullable
                  as double,
        paymentBreakdown: null == paymentBreakdown
            ? _value._paymentBreakdown
            : paymentBreakdown // ignore: cast_nullable_to_non_nullable
                  as Map<String, dynamic>,
      ),
    );
  }
}

/// @nodoc
@JsonSerializable()
class _$CashClosingTotalsImpl implements _CashClosingTotals {
  const _$CashClosingTotalsImpl({
    required this.totalSales,
    required final Map<String, dynamic> paymentBreakdown,
  }) : _paymentBreakdown = paymentBreakdown;

  factory _$CashClosingTotalsImpl.fromJson(Map<String, dynamic> json) =>
      _$$CashClosingTotalsImplFromJson(json);

  @override
  final double totalSales;
  final Map<String, dynamic> _paymentBreakdown;
  @override
  Map<String, dynamic> get paymentBreakdown {
    if (_paymentBreakdown is EqualUnmodifiableMapView) return _paymentBreakdown;
    // ignore: implicit_dynamic_type
    return EqualUnmodifiableMapView(_paymentBreakdown);
  }

  @override
  String toString() {
    return 'CashClosingTotals(totalSales: $totalSales, paymentBreakdown: $paymentBreakdown)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$CashClosingTotalsImpl &&
            (identical(other.totalSales, totalSales) ||
                other.totalSales == totalSales) &&
            const DeepCollectionEquality().equals(
              other._paymentBreakdown,
              _paymentBreakdown,
            ));
  }

  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  int get hashCode => Object.hash(
    runtimeType,
    totalSales,
    const DeepCollectionEquality().hash(_paymentBreakdown),
  );

  /// Create a copy of CashClosingTotals
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$CashClosingTotalsImplCopyWith<_$CashClosingTotalsImpl> get copyWith =>
      __$$CashClosingTotalsImplCopyWithImpl<_$CashClosingTotalsImpl>(
        this,
        _$identity,
      );

  @override
  Map<String, dynamic> toJson() {
    return _$$CashClosingTotalsImplToJson(this);
  }
}

abstract class _CashClosingTotals implements CashClosingTotals {
  const factory _CashClosingTotals({
    required final double totalSales,
    required final Map<String, dynamic> paymentBreakdown,
  }) = _$CashClosingTotalsImpl;

  factory _CashClosingTotals.fromJson(Map<String, dynamic> json) =
      _$CashClosingTotalsImpl.fromJson;

  @override
  double get totalSales;
  @override
  Map<String, dynamic> get paymentBreakdown;

  /// Create a copy of CashClosingTotals
  /// with the given fields replaced by the non-null parameter values.
  @override
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$CashClosingTotalsImplCopyWith<_$CashClosingTotalsImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

SaleMinimal _$SaleMinimalFromJson(Map<String, dynamic> json) {
  return _SaleMinimal.fromJson(json);
}

/// @nodoc
mixin _$SaleMinimal {
  int get id => throw _privateConstructorUsedError;
  double get total => throw _privateConstructorUsedError;
  String? get paymentMethod => throw _privateConstructorUsedError;
  DateTime? get createdAt => throw _privateConstructorUsedError;

  /// Serializes this SaleMinimal to a JSON map.
  Map<String, dynamic> toJson() => throw _privateConstructorUsedError;

  /// Create a copy of SaleMinimal
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  $SaleMinimalCopyWith<SaleMinimal> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $SaleMinimalCopyWith<$Res> {
  factory $SaleMinimalCopyWith(
    SaleMinimal value,
    $Res Function(SaleMinimal) then,
  ) = _$SaleMinimalCopyWithImpl<$Res, SaleMinimal>;
  @useResult
  $Res call({int id, double total, String? paymentMethod, DateTime? createdAt});
}

/// @nodoc
class _$SaleMinimalCopyWithImpl<$Res, $Val extends SaleMinimal>
    implements $SaleMinimalCopyWith<$Res> {
  _$SaleMinimalCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of SaleMinimal
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? id = null,
    Object? total = null,
    Object? paymentMethod = freezed,
    Object? createdAt = freezed,
  }) {
    return _then(
      _value.copyWith(
            id: null == id
                ? _value.id
                : id // ignore: cast_nullable_to_non_nullable
                      as int,
            total: null == total
                ? _value.total
                : total // ignore: cast_nullable_to_non_nullable
                      as double,
            paymentMethod: freezed == paymentMethod
                ? _value.paymentMethod
                : paymentMethod // ignore: cast_nullable_to_non_nullable
                      as String?,
            createdAt: freezed == createdAt
                ? _value.createdAt
                : createdAt // ignore: cast_nullable_to_non_nullable
                      as DateTime?,
          )
          as $Val,
    );
  }
}

/// @nodoc
abstract class _$$SaleMinimalImplCopyWith<$Res>
    implements $SaleMinimalCopyWith<$Res> {
  factory _$$SaleMinimalImplCopyWith(
    _$SaleMinimalImpl value,
    $Res Function(_$SaleMinimalImpl) then,
  ) = __$$SaleMinimalImplCopyWithImpl<$Res>;
  @override
  @useResult
  $Res call({int id, double total, String? paymentMethod, DateTime? createdAt});
}

/// @nodoc
class __$$SaleMinimalImplCopyWithImpl<$Res>
    extends _$SaleMinimalCopyWithImpl<$Res, _$SaleMinimalImpl>
    implements _$$SaleMinimalImplCopyWith<$Res> {
  __$$SaleMinimalImplCopyWithImpl(
    _$SaleMinimalImpl _value,
    $Res Function(_$SaleMinimalImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of SaleMinimal
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? id = null,
    Object? total = null,
    Object? paymentMethod = freezed,
    Object? createdAt = freezed,
  }) {
    return _then(
      _$SaleMinimalImpl(
        id: null == id
            ? _value.id
            : id // ignore: cast_nullable_to_non_nullable
                  as int,
        total: null == total
            ? _value.total
            : total // ignore: cast_nullable_to_non_nullable
                  as double,
        paymentMethod: freezed == paymentMethod
            ? _value.paymentMethod
            : paymentMethod // ignore: cast_nullable_to_non_nullable
                  as String?,
        createdAt: freezed == createdAt
            ? _value.createdAt
            : createdAt // ignore: cast_nullable_to_non_nullable
                  as DateTime?,
      ),
    );
  }
}

/// @nodoc
@JsonSerializable()
class _$SaleMinimalImpl implements _SaleMinimal {
  const _$SaleMinimalImpl({
    required this.id,
    required this.total,
    this.paymentMethod,
    this.createdAt,
  });

  factory _$SaleMinimalImpl.fromJson(Map<String, dynamic> json) =>
      _$$SaleMinimalImplFromJson(json);

  @override
  final int id;
  @override
  final double total;
  @override
  final String? paymentMethod;
  @override
  final DateTime? createdAt;

  @override
  String toString() {
    return 'SaleMinimal(id: $id, total: $total, paymentMethod: $paymentMethod, createdAt: $createdAt)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SaleMinimalImpl &&
            (identical(other.id, id) || other.id == id) &&
            (identical(other.total, total) || other.total == total) &&
            (identical(other.paymentMethod, paymentMethod) ||
                other.paymentMethod == paymentMethod) &&
            (identical(other.createdAt, createdAt) ||
                other.createdAt == createdAt));
  }

  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  int get hashCode =>
      Object.hash(runtimeType, id, total, paymentMethod, createdAt);

  /// Create a copy of SaleMinimal
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$SaleMinimalImplCopyWith<_$SaleMinimalImpl> get copyWith =>
      __$$SaleMinimalImplCopyWithImpl<_$SaleMinimalImpl>(this, _$identity);

  @override
  Map<String, dynamic> toJson() {
    return _$$SaleMinimalImplToJson(this);
  }
}

abstract class _SaleMinimal implements SaleMinimal {
  const factory _SaleMinimal({
    required final int id,
    required final double total,
    final String? paymentMethod,
    final DateTime? createdAt,
  }) = _$SaleMinimalImpl;

  factory _SaleMinimal.fromJson(Map<String, dynamic> json) =
      _$SaleMinimalImpl.fromJson;

  @override
  int get id;
  @override
  double get total;
  @override
  String? get paymentMethod;
  @override
  DateTime? get createdAt;

  /// Create a copy of SaleMinimal
  /// with the given fields replaced by the non-null parameter values.
  @override
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$SaleMinimalImplCopyWith<_$SaleMinimalImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

CashMovementRow _$CashMovementRowFromJson(Map<String, dynamic> json) {
  return _CashMovementRow.fromJson(json);
}

/// @nodoc
mixin _$CashMovementRow {
  int get id => throw _privateConstructorUsedError;
  String get type => throw _privateConstructorUsedError;
  double get amount => throw _privateConstructorUsedError;
  String? get note => throw _privateConstructorUsedError;
  DateTime? get createdAt => throw _privateConstructorUsedError;

  /// Serializes this CashMovementRow to a JSON map.
  Map<String, dynamic> toJson() => throw _privateConstructorUsedError;

  /// Create a copy of CashMovementRow
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  $CashMovementRowCopyWith<CashMovementRow> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $CashMovementRowCopyWith<$Res> {
  factory $CashMovementRowCopyWith(
    CashMovementRow value,
    $Res Function(CashMovementRow) then,
  ) = _$CashMovementRowCopyWithImpl<$Res, CashMovementRow>;
  @useResult
  $Res call({
    int id,
    String type,
    double amount,
    String? note,
    DateTime? createdAt,
  });
}

/// @nodoc
class _$CashMovementRowCopyWithImpl<$Res, $Val extends CashMovementRow>
    implements $CashMovementRowCopyWith<$Res> {
  _$CashMovementRowCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of CashMovementRow
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? id = null,
    Object? type = null,
    Object? amount = null,
    Object? note = freezed,
    Object? createdAt = freezed,
  }) {
    return _then(
      _value.copyWith(
            id: null == id
                ? _value.id
                : id // ignore: cast_nullable_to_non_nullable
                      as int,
            type: null == type
                ? _value.type
                : type // ignore: cast_nullable_to_non_nullable
                      as String,
            amount: null == amount
                ? _value.amount
                : amount // ignore: cast_nullable_to_non_nullable
                      as double,
            note: freezed == note
                ? _value.note
                : note // ignore: cast_nullable_to_non_nullable
                      as String?,
            createdAt: freezed == createdAt
                ? _value.createdAt
                : createdAt // ignore: cast_nullable_to_non_nullable
                      as DateTime?,
          )
          as $Val,
    );
  }
}

/// @nodoc
abstract class _$$CashMovementRowImplCopyWith<$Res>
    implements $CashMovementRowCopyWith<$Res> {
  factory _$$CashMovementRowImplCopyWith(
    _$CashMovementRowImpl value,
    $Res Function(_$CashMovementRowImpl) then,
  ) = __$$CashMovementRowImplCopyWithImpl<$Res>;
  @override
  @useResult
  $Res call({
    int id,
    String type,
    double amount,
    String? note,
    DateTime? createdAt,
  });
}

/// @nodoc
class __$$CashMovementRowImplCopyWithImpl<$Res>
    extends _$CashMovementRowCopyWithImpl<$Res, _$CashMovementRowImpl>
    implements _$$CashMovementRowImplCopyWith<$Res> {
  __$$CashMovementRowImplCopyWithImpl(
    _$CashMovementRowImpl _value,
    $Res Function(_$CashMovementRowImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of CashMovementRow
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? id = null,
    Object? type = null,
    Object? amount = null,
    Object? note = freezed,
    Object? createdAt = freezed,
  }) {
    return _then(
      _$CashMovementRowImpl(
        id: null == id
            ? _value.id
            : id // ignore: cast_nullable_to_non_nullable
                  as int,
        type: null == type
            ? _value.type
            : type // ignore: cast_nullable_to_non_nullable
                  as String,
        amount: null == amount
            ? _value.amount
            : amount // ignore: cast_nullable_to_non_nullable
                  as double,
        note: freezed == note
            ? _value.note
            : note // ignore: cast_nullable_to_non_nullable
                  as String?,
        createdAt: freezed == createdAt
            ? _value.createdAt
            : createdAt // ignore: cast_nullable_to_non_nullable
                  as DateTime?,
      ),
    );
  }
}

/// @nodoc
@JsonSerializable()
class _$CashMovementRowImpl implements _CashMovementRow {
  const _$CashMovementRowImpl({
    required this.id,
    required this.type,
    required this.amount,
    this.note,
    this.createdAt,
  });

  factory _$CashMovementRowImpl.fromJson(Map<String, dynamic> json) =>
      _$$CashMovementRowImplFromJson(json);

  @override
  final int id;
  @override
  final String type;
  @override
  final double amount;
  @override
  final String? note;
  @override
  final DateTime? createdAt;

  @override
  String toString() {
    return 'CashMovementRow(id: $id, type: $type, amount: $amount, note: $note, createdAt: $createdAt)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$CashMovementRowImpl &&
            (identical(other.id, id) || other.id == id) &&
            (identical(other.type, type) || other.type == type) &&
            (identical(other.amount, amount) || other.amount == amount) &&
            (identical(other.note, note) || other.note == note) &&
            (identical(other.createdAt, createdAt) ||
                other.createdAt == createdAt));
  }

  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  int get hashCode =>
      Object.hash(runtimeType, id, type, amount, note, createdAt);

  /// Create a copy of CashMovementRow
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$CashMovementRowImplCopyWith<_$CashMovementRowImpl> get copyWith =>
      __$$CashMovementRowImplCopyWithImpl<_$CashMovementRowImpl>(
        this,
        _$identity,
      );

  @override
  Map<String, dynamic> toJson() {
    return _$$CashMovementRowImplToJson(this);
  }
}

abstract class _CashMovementRow implements CashMovementRow {
  const factory _CashMovementRow({
    required final int id,
    required final String type,
    required final double amount,
    final String? note,
    final DateTime? createdAt,
  }) = _$CashMovementRowImpl;

  factory _CashMovementRow.fromJson(Map<String, dynamic> json) =
      _$CashMovementRowImpl.fromJson;

  @override
  int get id;
  @override
  String get type;
  @override
  double get amount;
  @override
  String? get note;
  @override
  DateTime? get createdAt;

  /// Create a copy of CashMovementRow
  /// with the given fields replaced by the non-null parameter values.
  @override
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$CashMovementRowImplCopyWith<_$CashMovementRowImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

class OverrideRequestItem {
  OverrideRequestItem({
    required this.id,
    required this.actionCode,
    required this.status,
    required this.createdAt,
    this.resourceType,
    this.resourceId,
    this.terminalId,
    this.meta,
    this.requestedByName,
    this.approvedByName,
  });

  final int id;
  final String actionCode;
  final String? resourceType;
  final String? resourceId;
  final String status;
  final String? terminalId;
  final DateTime createdAt;
  final Map<String, dynamic>? meta;
  final String? requestedByName;
  final String? approvedByName;

  factory OverrideRequestItem.fromJson(Map<String, dynamic> json) {
    final requestedBy = json['requestedBy'] as Map<String, dynamic>?;
    final approvedBy = json['approvedBy'] as Map<String, dynamic>?;
    final meta = json['meta'] is Map<String, dynamic>
        ? (json['meta'] as Map<String, dynamic>)
        : null;
    return OverrideRequestItem(
      id: json['id'] as int,
      actionCode: (json['actionCode'] ?? '').toString(),
      resourceType: json['resourceType'] as String?,
      resourceId: json['resourceId'] as String?,
      status: (json['status'] ?? '').toString(),
      terminalId: json['terminalId'] as String?,
      createdAt: DateTime.tryParse(json['createdAt']?.toString() ?? '') ??
          DateTime.now(),
      meta: meta,
      requestedByName:
          (requestedBy?['displayName'] ?? requestedBy?['username'])?.toString(),
      approvedByName:
          (approvedBy?['displayName'] ?? approvedBy?['username'])?.toString(),
    );
  }
}

class ApprovedOverrideToken {
  ApprovedOverrideToken({
    required this.requestId,
    required this.token,
    required this.expiresAt,
  });

  final int requestId;
  final String token;
  final DateTime expiresAt;

  factory ApprovedOverrideToken.fromJson(Map<String, dynamic> json) {
    return ApprovedOverrideToken(
      requestId: json['requestId'] as int,
      token: (json['token'] ?? '').toString(),
      expiresAt: DateTime.tryParse(json['expiresAt']?.toString() ?? '') ??
          DateTime.now(),
    );
  }
}

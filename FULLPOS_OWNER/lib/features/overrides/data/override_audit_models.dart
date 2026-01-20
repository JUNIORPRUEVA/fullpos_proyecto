class OverrideAuditEntry {
  OverrideAuditEntry({
    required this.id,
    required this.actionCode,
    required this.result,
    required this.method,
    required this.createdAt,
    this.resourceType,
    this.resourceId,
    this.terminalId,
    this.meta,
    this.requestedById,
    this.approvedById,
    this.requestedByName,
    this.approvedByName,
  });

  final int id;
  final String actionCode;
  final String result;
  final String method;
  final DateTime createdAt;
  final String? resourceType;
  final String? resourceId;
  final String? terminalId;
  final Map<String, dynamic>? meta;
  final int? requestedById;
  final int? approvedById;
  final String? requestedByName;
  final String? approvedByName;

  factory OverrideAuditEntry.fromJson(Map<String, dynamic> json) {
    final requestedByName = json['requestedByName'] as String? ??
        _resolveUserName(json['requestedBy'] as Map<String, dynamic>?);
    final approvedByName = json['approvedByName'] as String? ??
        _resolveUserName(json['approvedBy'] as Map<String, dynamic>?);
    final createdAt =
        DateTime.tryParse(json['createdAt']?.toString() ?? '') ?? DateTime.now();

    return OverrideAuditEntry(
      id: json['id'] as int,
      actionCode: (json['actionCode'] ?? '').toString(),
      resourceType: json['resourceType'] as String?,
      resourceId: json['resourceId'] as String?,
      result: (json['result'] ?? '').toString(),
      method: (json['method'] ?? '').toString(),
      createdAt: createdAt,
      terminalId: json['terminalId'] as String?,
      meta: _normalizeMeta(json['meta']),
      requestedById: json['requestedById'] as int?,
      approvedById: json['approvedById'] as int?,
      requestedByName: requestedByName,
      approvedByName: approvedByName,
    );
  }

  static String? _resolveUserName(Map<String, dynamic>? user) {
    if (user == null) return null;
    final displayName = (user['displayName'] ?? '').toString().trim();
    if (displayName.isNotEmpty) return displayName;
    final username = (user['username'] ?? '').toString().trim();
    if (username.isNotEmpty) return username;
    return null;
  }

  static Map<String, dynamic>? _normalizeMeta(dynamic raw) {
    if (raw == null) return null;
    if (raw is Map<String, dynamic>) return raw;
    if (raw is Map) return Map<String, dynamic>.from(raw);
    return null;
  }
}

import 'dart:convert';

enum BackupTrigger {
  manual,
  autoWindowClose,
  autoLifecycle,
}

class BackupMeta {
  const BackupMeta({
    required this.createdAtIso,
    required this.trigger,
    required this.appVersion,
    required this.platform,
    required this.dbFileName,
    required this.includedPaths,
    this.notes,
    this.integrityCheckOk,
  });

  final String createdAtIso;
  final BackupTrigger trigger;
  final String appVersion;
  final String platform;
  final String dbFileName;
  final List<String> includedPaths;
  final String? notes;
  final bool? integrityCheckOk;

  Map<String, dynamic> toJson() => {
        'createdAt': createdAtIso,
        'trigger': trigger.name,
        'appVersion': appVersion,
        'platform': platform,
        'dbFileName': dbFileName,
        'includedPaths': includedPaths,
        if (notes != null) 'notes': notes,
        if (integrityCheckOk != null) 'integrityCheckOk': integrityCheckOk,
      };

  String toPrettyJson() => const JsonEncoder.withIndent('  ').convert(toJson());
}

class BackupResult {
  const BackupResult({
    required this.ok,
    this.path,
    this.messageUser,
    this.messageDev,
    this.integrityCheckOk,
  });

  final bool ok;
  final String? path;
  final String? messageUser;
  final String? messageDev;
  final bool? integrityCheckOk;
}


final class ContentPolicy {
  const ContentPolicy({
    required this.configured,
    required this.catalogRootId,
    required this.displayName,
    required this.contentOptIn,
    required this.eligibleFileCount,
    required this.supportedFileCount,
    required this.supportedFormatCounts,
  });

  final bool configured;
  final String? catalogRootId;
  final String? displayName;
  final bool contentOptIn;
  final int eligibleFileCount;
  final int supportedFileCount;
  final Map<String, int> supportedFormatCounts;

  factory ContentPolicy.fromJson(Map<String, Object?> value) {
    const keys = {
      'configured',
      'catalog_root_id',
      'display_name',
      'content_opt_in',
      'eligible_file_count',
      'supported_file_count',
      'supported_format_counts',
    };
    if (value.length != keys.length || !value.keys.toSet().containsAll(keys)) {
      throw const FormatException();
    }
    final configured = value['configured'];
    final rootId = value['catalog_root_id'];
    final displayName = value['display_name'];
    final optIn = value['content_opt_in'];
    final eligible = value['eligible_file_count'];
    final supported = value['supported_file_count'];
    final formatCounts = value['supported_format_counts'];
    const supportedFormats = {'txt', 'md', 'docx', 'pptx', 'pdf'};
    if (configured is! bool ||
        optIn is! bool ||
        eligible is! int ||
        eligible < 0 ||
        supported is! int ||
        supported < 0 ||
        supported > eligible ||
        formatCounts is! Map<String, Object?> ||
        formatCounts.keys.any((key) => !supportedFormats.contains(key)) ||
        formatCounts.values.any((count) => count is! int || count <= 0) ||
        formatCounts.values.fold<int>(
              0,
              (sum, count) => sum + (count as int),
            ) !=
            supported ||
        (rootId != null &&
            (rootId is! String ||
                !RegExp(
                  r'^(?:[0-9a-f]{64}|pc-[0-9a-f]{12})$',
                ).hasMatch(rootId))) ||
        (displayName != null &&
            (displayName is! String ||
                displayName.isEmpty ||
                displayName.length > 80)) ||
        configured != (rootId != null && displayName != null) ||
        (!configured && (optIn || eligible != 0 || supported != 0))) {
      throw const FormatException();
    }
    return ContentPolicy(
      configured: configured,
      catalogRootId: rootId as String?,
      displayName: displayName as String?,
      contentOptIn: optIn,
      eligibleFileCount: eligible,
      supportedFileCount: supported,
      supportedFormatCounts: Map.unmodifiable(
        formatCounts.map((key, count) => MapEntry(key, count as int)),
      ),
    );
  }
}

final class StudyPack {
  const StudyPack({
    required this.title,
    required this.summary,
    required this.topics,
    required this.reviewPoints,
    required this.source,
    required this.createdAt,
  });

  final String title;
  final String summary;
  final List<String> topics;
  final List<String> reviewPoints;
  final String source;
  final DateTime createdAt;

  factory StudyPack.fromJson(Map<String, Object?> value) {
    const keys = {
      'schema_version',
      'title',
      'summary',
      'topics',
      'review_points',
      'source',
      'created_at',
    };
    if (value.length != keys.length ||
        !value.keys.toSet().containsAll(keys) ||
        value['schema_version'] != 'data-steward.study-pack/v1') {
      throw const FormatException();
    }
    final title = _safeText(value['title'], 80);
    final summary = _safeText(value['summary'], 600);
    final topics = _safeList(value['topics'], maxItems: 5, maxChars: 40);
    final points = _safeList(
      value['review_points'],
      maxItems: 6,
      maxChars: 160,
    );
    final source = value['source'];
    final created = value['created_at'];
    if (!const {'hermes', 'deterministic_fallback'}.contains(source) ||
        created is! String) {
      throw const FormatException();
    }
    final createdAt = DateTime.tryParse(created)?.toUtc();
    if (createdAt == null || !created.endsWith('Z')) {
      throw const FormatException();
    }
    return StudyPack(
      title: title,
      summary: summary,
      topics: List.unmodifiable(topics),
      reviewPoints: List.unmodifiable(points),
      source: source! as String,
      createdAt: createdAt,
    );
  }
}

String _safeText(Object? value, int maxChars) {
  if (value is! String ||
      value.trim().isEmpty ||
      value.length > maxChars ||
      value.runes.any((rune) => rune < 0x20 && rune != 0x0a && rune != 0x09) ||
      value.toLowerCase().contains('content://') ||
      RegExp(
        r'(?:[a-z]:\\|\\\\|/users/|/home/)',
        caseSensitive: false,
      ).hasMatch(value)) {
    throw const FormatException();
  }
  return value.trim();
}

List<String> _safeList(
  Object? value, {
  required int maxItems,
  required int maxChars,
}) {
  if (value is! List<Object?> || value.isEmpty || value.length > maxItems) {
    throw const FormatException();
  }
  final result = value.map((item) => _safeText(item, maxChars)).toList();
  if (result.toSet().length != result.length) throw const FormatException();
  return result;
}

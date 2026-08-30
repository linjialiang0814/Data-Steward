import 'dart:convert';

import 'package:crypto/crypto.dart';

const todayMaterialsSchema = 'data-steward.today-materials/v1';
const todayClusterRuleVersion = 'time-name-v1';

final class TodayAsset {
  const TodayAsset({
    required this.assetId,
    required this.displayName,
    required this.platform,
    required this.sourceDisplayName,
    required this.mimeFamily,
    required this.effectiveAtMillis,
    required this.timeSource,
  });

  final String assetId;
  final String displayName;
  final String platform;
  final String sourceDisplayName;
  final String mimeFamily;
  final int effectiveAtMillis;
  final String timeSource;

  factory TodayAsset.fromJson(Object? raw) {
    final value = _map(raw);
    const keys = {
      'asset_id',
      'display_name',
      'platform',
      'source_display_name',
      'mime_family',
      'effective_at_ms',
      'time_source',
    };
    if (!_exactKeys(value, keys) ||
        !_digest(value['asset_id']) ||
        !_safeText(value['display_name'], 255) ||
        !const {'android', 'windows'}.contains(value['platform']) ||
        !_safeText(value['source_display_name'], 80) ||
        !const {
          'image',
          'audio',
          'video',
          'text',
          'document',
          'archive',
          'other',
        }.contains(value['mime_family']) ||
        value['effective_at_ms'] is! int ||
        (value['effective_at_ms']! as int) < 0 ||
        !const {'modified', 'observed'}.contains(value['time_source'])) {
      throw const FormatException('today_asset_invalid');
    }
    return TodayAsset(
      assetId: value['asset_id']! as String,
      displayName: value['display_name']! as String,
      platform: value['platform']! as String,
      sourceDisplayName: value['source_display_name']! as String,
      mimeFamily: value['mime_family']! as String,
      effectiveAtMillis: value['effective_at_ms']! as int,
      timeSource: value['time_source']! as String,
    );
  }
}

final class TodayCluster {
  const TodayCluster({
    required this.clusterId,
    required this.title,
    required this.startAtMillis,
    required this.endAtMillis,
    required this.sourcePlatforms,
    required this.mimeFamilies,
    required this.assetCount,
    required this.confidencePermille,
    required this.confidenceBand,
    required this.reasons,
    required this.assets,
  });

  final String clusterId;
  final String title;
  final int startAtMillis;
  final int endAtMillis;
  final List<String> sourcePlatforms;
  final List<String> mimeFamilies;
  final int assetCount;
  final int confidencePermille;
  final String confidenceBand;
  final List<String> reasons;
  final List<TodayAsset> assets;

  factory TodayCluster.fromJson(Object? raw) {
    final value = _map(raw);
    const keys = {
      'cluster_id',
      'title',
      'start_at_ms',
      'end_at_ms',
      'source_platforms',
      'mime_families',
      'asset_count',
      'confidence_permille',
      'confidence_band',
      'reasons',
      'assets',
    };
    final platforms = _strings(value['source_platforms']);
    final families = _strings(value['mime_families']);
    final reasons = _strings(value['reasons']);
    final rawAssets = value['assets'];
    if (!_exactKeys(value, keys) ||
        value['cluster_id'] is! String ||
        !RegExp(
          r'^cl-[0-9a-f]{16}$',
        ).hasMatch(value['cluster_id']! as String) ||
        !_safeText(value['title'], 80) ||
        value['start_at_ms'] is! int ||
        value['end_at_ms'] is! int ||
        (value['start_at_ms']! as int) < 0 ||
        (value['end_at_ms']! as int) < (value['start_at_ms']! as int) ||
        platforms == null ||
        platforms.isEmpty ||
        !_sortedUnique(platforms) ||
        platforms.any((item) => !const {'android', 'windows'}.contains(item)) ||
        families == null ||
        families.isEmpty ||
        !_sortedUnique(families) ||
        reasons == null ||
        reasons.isEmpty ||
        reasons.length > 3 ||
        reasons.any((item) => !_safeText(item, 120)) ||
        rawAssets is! List<Object?> ||
        value['asset_count'] is! int ||
        value['confidence_permille'] is! int ||
        !const {'high', 'medium'}.contains(value['confidence_band'])) {
      throw const FormatException('today_cluster_invalid');
    }
    final assets = rawAssets.map(TodayAsset.fromJson).toList(growable: false);
    final confidence = value['confidence_permille']! as int;
    final band = value['confidence_band']! as String;
    if (assets.length != value['asset_count'] ||
        assets.length < 2 ||
        confidence < 550 ||
        confidence > 1000 ||
        (band == 'high') != (confidence >= 800) ||
        !_assetsAscending(assets) ||
        assets.any(
          (asset) =>
              asset.effectiveAtMillis < (value['start_at_ms']! as int) ||
              asset.effectiveAtMillis > (value['end_at_ms']! as int) ||
              !platforms.contains(asset.platform) ||
              !families.contains(asset.mimeFamily),
        )) {
      throw const FormatException('today_cluster_invalid');
    }
    return TodayCluster(
      clusterId: value['cluster_id']! as String,
      title: value['title']! as String,
      startAtMillis: value['start_at_ms']! as int,
      endAtMillis: value['end_at_ms']! as int,
      sourcePlatforms: platforms,
      mimeFamilies: families,
      assetCount: assets.length,
      confidencePermille: confidence,
      confidenceBand: band,
      reasons: reasons,
      assets: assets,
    );
  }
}

final class TodayMaterialsProjection {
  const TodayMaterialsProjection({
    required this.localDay,
    required this.timezoneOffsetMinutes,
    required this.rootCount,
    required this.assetCount,
    required this.clusters,
    required this.unassigned,
    required this.projectionSha256,
  });

  final String localDay;
  final int timezoneOffsetMinutes;
  final int rootCount;
  final int assetCount;
  final List<TodayCluster> clusters;
  final List<TodayAsset> unassigned;
  final String projectionSha256;

  factory TodayMaterialsProjection.fromJson(Map<String, Object?> value) {
    const keys = {
      'schema_version',
      'rule_version',
      'local_day',
      'timezone_offset_minutes',
      'source_projection_sha256',
      'root_count',
      'asset_count',
      'cluster_count',
      'unassigned_count',
      'clusters',
      'unassigned',
      'projection_sha256',
    };
    final rawClusters = value['clusters'];
    final rawUnassigned = value['unassigned'];
    if (!_exactKeys(value, keys) ||
        value['schema_version'] != todayMaterialsSchema ||
        value['rule_version'] != todayClusterRuleVersion ||
        value['local_day'] is! String ||
        !RegExp(
          r'^\d{4}-\d{2}-\d{2}$',
        ).hasMatch(value['local_day']! as String) ||
        value['timezone_offset_minutes'] != 480 ||
        !_digest(value['source_projection_sha256']) ||
        !_digest(value['projection_sha256']) ||
        value['root_count'] is! int ||
        value['asset_count'] is! int ||
        value['cluster_count'] is! int ||
        value['unassigned_count'] is! int ||
        rawClusters is! List<Object?> ||
        rawUnassigned is! List<Object?> ||
        (value['root_count']! as int) < 0 ||
        (value['root_count']! as int) > 512 ||
        (value['asset_count']! as int) < 0 ||
        (value['asset_count']! as int) > 512) {
      throw const FormatException('today_projection_invalid');
    }
    final clusters = rawClusters
        .map(TodayCluster.fromJson)
        .toList(growable: false);
    final unassigned = rawUnassigned
        .map(TodayAsset.fromJson)
        .toList(growable: false);
    final allAssets = [
      for (final cluster in clusters) ...cluster.assets,
      ...unassigned,
    ];
    if (clusters.length != value['cluster_count'] ||
        unassigned.length != value['unassigned_count'] ||
        allAssets.length != value['asset_count'] ||
        {for (final item in allAssets) item.assetId}.length !=
            allAssets.length ||
        {for (final item in clusters) item.clusterId}.length !=
            clusters.length ||
        !_clustersDescending(clusters) ||
        !_assetsDescending(unassigned)) {
      throw const FormatException('today_projection_invalid');
    }
    final projectionHash = value['projection_sha256']! as String;
    final hashInput = Map<String, Object?>.from(value)
      ..remove('projection_sha256');
    final actual = sha256
        .convert(utf8.encode(jsonEncode(_canonical(hashInput))))
        .toString();
    if (actual != projectionHash) {
      throw const FormatException('today_projection_hash_invalid');
    }
    return TodayMaterialsProjection(
      localDay: value['local_day']! as String,
      timezoneOffsetMinutes: value['timezone_offset_minutes']! as int,
      rootCount: value['root_count']! as int,
      assetCount: value['asset_count']! as int,
      clusters: clusters,
      unassigned: unassigned,
      projectionSha256: projectionHash,
    );
  }
}

Map<String, Object?> _map(Object? value) {
  if (value is! Map<String, Object?>) throw const FormatException();
  return value;
}

bool _exactKeys(Map<String, Object?> value, Set<String> expected) =>
    value.length == expected.length && value.keys.toSet().containsAll(expected);

bool _digest(Object? value) =>
    value is String && RegExp(r'^[0-9a-f]{64}$').hasMatch(value);

bool _safeText(Object? value, int maxLength) =>
    value is String &&
    value.isNotEmpty &&
    value.length <= maxLength &&
    !value.runes.any((rune) => rune < 0x20 || rune == 0x7f);

List<String>? _strings(Object? value) {
  if (value is! List<Object?> || value.any((item) => item is! String)) {
    return null;
  }
  return value.cast<String>();
}

bool _sortedUnique(List<String> values) {
  final sorted = [...values]..sort();
  return values.length == values.toSet().length &&
      List.generate(
        values.length,
        (index) => values[index] == sorted[index],
      ).every((v) => v);
}

bool _assetsAscending(List<TodayAsset> assets) {
  for (var index = 1; index < assets.length; index++) {
    final previous = assets[index - 1];
    final current = assets[index];
    if (previous.effectiveAtMillis > current.effectiveAtMillis ||
        (previous.effectiveAtMillis == current.effectiveAtMillis &&
            previous.assetId.compareTo(current.assetId) > 0)) {
      return false;
    }
  }
  return true;
}

bool _assetsDescending(List<TodayAsset> assets) {
  for (var index = 1; index < assets.length; index++) {
    final previous = assets[index - 1];
    final current = assets[index];
    if (previous.effectiveAtMillis < current.effectiveAtMillis ||
        (previous.effectiveAtMillis == current.effectiveAtMillis &&
            previous.assetId.compareTo(current.assetId) > 0)) {
      return false;
    }
  }
  return true;
}

bool _clustersDescending(List<TodayCluster> clusters) {
  for (var index = 1; index < clusters.length; index++) {
    final previous = clusters[index - 1];
    final current = clusters[index];
    if (previous.endAtMillis < current.endAtMillis ||
        (previous.endAtMillis == current.endAtMillis &&
            previous.clusterId.compareTo(current.clusterId) > 0)) {
      return false;
    }
  }
  return true;
}

Object? _canonical(Object? value) {
  if (value is Map<String, Object?>) {
    final keys = value.keys.toList()..sort();
    return {for (final key in keys) key: _canonical(value[key])};
  }
  if (value is List<Object?>) {
    return value.map(_canonical).toList(growable: false);
  }
  return value;
}

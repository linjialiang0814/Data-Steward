import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import '../secure_pairing/pairing_crypto.dart';
import '../secure_pairing/pairing_vault.dart';
import '../secure_pairing/pinned_transport.dart';
import '../secure_pairing/strict_json.dart';
import '../shared_session/authenticated_transport.dart';

const proactiveActionCardSchema = 'data-steward.proactive-action-card/v1';
const _maxSuggestionResponseBytes = 128 * 1024;
const _suggestionTimeout = Duration(seconds: 75);

final class ProactiveSuggestionFailure implements Exception {
  const ProactiveSuggestionFailure(this.code);
  final String code;
}

final class ProactiveSuggestionSettings {
  const ProactiveSuggestionSettings({
    required this.enabled,
    required this.disabledCategories,
  });

  final bool enabled;
  final List<String> disabledCategories;
}

final class ProactiveActionCard {
  const ProactiveActionCard({
    required this.suggestionId,
    required this.actionType,
    required this.category,
    required this.title,
    required this.reason,
    required this.request,
    required this.source,
    required this.status,
    required this.createdAt,
    this.actionTarget,
  });

  final String suggestionId;
  final String actionType;
  final String category;
  final String title;
  final String reason;
  final String request;
  final String source;
  final String status;
  final String createdAt;
  final String? actionTarget;
}

final class ProactiveSuggestionObservation {
  const ProactiveSuggestionObservation({
    required this.state,
    required this.messageKey,
    required this.suggestions,
  });

  final String state;
  final String messageKey;
  final List<ProactiveActionCard> suggestions;
}

final class ProactiveSuggestionClient {
  factory ProactiveSuggestionClient.operator({
    required Uri baseUri,
    required String operatorToken,
    http.Client? client,
  }) => ProactiveSuggestionClient._(
    baseUri,
    null,
    operatorToken,
    client ?? http.Client(),
  );

  factory ProactiveSuggestionClient.device({
    required ActiveDeviceCredential credential,
    http.Client? client,
  }) => ProactiveSuggestionClient._(
    credential.baseUrl,
    credential,
    null,
    client ??
        PinnedAuthenticatedHttpClient(
          credential: credential,
          transport: const IoPinFirstTransport(
            timeout: _suggestionTimeout,
            maxResponseBytes: _maxSuggestionResponseBytes,
          ),
        ),
  );

  ProactiveSuggestionClient._(
    this._baseUri,
    this._credential,
    this._operatorToken,
    this._client,
  );

  final Uri _baseUri;
  final ActiveDeviceCredential? _credential;
  final String? _operatorToken;
  final http.Client _client;

  String get _prefix =>
      _credential == null ? '/v1/operator/suggestions' : '/v1/suggestions';

  Future<ProactiveSuggestionSettings> settings() async {
    final response = await _send('GET', '/settings');
    if (response.statusCode != 200) _throwResponse(response);
    return _settings(_object(response.body));
  }

  Future<ProactiveSuggestionSettings> updateSettings({
    required bool enabled,
    required List<String> disabledCategories,
  }) async {
    final response = await _send(
      'PUT',
      '/settings',
      body: jsonEncode({
        'enabled': enabled,
        'disabled_categories': disabledCategories,
      }),
    );
    if (response.statusCode != 200) _throwResponse(response);
    return _settings(_object(response.body));
  }

  Future<List<ProactiveActionCard>> inbox() async {
    final response = await _send('GET', '/inbox');
    if (response.statusCode != 200) _throwResponse(response);
    final value = _object(response.body);
    _exact(value, {'schema_version', 'suggestions'});
    _schema(value);
    return _cards(value['suggestions']);
  }

  Future<ProactiveSuggestionObservation> observe() async {
    if (_credential != null &&
        !_credential.grantedCapabilities.contains('content.analyze')) {
      throw const ProactiveSuggestionFailure('capability_denied');
    }
    final response = await _send('POST', '/observe', body: '{}');
    if (response.statusCode != 200) _throwResponse(response);
    final value = _object(response.body);
    try {
      _exact(value, {'schema_version', 'state', 'message_key', 'suggestions'});
      _schema(value);
      final state = _string(value['state']);
      if (!const {
        'disabled',
        'stabilizing',
        'ready',
        'handled',
        'cooldown',
        'daily_limit',
        'category_paused',
        'unavailable',
      }.contains(state)) {
        throw const FormatException();
      }
      return ProactiveSuggestionObservation(
        state: state,
        messageKey: _string(value['message_key']),
        suggestions: _cards(value['suggestions']),
      );
    } on Object {
      throw const ProactiveSuggestionFailure('protocol_integrity_error');
    }
  }

  Future<ProactiveActionCard> accept(String suggestionId) =>
      _transition(suggestionId, 'accept', accepted: true);

  Future<ProactiveActionCard> dismiss(String suggestionId) =>
      _transition(suggestionId, 'dismiss');

  Future<ProactiveSuggestionSettings> disableCategory(
    String suggestionId,
  ) async {
    _suggestionId(suggestionId);
    final response = await _send(
      'POST',
      '/${Uri.encodeComponent(suggestionId)}/disable-category',
      body: '{}',
    );
    if (response.statusCode != 200) _throwResponse(response);
    return _settings(_object(response.body));
  }

  Future<ProactiveActionCard> _transition(
    String suggestionId,
    String operation, {
    bool accepted = false,
  }) async {
    _suggestionId(suggestionId);
    final response = await _send(
      'POST',
      '/${Uri.encodeComponent(suggestionId)}/$operation',
      body: '{}',
    );
    if (response.statusCode != 200) _throwResponse(response);
    return _card(_object(response.body), accepted: accepted);
  }

  Future<http.Response> _send(
    String method,
    String path, {
    String? body,
  }) async {
    try {
      final request = http.Request(
        method,
        _baseUri.replace(path: '$_prefix$path'),
      )..headers['accept'] = 'application/json';
      final token = _operatorToken;
      if (token != null) {
        request.headers['authorization'] = 'DataSteward-Operator $token';
        request.headers['x-datasteward-protocol'] = pairingProtocolVersion;
      }
      if (body != null) {
        request.headers['content-type'] = 'application/json';
        request.body = body;
      }
      final streamed = await _client.send(request).timeout(_suggestionTimeout);
      final type = streamed.headers['content-type']?.toLowerCase();
      if (type == null || !type.startsWith('application/json')) {
        throw const ProactiveSuggestionFailure('protocol_integrity_error');
      }
      final bytes = <int>[];
      await for (final chunk in streamed.stream) {
        if (bytes.length + chunk.length > _maxSuggestionResponseBytes) {
          throw const ProactiveSuggestionFailure('protocol_integrity_error');
        }
        bytes.addAll(chunk);
      }
      return http.Response.bytes(
        bytes,
        streamed.statusCode,
        headers: streamed.headers,
      );
    } on ProactiveSuggestionFailure {
      rethrow;
    } on Object {
      throw const ProactiveSuggestionFailure('transient_network');
    }
  }

  Map<String, Object?> _object(String source) {
    try {
      return decodeStrictJsonObject(
        source,
        maxUtf8Bytes: _maxSuggestionResponseBytes,
      );
    } on Object {
      throw const ProactiveSuggestionFailure('protocol_integrity_error');
    }
  }

  ProactiveSuggestionSettings _settings(Map<String, Object?> value) {
    try {
      _exact(value, {'schema_version', 'enabled', 'disabled_categories'});
      _schema(value);
      final raw = value['disabled_categories'];
      if (value['enabled'] is! bool ||
          raw is! List ||
          raw.length > 2 ||
          !raw.every(
            (item) => const {'organization', 'knowledge_pack'}.contains(item),
          )) {
        throw const FormatException();
      }
      final disabled = raw.cast<String>().toList(growable: false);
      if (disabled.toSet().length != disabled.length) {
        throw const FormatException();
      }
      return ProactiveSuggestionSettings(
        enabled: value['enabled'] as bool,
        disabledCategories: disabled,
      );
    } on Object {
      throw const ProactiveSuggestionFailure('protocol_integrity_error');
    }
  }

  List<ProactiveActionCard> _cards(Object? raw) {
    if (raw is! List || raw.length > 10) {
      throw const ProactiveSuggestionFailure('protocol_integrity_error');
    }
    return raw.map((item) => _card(_map(item))).toList(growable: false);
  }

  ProactiveActionCard _card(
    Map<String, Object?> value, {
    bool accepted = false,
  }) {
    try {
      final keys = {
        'schema_version',
        'suggestion_id',
        'action_type',
        'category',
        'title',
        'reason',
        'request',
        'source',
        'status',
        'created_at',
        if (accepted) 'action_target',
      };
      _exact(value, keys);
      _schema(value);
      final action = _string(value['action_type']);
      final category = _string(value['category']);
      final status = _string(value['status']);
      if (!const {
            'organize_selected',
            'export_knowledge_pack',
          }.contains(action) ||
          !const {'organization', 'knowledge_pack'}.contains(category) ||
          value['source'] != 'hermes' ||
          !const {'available', 'accepted', 'dismissed'}.contains(status)) {
        throw const FormatException();
      }
      final target = accepted ? _string(value['action_target']) : null;
      if (target != null &&
          !RegExp(
            r'^(?:cl-[0-9a-f]{16}|learning|meeting|project|general)$',
          ).hasMatch(target)) {
        throw const FormatException();
      }
      return ProactiveActionCard(
        suggestionId: _suggestionId(value['suggestion_id']),
        actionType: action,
        category: category,
        title: _safeText(value['title'], 80),
        reason: _safeText(value['reason'], 240),
        request: _safeText(value['request'], 500),
        source: 'hermes',
        status: status,
        createdAt: _string(value['created_at']),
        actionTarget: target,
      );
    } on Object {
      throw const ProactiveSuggestionFailure('protocol_integrity_error');
    }
  }

  Never _throwResponse(http.Response response) {
    final value = _object(response.body);
    final code = value['error_code'];
    final message = value['message_key'];
    if (value.length != 2 ||
        code is! String ||
        message is! String ||
        !{code, 'operator.$code', 'auth.$code'}.contains(message)) {
      throw const ProactiveSuggestionFailure('protocol_integrity_error');
    }
    throw ProactiveSuggestionFailure(code);
  }

  void close() => _client.close();
}

Map<String, Object?> _map(Object? value) {
  if (value is! Map<String, Object?>) throw const FormatException();
  return value;
}

void _exact(Map<String, Object?> value, Set<String> keys) {
  if (value.keys.toSet().difference(keys).isNotEmpty ||
      keys.difference(value.keys.toSet()).isNotEmpty) {
    throw const FormatException();
  }
}

void _schema(Map<String, Object?> value) {
  if (value['schema_version'] != proactiveActionCardSchema) {
    throw const FormatException();
  }
}

String _string(Object? value) {
  if (value is! String || value.isEmpty) throw const FormatException();
  return value;
}

String _safeText(Object? value, int maxLength) {
  final result = _string(value);
  if (result.length > maxLength ||
      result.runes.any((rune) => rune < 0x20 || rune == 0x7f) ||
      result.toLowerCase().contains('content://') ||
      RegExp(r'(?:[A-Za-z]:\\|\\\\|/Users/|/home/)').hasMatch(result)) {
    throw const FormatException();
  }
  return result;
}

String _suggestionId(Object? value) {
  final result = _string(value);
  if (!RegExp(r'^ps-[0-9a-f]{20}$').hasMatch(result)) {
    throw const FormatException();
  }
  return result;
}

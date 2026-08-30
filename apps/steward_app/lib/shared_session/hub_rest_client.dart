import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';

import 'protocol_codec.dart';
import 'protocol_models.dart';
import 'shared_session_errors.dart';

const _stableErrors = <String>{
  'validation_error',
  'conversation_not_found',
  'conversation_already_exists',
  'idempotency_conflict',
  'cursor_ahead',
  'persistence_unavailable',
  'auth_invalid',
  'auth_revoked',
  'auth_unavailable',
  'capability_denied',
  'capability_epoch_stale',
  'protocol_version_rejected',
  'action_not_found',
  'action_not_supported',
  'action_persistence_failed',
  'action_service_closed',
  'action_unavailable',
};
const _errorStatuses = <String, Set<int>>{
  'validation_error': <int>{400, 422},
  'conversation_not_found': <int>{404},
  'conversation_already_exists': <int>{409},
  'idempotency_conflict': <int>{409},
  'cursor_ahead': <int>{409},
  'persistence_unavailable': <int>{503},
  'auth_invalid': <int>{401},
  'auth_revoked': <int>{401},
  'auth_unavailable': <int>{503},
  'capability_denied': <int>{403},
  'capability_epoch_stale': <int>{409},
  'protocol_version_rejected': <int>{400},
  'action_not_found': <int>{404},
  'action_not_supported': <int>{409},
  'action_persistence_failed': <int>{503},
  'action_service_closed': <int>{503},
  'action_unavailable': <int>{409},
};
final _utcTimestamp = RegExp(
  r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$',
);

Uri validateLoopbackBaseUri(
  Uri uri, {
  required String scheme,
  bool allowPathAndQuery = false,
}) {
  if (uri.scheme != scheme ||
      uri.host != '127.0.0.1' ||
      !uri.hasPort ||
      uri.userInfo.isNotEmpty ||
      uri.fragment.isNotEmpty ||
      (!allowPathAndQuery &&
          (uri.query.isNotEmpty || (uri.path.isNotEmpty && uri.path != '/')))) {
    throw const NetworkBoundaryException();
  }
  if (allowPathAndQuery) return uri;
  return uri.replace(path: '', query: null, fragment: null);
}

Uri validateAuthenticatedPrivateBaseUri(Uri uri, {required String scheme}) {
  final parts = uri.host.split('.').map(int.tryParse).toList();
  final privateIpv4 =
      parts.length == 4 &&
      parts.every((value) => value != null && value >= 0 && value <= 255) &&
      (parts[0] == 10 ||
          (parts[0] == 172 && parts[1]! >= 16 && parts[1]! <= 31) ||
          (parts[0] == 192 && parts[1] == 168));
  if (uri.scheme != scheme ||
      !privateIpv4 ||
      !uri.hasPort ||
      uri.userInfo.isNotEmpty ||
      uri.path.isNotEmpty && uri.path != '/' ||
      uri.query.isNotEmpty ||
      uri.fragment.isNotEmpty) {
    throw const NetworkBoundaryException();
  }
  return uri.replace(path: '', query: null, fragment: null);
}

http.Client createDirectHttpClient() {
  final ioClient = HttpClient()..findProxy = (_) => 'DIRECT';
  return IOClient(ioClient);
}

final class HubRestClient {
  HubRestClient({
    required Uri baseUri,
    http.Client? client,
    this.authenticatedPrivateLan = false,
    this.expectedTransportScope = 'loopback_only',
    this.timeout = const Duration(seconds: 5),
    this.maxRequestBytes = 256 * 1024,
    this.maxResponseBytes = 1024 * 1024,
  }) : baseUri = authenticatedPrivateLan
           ? validateAuthenticatedPrivateBaseUri(baseUri, scheme: 'https')
           : validateLoopbackBaseUri(baseUri, scheme: 'http'),
       _client = client ?? createDirectHttpClient();

  final Uri baseUri;
  final Duration timeout;
  final bool authenticatedPrivateLan;
  final String expectedTransportScope;
  final int maxRequestBytes;
  final int maxResponseBytes;
  final http.Client _client;
  bool _closed = false;

  Future<HealthStatus> health() async {
    final response = await _send('GET', '/health');
    _expectStatus(response, const <int>{200});
    final body = decodeJsonObject(response.body);
    _requireExactKeys(body, const <String>{
      'status',
      'protocol_version',
      'database_ready',
      'transport_scope',
    });
    if (body['status'] != 'ok' ||
        body['protocol_version'] != 1 ||
        body['database_ready'] is! bool ||
        body['transport_scope'] != expectedTransportScope) {
      throw const ProtocolIntegrityException();
    }
    return HealthStatus(
      protocolVersion: body['protocol_version']! as int,
      databaseReady: body['database_ready']! as bool,
    );
  }

  Future<DeviceAuthorizationSnapshot> deviceSelf() async {
    final response = await _send('GET', '/v1/device/self');
    _expectStatus(response, const <int>{200});
    final body = decodeJsonObject(response.body);
    _requireExactKeys(body, const <String>{
      'protocol_version',
      'hub_id',
      'device_id',
      'status',
      'capability_epoch',
      'granted_capabilities',
      'display_name',
      'platform',
    });
    final hubId = body['hub_id'];
    final deviceId = body['device_id'];
    final epoch = body['capability_epoch'];
    final rawCapabilities = body['granted_capabilities'];
    final displayName = body['display_name'];
    final platform = body['platform'];
    if (body['protocol_version'] != 'pairing_auth/1' ||
        body['status'] != 'ACTIVE' ||
        hubId is! String ||
        deviceId is! String ||
        epoch is! int ||
        epoch < 1 ||
        rawCapabilities is! List ||
        rawCapabilities.any((value) => value is! String) ||
        (displayName != null && displayName is! String) ||
        platform is! String ||
        platform.isEmpty) {
      throw const ProtocolIntegrityException();
    }
    final capabilities = rawCapabilities.cast<String>();
    if (capabilities.toSet().length != capabilities.length ||
        capabilities.join('\n') !=
            (List<String>.of(capabilities)..sort()).join('\n')) {
      throw const ProtocolIntegrityException();
    }
    return DeviceAuthorizationSnapshot(
      hubId: hubId,
      deviceId: deviceId,
      capabilityEpoch: epoch,
      grantedCapabilities: List<String>.unmodifiable(capabilities),
      displayName: displayName as String?,
      platform: platform,
    );
  }

  Future<ConversationCreation> createConversation({
    required String title,
    String? conversationId,
    bool continueIfAlreadyExists = false,
  }) async {
    final body = <String, Object>{'title': title};
    if (conversationId != null) {
      body['conversation_id'] = conversationId;
    }
    final response = await _send('POST', '/v1/conversations', body: body);
    if (response.statusCode == 201) {
      final value = decodeJsonObject(response.body);
      _requireExactKeys(value, const <String>{
        'conversation_id',
        'title',
        'next_seq',
        'created_at',
        'updated_at',
      });
      final id = value['conversation_id'];
      final responseTitle = value['title'];
      final nextSeq = value['next_seq'];
      if (id is! String ||
          id.isEmpty ||
          (conversationId != null && id != conversationId) ||
          responseTitle is! String ||
          responseTitle != title ||
          nextSeq is! int ||
          nextSeq < 1) {
        throw const ProtocolIntegrityException();
      }
      _parseUtcTimestamp(value['created_at']);
      _parseUtcTimestamp(value['updated_at']);
      return ConversationCreation(conversationId: id, alreadyExisted: false);
    }
    final error = _apiError(response);
    if (continueIfAlreadyExists &&
        error.code == 'conversation_already_exists' &&
        conversationId != null) {
      return ConversationCreation(
        conversationId: conversationId,
        alreadyExisted: true,
      );
    }
    throw error;
  }

  Future<AppendMessageResult> appendMessage({
    required String conversationId,
    required String clientMessageId,
    required String actorDeviceId,
    required String role,
    required String content,
    String? causationId,
    String? correlationId,
  }) async {
    final body = <String, Object>{
      'client_message_id': clientMessageId,
      'actor_device_id': actorDeviceId,
      'role': role,
      'content': content,
    };
    if (causationId != null) body['causation_id'] = causationId;
    if (correlationId != null) body['correlation_id'] = correlationId;
    final response = await _send(
      'POST',
      '/v1/conversations/${Uri.encodeComponent(conversationId)}/messages',
      body: body,
    );
    _expectStatus(response, const <int>{200, 201});
    final value = decodeJsonObject(response.body);
    _requireExactKeys(value, const <String>{
      'message_id',
      'deduplicated',
      'event',
    });
    final messageId = value['message_id'];
    final deduplicated = value['deduplicated'];
    if (messageId is! String ||
        messageId.isEmpty ||
        deduplicated is! bool ||
        (response.statusCode == 200 && !deduplicated) ||
        (response.statusCode == 201 && deduplicated)) {
      throw const ProtocolIntegrityException();
    }
    final event = decodeWireEvent(
      value['event'],
      expectedConversationId: conversationId,
    );
    if (event.payload.messageId != messageId) {
      throw const ProtocolIntegrityException();
    }
    return AppendMessageResult(deduplicated: deduplicated, event: event);
  }

  Future<ReplayPage> replayEvents({
    required String conversationId,
    required int afterSeq,
    int limit = 100,
  }) async {
    if (afterSeq < 0 || limit < 1 || limit > 500) {
      throw const ProtocolIntegrityException();
    }
    final response = await _send(
      'GET',
      '/v1/conversations/${Uri.encodeComponent(conversationId)}/events',
      query: <String, String>{'after_seq': '$afterSeq', 'limit': '$limit'},
    );
    _expectStatus(response, const <int>{200});
    final value = decodeJsonObject(response.body);
    _requireExactKeys(value, const <String>{'events', 'last_conversation_seq'});
    final rawEvents = value['events'];
    final last = value['last_conversation_seq'];
    if (rawEvents is! List || last is! int || last < 0) {
      throw const ProtocolIntegrityException();
    }
    final events = <WireEvent>[];
    var expectedSequence = afterSeq + 1;
    for (final rawEvent in rawEvents) {
      final event = decodeWireEvent(
        rawEvent,
        expectedConversationId: conversationId,
      );
      if (event.conversationSeq != expectedSequence) {
        throw const ProtocolIntegrityException();
      }
      events.add(event);
      expectedSequence += 1;
    }
    final expectedLast = events.isEmpty
        ? afterSeq
        : events.last.conversationSeq;
    if (last != expectedLast || events.length > limit) {
      throw const ProtocolIntegrityException();
    }
    return ReplayPage(events: events, lastConversationSeq: last);
  }

  Future<List<ProductAction>> listProductActions({
    required String conversationId,
    required String assistantMessageId,
  }) async {
    final response = await _send(
      'GET',
      '/v1/conversations/${Uri.encodeComponent(conversationId)}'
          '/messages/${Uri.encodeComponent(assistantMessageId)}/actions',
    );
    _expectStatus(response, const <int>{200});
    final value = decodeJsonObject(response.body);
    _requireExactKeys(value, const <String>{'actions'});
    final rows = value['actions'];
    if (rows is! List || rows.length > 8) {
      throw const ProtocolIntegrityException();
    }
    return List<ProductAction>.unmodifiable(
      rows.map((row) => _decodeProductAction(row, assistantMessageId)),
    );
  }

  Future<ProductActionExecution> executeProductAction({
    required String conversationId,
    required String assistantMessageId,
    required String actionId,
  }) async {
    final response = await _send(
      'POST',
      '/v1/conversations/${Uri.encodeComponent(conversationId)}'
          '/messages/${Uri.encodeComponent(assistantMessageId)}'
          '/actions/${Uri.encodeComponent(actionId)}',
    );
    _expectStatus(response, const <int>{200});
    final value = decodeJsonObject(response.body);
    _requireExactKeys(value, const <String>{'status', 'event', 'actions'});
    if (value['status'] != 'completed' || value['actions'] is! List) {
      throw const ProtocolIntegrityException();
    }
    final event = decodeWireEvent(
      value['event'],
      expectedConversationId: conversationId,
    );
    final actions = (value['actions']! as List)
        .map((row) => _decodeProductAction(row, event.payload.messageId))
        .toList(growable: false);
    if (actions.length > 8) throw const ProtocolIntegrityException();
    return ProductActionExecution(event: event, actions: actions);
  }

  Future<MemoryCenterSnapshot> memoryCenter({
    required String conversationId,
  }) async {
    final response = await _send(
      'GET',
      '/v1/conversations/${Uri.encodeComponent(conversationId)}/memory',
    );
    _expectStatus(response, const <int>{200});
    final value = decodeJsonObject(response.body);
    _requireExactKeys(value, const <String>{
      'status',
      'support_count',
      'activation_threshold',
      'version',
      'actions',
    });
    final status = value['status'];
    final support = value['support_count'];
    final threshold = value['activation_threshold'];
    final version = value['version'];
    final rows = value['actions'];
    if (status is! String ||
        !const {
          'none',
          'learning',
          'candidate',
          'active',
          'forgotten',
        }.contains(status) ||
        support is! int ||
        support < 0 ||
        threshold is! int ||
        threshold < 1 ||
        (version != null && (version is! int || version < 1)) ||
        rows is! List ||
        rows.length > 2) {
      throw const ProtocolIntegrityException();
    }
    final actions = rows
        .map((row) {
          if (row is! Map<String, dynamic>) {
            throw const ProtocolIntegrityException();
          }
          final messageId = row['assistant_message_id'];
          if (messageId is! String) throw const ProtocolIntegrityException();
          return _decodeProductAction(row, messageId);
        })
        .toList(growable: false);
    return MemoryCenterSnapshot(
      status: status,
      supportCount: support,
      activationThreshold: threshold,
      version: version as int?,
      actions: actions,
    );
  }

  void close() {
    if (_closed) return;
    _closed = true;
    _client.close();
  }

  Future<_JsonResponse> _send(
    String method,
    String path, {
    Map<String, Object>? body,
    Map<String, String>? query,
  }) async {
    if (_closed) throw const TransportException();
    try {
      return await _performSend(
        method,
        path,
        body: body,
        query: query,
      ).timeout(timeout);
    } on SharedSessionException {
      rethrow;
    } on TimeoutException {
      _closed = true;
      _client.close();
      throw const TransportException();
    } on Object {
      throw const TransportException();
    }
  }

  Future<_JsonResponse> _performSend(
    String method,
    String path, {
    Map<String, Object>? body,
    Map<String, String>? query,
  }) async {
    try {
      final uri = baseUri.replace(path: path, queryParameters: query);
      final request = http.Request(method, uri)
        ..headers['accept'] = 'application/json';
      if (body != null) {
        request.headers['content-type'] = 'application/json; charset=utf-8';
        final requestBytes = utf8.encode(jsonEncode(body));
        if (requestBytes.length > maxRequestBytes) {
          throw const ProtocolIntegrityException();
        }
        request.bodyBytes = requestBytes;
      }
      final streamed = await _client.send(request);
      final contentType = streamed.headers['content-type']?.toLowerCase();
      if (contentType == null || !contentType.startsWith('application/json')) {
        throw const ProtocolIntegrityException();
      }
      final contentLength = streamed.contentLength;
      if (contentLength != null && contentLength > maxResponseBytes) {
        throw const ProtocolIntegrityException();
      }
      final bytes = <int>[];
      await for (final chunk in streamed.stream) {
        if (bytes.length + chunk.length > maxResponseBytes) {
          throw const ProtocolIntegrityException();
        }
        bytes.addAll(chunk);
      }
      return _JsonResponse(
        streamed.statusCode,
        utf8.decode(bytes, allowMalformed: false),
      );
    } on SharedSessionException {
      rethrow;
    } on FormatException {
      throw const ProtocolIntegrityException();
    } on Object {
      throw const TransportException();
    }
  }

  void _expectStatus(_JsonResponse response, Set<int> allowed) {
    if (!allowed.contains(response.statusCode)) {
      throw _apiError(response);
    }
  }

  HubApiException _apiError(_JsonResponse response) {
    try {
      final value = decodeJsonObject(response.body);
      if (value.keys.toSet().containsAll(const {'error_code', 'message_key'}) &&
          value.length == 2) {
        final code = value['error_code'];
        if (code is! String ||
            !_stableErrors.contains(code) ||
            value['message_key'] != 'auth.$code' ||
            !_errorStatuses[code]!.contains(response.statusCode)) {
          throw const ProtocolIntegrityException();
        }
        return HubApiException(statusCode: response.statusCode, code: code);
      }
      _requireExactKeys(value, const <String>{'error'});
      final error = value['error'];
      if (error is! Map<String, dynamic>) {
        throw const ProtocolIntegrityException();
      }
      final code = error['code'];
      if (code is! String || !_stableErrors.contains(code)) {
        throw const ProtocolIntegrityException();
      }
      final expectsWatermark = code == 'cursor_ahead';
      _requireExactKeys(
        error,
        expectsWatermark
            ? const <String>{'code', 'message', 'server_last_conversation_seq'}
            : const <String>{'code', 'message'},
      );
      final message = error['message'];
      final watermark = error['server_last_conversation_seq'];
      if (message is! String ||
          message.isEmpty ||
          !_errorStatuses[code]!.contains(response.statusCode) ||
          (expectsWatermark && (watermark is! int || watermark < 0)) ||
          (!expectsWatermark && watermark != null)) {
        throw const ProtocolIntegrityException();
      }
      return HubApiException(
        statusCode: response.statusCode,
        code: code,
        serverLastConversationSeq: watermark as int?,
      );
    } on HubApiException {
      rethrow;
    } on SharedSessionException {
      rethrow;
    } on Object {
      throw const ProtocolIntegrityException();
    }
  }
}

ProductAction _decodeProductAction(Object? raw, String expectedMessageId) {
  if (raw is! Map<String, dynamic>) {
    throw const ProtocolIntegrityException();
  }
  _requireExactKeys(raw, const <String>{
    'action_id',
    'assistant_message_id',
    'kind',
    'label',
    'description',
    'risk',
    'requires_confirmation',
    'required_capability',
    'status',
  });
  final actionId = raw['action_id'];
  final messageId = raw['assistant_message_id'];
  final kind = raw['kind'];
  final label = raw['label'];
  final description = raw['description'];
  final risk = raw['risk'];
  final confirmation = raw['requires_confirmation'];
  final capability = raw['required_capability'];
  final status = raw['status'];
  if (actionId is! String ||
      !RegExp(r'^act-[0-9a-f]{16}$').hasMatch(actionId) ||
      messageId != expectedMessageId ||
      kind is! String ||
      !const {
        'archive_accept',
        'archive_reject',
        'memory_approve',
        'memory_forget',
        'organize_execute',
        'organize_undo',
      }.contains(kind) ||
      label is! String ||
      label.isEmpty ||
      label.length > 32 ||
      description is! String ||
      description.isEmpty ||
      description.length > 120 ||
      risk is! String ||
      !const {'none', 'preference', 'memory', 'file_move'}.contains(risk) ||
      confirmation is! bool ||
      !const {'session.sync', 'files.organize'}.contains(capability) ||
      !const {'available', 'completed'}.contains(status)) {
    throw const ProtocolIntegrityException();
  }
  return ProductAction(
    actionId: actionId,
    assistantMessageId: messageId as String,
    kind: kind,
    label: label,
    description: description,
    risk: risk,
    requiresConfirmation: confirmation,
    requiredCapability: capability as String,
    status: status as String,
  );
}

void _requireExactKeys(Map<String, Object?> value, Set<String> expected) {
  final actual = value.keys.toSet();
  if (actual.length != expected.length || !actual.containsAll(expected)) {
    throw const ProtocolIntegrityException();
  }
}

DateTime _parseUtcTimestamp(Object? value) {
  if (value is! String || !_utcTimestamp.hasMatch(value)) {
    throw const ProtocolIntegrityException();
  }
  final parsed = DateTime.tryParse(value);
  if (parsed == null || !parsed.isUtc) {
    throw const ProtocolIntegrityException();
  }
  return parsed;
}

final class _JsonResponse {
  const _JsonResponse(this.statusCode, this.body);

  final int statusCode;
  final String body;
}

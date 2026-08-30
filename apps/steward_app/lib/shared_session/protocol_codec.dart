import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'protocol_models.dart';
import 'shared_session_errors.dart';

const _roles = <String>{'user', 'assistant', 'system', 'tool'};
final _lowerHex64 = RegExp(r'^[0-9a-f]{64}$');
final _utcTimestamp = RegExp(
  r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$',
);

Map<String, Object?> decodeJsonObject(String source) {
  try {
    final value = jsonDecode(source);
    if (value is! Map<String, dynamic>) {
      throw const ProtocolIntegrityException();
    }
    return value;
  } on SharedSessionException {
    rethrow;
  } on Object {
    throw const ProtocolIntegrityException();
  }
}

WireEvent decodeWireEvent(
  Object? source, {
  required String expectedConversationId,
}) {
  try {
    final map = _objectMap(source);
    _requireKeys(map, const <String>{
      'event_id',
      'protocol_version',
      'event_type',
      'conversation_id',
      'conversation_seq',
      'actor_device_id',
      'causation_id',
      'correlation_id',
      'occurred_at',
      'payload',
      'payload_sha256',
    });
    final protocolVersion = _integer(map['protocol_version']);
    final eventType = _nonEmptyString(map['event_type']);
    final conversationId = _nonEmptyString(map['conversation_id']);
    final conversationSeq = _positiveInteger(map['conversation_seq']);
    final occurredAtText = _nonEmptyString(map['occurred_at']);
    if (protocolVersion != 1 ||
        eventType != 'conversation.message.accepted' ||
        conversationId != expectedConversationId ||
        !_utcTimestamp.hasMatch(occurredAtText)) {
      throw const ProtocolIntegrityException();
    }
    final occurredAt = DateTime.tryParse(occurredAtText);
    if (occurredAt == null || !occurredAt.isUtc) {
      throw const ProtocolIntegrityException();
    }

    final payloadMap = _objectMap(map['payload']);
    _requireKeys(payloadMap, const <String>{
      'accepted_seq',
      'client_message_id',
      'message_id',
      'role',
      'content',
    });
    final payload = WirePayload(
      acceptedSeq: _positiveInteger(payloadMap['accepted_seq']),
      clientMessageId: _nonEmptyString(payloadMap['client_message_id']),
      messageId: _nonEmptyString(payloadMap['message_id']),
      role: _nonEmptyString(payloadMap['role']),
      content: _string(payloadMap['content']),
    );
    if (payload.acceptedSeq != conversationSeq ||
        !_roles.contains(payload.role)) {
      throw const ProtocolIntegrityException();
    }

    final payloadSha256 = _nonEmptyString(map['payload_sha256']);
    if (!_lowerHex64.hasMatch(payloadSha256)) {
      throw const ProtocolIntegrityException();
    }
    final stablePayload = jsonEncode(payload.stableJson());
    final computed = sha256.convert(utf8.encode(stablePayload)).toString();
    if (computed != payloadSha256) {
      throw const ProtocolIntegrityException();
    }

    return WireEvent(
      eventId: _nonEmptyString(map['event_id']),
      protocolVersion: protocolVersion,
      eventType: eventType,
      conversationId: conversationId,
      conversationSeq: conversationSeq,
      actorDeviceId: _nonEmptyString(map['actor_device_id']),
      causationId: _nonEmptyString(map['causation_id']),
      correlationId: _nonEmptyString(map['correlation_id']),
      occurredAt: occurredAt,
      payload: payload,
      payloadSha256: payloadSha256,
    );
  } on SharedSessionException {
    rethrow;
  } on Object {
    throw const ProtocolIntegrityException();
  }
}

Object decodeWebSocketFrame(
  String source, {
  required String expectedConversationId,
}) {
  final map = decodeJsonObject(source);
  final kind = _nonEmptyString(map['kind']);
  if (kind == 'event') {
    _requireKeys(map, const <String>{'kind', 'delivery', 'event'});
    final delivery = _nonEmptyString(map['delivery']);
    if (delivery != 'replay' && delivery != 'live') {
      throw const ProtocolIntegrityException();
    }
    return EventFrame(
      delivery: delivery,
      event: decodeWireEvent(
        map['event'],
        expectedConversationId: expectedConversationId,
      ),
    );
  }
  if (kind == 'ready') {
    _requireKeys(map, const <String>{'kind', 'last_conversation_seq'});
    return ReadyFrame(_nonNegativeInteger(map['last_conversation_seq']));
  }
  if (kind == 'error') {
    _requireKeys(map, const <String>{'kind', 'error'});
    final error = _objectMap(map['error']);
    final code = _nonEmptyString(error['code']);
    if (code != 'cursor_ahead') {
      throw const ProtocolIntegrityException();
    }
    _requireKeys(error, const <String>{
      'code',
      'message',
      'server_last_conversation_seq',
    });
    _nonEmptyString(error['message']);
    return ErrorFrame(
      code: code,
      serverLastConversationSeq: _nonNegativeInteger(
        error['server_last_conversation_seq'],
      ),
    );
  }
  throw const ProtocolIntegrityException();
}

Map<String, Object?> _objectMap(Object? value) {
  if (value is! Map<String, dynamic>) {
    throw const ProtocolIntegrityException();
  }
  return value;
}

void _requireKeys(Map<String, Object?> value, Set<String> expected) {
  if (value.keys.toSet().length != expected.length ||
      !value.keys.toSet().containsAll(expected)) {
    throw const ProtocolIntegrityException();
  }
}

String _string(Object? value) {
  if (value is! String) {
    throw const ProtocolIntegrityException();
  }
  return value;
}

String _nonEmptyString(Object? value) {
  final text = _string(value);
  if (text.isEmpty) {
    throw const ProtocolIntegrityException();
  }
  return text;
}

int _integer(Object? value) {
  if (value is! int) {
    throw const ProtocolIntegrityException();
  }
  return value;
}

int _positiveInteger(Object? value) {
  final number = _integer(value);
  if (number < 1) {
    throw const ProtocolIntegrityException();
  }
  return number;
}

int _nonNegativeInteger(Object? value) {
  final number = _integer(value);
  if (number < 0) {
    throw const ProtocolIntegrityException();
  }
  return number;
}

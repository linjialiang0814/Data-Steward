import 'dart:async';
import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:steward_app/shared_session/hub_websocket_client.dart';

Map<String, Object> wireEventMap({
  int sequence = 1,
  String eventId = 'event-1',
  String conversationId = 'conversation-1',
  String actor = 'windows',
  String role = 'user',
  String content = 'message-1',
  String? clientMessageId,
  int? acceptedSeq,
  int protocolVersion = 1,
  String eventType = 'conversation.message.accepted',
  String occurredAt = '2026-07-28T00:00:00.000Z',
  String? payloadHash,
}) {
  final acceptedClientMessageId = clientMessageId ?? 'client-$sequence';
  final payload = <String, Object>{
    'accepted_seq': acceptedSeq ?? sequence,
    'client_message_id': acceptedClientMessageId,
    'content': content,
    'message_id': 'message-$sequence',
    'role': role,
  };
  final hash =
      payloadHash ??
      sha256.convert(utf8.encode(jsonEncode(payload))).toString();
  return <String, Object>{
    'event_id': eventId,
    'protocol_version': protocolVersion,
    'event_type': eventType,
    'conversation_id': conversationId,
    'conversation_seq': sequence,
    'actor_device_id': actor,
    'causation_id': acceptedClientMessageId,
    'correlation_id': conversationId,
    'occurred_at': occurredAt,
    'payload': payload,
    'payload_sha256': hash,
  };
}

String eventFrameJson({
  int sequence = 1,
  String delivery = 'replay',
  String conversationId = 'conversation-1',
}) => jsonEncode(<String, Object>{
  'kind': 'event',
  'delivery': delivery,
  'event': wireEventMap(
    sequence: sequence,
    eventId: 'event-$sequence',
    conversationId: conversationId,
    content: 'message-$sequence',
  ),
});

final class FakeHubSocket implements HubSocket {
  final StreamController<Object?> controller =
      StreamController<Object?>.broadcast();
  bool closed = false;
  int? sentCloseCode;
  int closeCount = 0;

  @override
  int? closeCode;

  @override
  Stream<Object?> get frames => controller.stream;

  void add(Object? frame) => controller.add(frame);

  void addError(Object error) => controller.addError(error);

  Future<void> serverClose(int code) async {
    closeCode = code;
    await controller.close();
  }

  @override
  Future<void> close([int? code, String? reason]) async {
    closeCount += 1;
    if (closed) return;
    closed = true;
    sentCloseCode = code;
    closeCode = code;
    if (!controller.isClosed) {
      await controller.close();
    }
  }
}

import 'dart:convert';

import 'package:crypto/crypto.dart';

final class WirePayload {
  const WirePayload({
    required this.acceptedSeq,
    required this.clientMessageId,
    required this.messageId,
    required this.role,
    required this.content,
  });

  final int acceptedSeq;
  final String clientMessageId;
  final String messageId;
  final String role;
  final String content;

  Map<String, Object> stableJson() => <String, Object>{
    'accepted_seq': acceptedSeq,
    'client_message_id': clientMessageId,
    'content': content,
    'message_id': messageId,
    'role': role,
  };
}

final class WireEvent {
  const WireEvent({
    required this.eventId,
    required this.protocolVersion,
    required this.eventType,
    required this.conversationId,
    required this.conversationSeq,
    required this.actorDeviceId,
    required this.causationId,
    required this.correlationId,
    required this.occurredAt,
    required this.payload,
    required this.payloadSha256,
  });

  final String eventId;
  final int protocolVersion;
  final String eventType;
  final String conversationId;
  final int conversationSeq;
  final String actorDeviceId;
  final String causationId;
  final String correlationId;
  final DateTime occurredAt;
  final WirePayload payload;
  final String payloadSha256;

  String get fullFingerprint {
    final value = <String, Object>{
      'actor_device_id': actorDeviceId,
      'causation_id': causationId,
      'conversation_id': conversationId,
      'conversation_seq': conversationSeq,
      'correlation_id': correlationId,
      'event_id': eventId,
      'event_type': eventType,
      'occurred_at': occurredAt.toUtc().toIso8601String(),
      'payload': payload.stableJson(),
      'payload_sha256': payloadSha256,
      'protocol_version': protocolVersion,
    };
    return sha256.convert(utf8.encode(jsonEncode(value))).toString();
  }

  Map<String, Object> semanticJson() => <String, Object>{
    'actor_device_id': actorDeviceId,
    'causation_id': causationId,
    'conversation_seq': conversationSeq,
    'correlation_id': correlationId,
    'event_type': eventType,
    'payload': <String, Object>{
      'accepted_seq': payload.acceptedSeq,
      'client_message_id': payload.clientMessageId,
      'content': payload.content,
      'role': payload.role,
    },
    'protocol_version': protocolVersion,
  };
}

final class EventFrame {
  const EventFrame({required this.delivery, required this.event});

  final String delivery;
  final WireEvent event;
}

final class ReadyFrame {
  const ReadyFrame(this.lastConversationSeq);

  final int lastConversationSeq;
}

final class ErrorFrame {
  const ErrorFrame({
    required this.code,
    required this.serverLastConversationSeq,
  });

  final String code;
  final int? serverLastConversationSeq;
}

final class HealthStatus {
  const HealthStatus({
    required this.protocolVersion,
    required this.databaseReady,
  });

  final int protocolVersion;
  final bool databaseReady;
}

final class DeviceAuthorizationSnapshot {
  const DeviceAuthorizationSnapshot({
    required this.hubId,
    required this.deviceId,
    required this.capabilityEpoch,
    required this.grantedCapabilities,
    required this.displayName,
    required this.platform,
  });

  final String hubId;
  final String deviceId;
  final int capabilityEpoch;
  final List<String> grantedCapabilities;
  final String? displayName;
  final String platform;
}

final class ConversationCreation {
  const ConversationCreation({
    required this.conversationId,
    required this.alreadyExisted,
  });

  final String conversationId;
  final bool alreadyExisted;
}

final class AppendMessageResult {
  const AppendMessageResult({required this.deduplicated, required this.event});

  final bool deduplicated;
  final WireEvent event;
}

final class ProductAction {
  const ProductAction({
    required this.actionId,
    required this.assistantMessageId,
    required this.kind,
    required this.label,
    required this.description,
    required this.risk,
    required this.requiresConfirmation,
    required this.requiredCapability,
    required this.status,
  });

  final String actionId;
  final String assistantMessageId;
  final String kind;
  final String label;
  final String description;
  final String risk;
  final bool requiresConfirmation;
  final String requiredCapability;
  final String status;
}

final class ProductActionExecution {
  const ProductActionExecution({required this.event, required this.actions});

  final WireEvent event;
  final List<ProductAction> actions;
}

final class MemoryCenterSnapshot {
  const MemoryCenterSnapshot({
    required this.status,
    required this.supportCount,
    required this.activationThreshold,
    required this.version,
    required this.actions,
  });

  final String status;
  final int supportCount;
  final int activationThreshold;
  final int? version;
  final List<ProductAction> actions;
}

final class ReplayPage {
  const ReplayPage({required this.events, required this.lastConversationSeq});

  final List<WireEvent> events;
  final int lastConversationSeq;
}

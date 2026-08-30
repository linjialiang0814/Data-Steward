import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'protocol_models.dart';
import 'shared_session_errors.dart';

abstract interface class CursorStore {
  Future<int> read(String conversationId);

  Future<void> write(String conversationId, int conversationSeq);
}

abstract interface class ResettableCursorStore implements CursorStore {
  Future<void> reset(String conversationId);
}

final class MemoryCursorStore implements ResettableCursorStore {
  final Map<String, int> _values = <String, int>{};

  @override
  Future<int> read(String conversationId) async => _values[conversationId] ?? 0;

  @override
  Future<void> write(String conversationId, int conversationSeq) async {
    _values[conversationId] = conversationSeq;
  }

  @override
  Future<void> reset(String conversationId) async {
    _values.remove(conversationId);
  }
}

final class SessionProjection {
  SessionProjection({
    required this.conversationId,
    int initialConversationSeq = 0,
  }) : _lastConversationSeq = initialConversationSeq;

  final String conversationId;
  int _lastConversationSeq;
  final List<WireEvent> _events = <WireEvent>[];
  final Map<String, String> _eventFingerprints = <String, String>{};

  int get lastConversationSeq => _lastConversationSeq;
  List<WireEvent> get events => List<WireEvent>.unmodifiable(_events);

  bool apply(WireEvent event) {
    if (event.conversationId != conversationId) {
      throw const ProjectionException('conversation_mismatch');
    }
    final knownFingerprint = _eventFingerprints[event.eventId];
    if (knownFingerprint != null) {
      if (knownFingerprint != event.fullFingerprint) {
        throw const ProjectionException('event_integrity_conflict');
      }
      return false;
    }
    if (event.conversationSeq <= _lastConversationSeq) {
      throw const ProjectionException('stale_or_conflicting_event');
    }
    if (event.conversationSeq != _lastConversationSeq + 1) {
      throw const ProjectionException('sequence_gap');
    }

    _events.add(event);
    _eventFingerprints[event.eventId] = event.fullFingerprint;
    _lastConversationSeq = event.conversationSeq;
    return true;
  }

  String get semanticProjectionHash {
    final encoded = jsonEncode(
      _events.map((event) => event.semanticJson()).toList(growable: false),
    );
    return sha256.convert(utf8.encode(encoded)).toString();
  }
}

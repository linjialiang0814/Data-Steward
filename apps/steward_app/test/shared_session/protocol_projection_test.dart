import 'package:flutter_test/flutter_test.dart';
import 'package:steward_app/shared_session/protocol_codec.dart';
import 'package:steward_app/shared_session/session_projection.dart';
import 'package:steward_app/shared_session/shared_session_errors.dart';

import 'test_helpers.dart';

void main() {
  group('wire event validation', () {
    test('accepts a valid event and matching payload hash', () {
      final event = decodeWireEvent(
        wireEventMap(),
        expectedConversationId: 'conversation-1',
      );

      expect(event.conversationSeq, 1);
      expect(event.payload.acceptedSeq, 1);
      expect(event.payloadSha256, hasLength(64));
    });

    test('rejects a changed payload hash', () {
      expect(
        () => decodeWireEvent(
          wireEventMap(payloadHash: '0' * 64),
          expectedConversationId: 'conversation-1',
        ),
        throwsA(isA<ProtocolIntegrityException>()),
      );
    });

    test('rejects accepted sequence mismatch', () {
      expect(
        () => decodeWireEvent(
          wireEventMap(acceptedSeq: 2),
          expectedConversationId: 'conversation-1',
        ),
        throwsA(isA<ProtocolIntegrityException>()),
      );
    });

    test('rejects unsupported protocol version', () {
      expect(
        () => decodeWireEvent(
          wireEventMap(protocolVersion: 2),
          expectedConversationId: 'conversation-1',
        ),
        throwsA(isA<ProtocolIntegrityException>()),
      );
    });

    test('rejects a different conversation', () {
      expect(
        () => decodeWireEvent(
          wireEventMap(conversationId: 'other'),
          expectedConversationId: 'conversation-1',
        ),
        throwsA(isA<ProtocolIntegrityException>()),
      );
    });

    test('rejects invalid UTC timestamp', () {
      expect(
        () => decodeWireEvent(
          wireEventMap(occurredAt: '2026-07-28T00:00:00+08:00'),
          expectedConversationId: 'conversation-1',
        ),
        throwsA(isA<ProtocolIntegrityException>()),
      );
    });

    test('rejects invalid role', () {
      expect(
        () => decodeWireEvent(
          wireEventMap(role: 'owner'),
          expectedConversationId: 'conversation-1',
        ),
        throwsA(isA<ProtocolIntegrityException>()),
      );
    });

    test('rejects incorrect field type', () {
      final source = wireEventMap()..['conversation_seq'] = 1.0;
      expect(
        () => decodeWireEvent(source, expectedConversationId: 'conversation-1'),
        throwsA(isA<ProtocolIntegrityException>()),
      );
    });
  });

  group('session projection', () {
    test('applies contiguous events', () {
      final projection = SessionProjection(conversationId: 'conversation-1');
      final first = decodeWireEvent(
        wireEventMap(),
        expectedConversationId: 'conversation-1',
      );

      expect(projection.apply(first), isTrue);
      expect(projection.lastConversationSeq, 1);
      expect(projection.events, hasLength(1));
    });

    test('deduplicates an identical event idempotently', () {
      final projection = SessionProjection(conversationId: 'conversation-1');
      final event = decodeWireEvent(
        wireEventMap(),
        expectedConversationId: 'conversation-1',
      );

      expect(projection.apply(event), isTrue);
      expect(projection.apply(event), isFalse);
      expect(projection.events, hasLength(1));
    });

    test('rejects the same event id with different content', () {
      final projection = SessionProjection(conversationId: 'conversation-1');
      projection.apply(
        decodeWireEvent(
          wireEventMap(),
          expectedConversationId: 'conversation-1',
        ),
      );
      final changed = decodeWireEvent(
        wireEventMap(content: 'changed'),
        expectedConversationId: 'conversation-1',
      );

      expect(
        () => projection.apply(changed),
        throwsA(
          isA<ProjectionException>().having(
            (error) => error.code,
            'code',
            'event_integrity_conflict',
          ),
        ),
      );
    });

    test('rejects a sequence gap', () {
      final projection = SessionProjection(conversationId: 'conversation-1');
      final second = decodeWireEvent(
        wireEventMap(sequence: 2, eventId: 'event-2'),
        expectedConversationId: 'conversation-1',
      );

      expect(
        () => projection.apply(second),
        throwsA(
          isA<ProjectionException>().having(
            (error) => error.code,
            'code',
            'sequence_gap',
          ),
        ),
      );
      expect(projection.lastConversationSeq, 0);
    });

    test('rejects an unknown stale event', () {
      final projection = SessionProjection(conversationId: 'conversation-1');
      projection.apply(
        decodeWireEvent(
          wireEventMap(),
          expectedConversationId: 'conversation-1',
        ),
      );
      final stale = decodeWireEvent(
        wireEventMap(eventId: 'different-event'),
        expectedConversationId: 'conversation-1',
      );

      expect(
        () => projection.apply(stale),
        throwsA(
          isA<ProjectionException>().having(
            (error) => error.code,
            'code',
            'stale_or_conflicting_event',
          ),
        ),
      );
    });

    test('rejects a projection conversation mismatch', () {
      final projection = SessionProjection(conversationId: 'conversation-1');
      final event = decodeWireEvent(
        wireEventMap(conversationId: 'other'),
        expectedConversationId: 'other',
      );

      expect(
        () => projection.apply(event),
        throwsA(isA<ProjectionException>()),
      );
    });

    test('semantic hash matches Python golden value', () {
      final projection = SessionProjection(conversationId: 'conversation-1')
        ..apply(
          decodeWireEvent(
            wireEventMap(),
            expectedConversationId: 'conversation-1',
          ),
        );

      expect(
        projection.semanticProjectionHash,
        'c376511df575294d58599651596995b0db0988853143f9cdbf7d8b1f70e42d42',
      );
    });
  });
}

import 'hub_rest_client.dart';
import 'hub_websocket_client.dart';
import 'protocol_models.dart';
import 'session_projection.dart';

final class SharedSessionClient {
  SharedSessionClient({
    required this.rest,
    required this.projection,
    required this.cursorStore,
  });

  final HubRestClient rest;
  final SessionProjection projection;
  final CursorStore cursorStore;

  Future<ReplayPage> replay({int limit = 100}) async {
    final page = await rest.replayEvents(
      conversationId: projection.conversationId,
      afterSeq: projection.lastConversationSeq,
      limit: limit,
    );
    for (final event in page.events) {
      projection.apply(event);
    }
    await cursorStore.write(
      projection.conversationId,
      projection.lastConversationSeq,
    );
    return page;
  }

  Future<AppendMessageResult> submit({
    required String clientMessageId,
    required String actorDeviceId,
    required String role,
    required String content,
  }) async {
    final result = await rest.appendMessage(
      conversationId: projection.conversationId,
      clientMessageId: clientMessageId,
      actorDeviceId: actorDeviceId,
      role: role,
      content: content,
    );
    projection.apply(result.event);
    await cursorStore.write(
      projection.conversationId,
      projection.lastConversationSeq,
    );
    return result;
  }

  Future<void> persistCursor() => cursorStore.write(
    projection.conversationId,
    projection.lastConversationSeq,
  );

  Future<void> close({HubWebSocketClient? websocket}) async {
    await websocket?.close();
    rest.close();
  }
}

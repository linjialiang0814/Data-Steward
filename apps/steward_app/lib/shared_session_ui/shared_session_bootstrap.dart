import 'dart:io';

import '../shared_session/application_cursor_store.dart';
import '../shared_session/authenticated_transport.dart';
import '../shared_session/file_cursor_store.dart';
import '../shared_session/hub_rest_client.dart';
import '../shared_session/hub_websocket_client.dart';
import '../shared_session/session_projection.dart';
import 'shared_session_controller.dart';

typedef SharedSessionControllerFactory =
    Future<SharedSessionController> Function();

Future<SharedSessionController> createDefaultSharedSessionController() async {
  final config = DemoHubConfig.fromEnvironment(Platform.environment);
  return createSharedSessionController(config: config);
}

Future<SharedSessionController> createSharedSessionController({
  required DemoHubConfig? config,
}) async {
  final stateDirectory = Platform.environment['DATA_STEWARD_STATE_DIR'];
  final ResettableCursorStore store;
  if (config != null && stateDirectory != null && stateDirectory.isNotEmpty) {
    store = FileCursorStore(Directory(stateDirectory));
  } else {
    store = await createApplicationCursorStore();
  }
  return SharedSessionController(
    config: config,
    cursorStore: store,
    pageSize: config?.authenticated == true ? 32 : 100,
    transportFactory: (value) => HubSharedSessionTransport(
      value.authenticated
          ? createAuthenticatedHubRestClient(value.activeCredential!)
          : HubRestClient(baseUri: value.resolvedHttpBase),
      actorDeviceId: value.actorDeviceId,
    ),
    socketFactory: (value, projection) => HubWebSocketClient(
      baseUri: value.resolvedWebsocketBase,
      conversationId: demoConversationId,
      projection: projection,
      authenticatedPrivateLan: value.authenticated,
      connector: value.authenticated
          ? authenticatedHubSocketConnector(value.activeCredential!)
          : null,
    ),
  );
}

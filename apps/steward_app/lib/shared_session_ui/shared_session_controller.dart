import 'dart:async';
import 'dart:convert';
import 'dart:math';

import '../shared_session/hub_rest_client.dart';
import '../shared_session/hub_websocket_client.dart';
import '../secure_pairing/pairing_vault.dart';
import '../shared_session/protocol_models.dart';
import '../shared_session/session_projection.dart';
import '../shared_session/shared_session_errors.dart';
import 'memory_center_controller.dart';

const demoConversationId = 'data-steward-windows-demo-v1';

enum SharedSessionViewState {
  unconfigured,
  connecting,
  replaying,
  ready,
  reconnecting,
  authorizationChanged,
  offline,
  protocolError,
  localStateCorrupt,
  cursorAhead,
  closed,
}

final class DemoHubConfig {
  const DemoHubConfig(this.port)
    : httpBase = null,
      websocketBase = null,
      actorDeviceId = 'windows-demo',
      activeCredential = null;

  const DemoHubConfig.authenticated({
    required this.httpBase,
    required this.websocketBase,
    required this.actorDeviceId,
    required this.activeCredential,
  }) : port = null;

  final int? port;
  final Uri? httpBase;
  final Uri? websocketBase;
  final String actorDeviceId;
  final ActiveDeviceCredential? activeCredential;

  bool get authenticated => activeCredential != null;

  static DemoHubConfig? fromEnvironment(Map<String, String> environment) {
    if (environment['DATA_STEWARD_DEMO_MODE'] != '1') return null;
    final rawPort = environment['DATA_STEWARD_HUB_PORT'];
    final port = int.tryParse(rawPort ?? '');
    if (port == null || port < 1 || port > 65535) return null;
    return DemoHubConfig(port);
  }

  Uri get resolvedHttpBase => httpBase ?? Uri.parse('http://127.0.0.1:$port');
  Uri get resolvedWebsocketBase =>
      websocketBase ?? Uri.parse('ws://127.0.0.1:$port');
}

abstract interface class SharedSessionTransport {
  Future<HealthStatus> health();

  Future<ConversationCreation> createDemoConversation();

  Future<ReplayPage> replay({required int afterSeq, required int limit});

  Future<AppendMessageResult> append({
    required String clientMessageId,
    required String content,
  });

  void close();
}

abstract interface class ProductActionTransport {
  Future<List<ProductAction>> listActions({required String assistantMessageId});

  Future<ProductActionExecution> executeAction({
    required String assistantMessageId,
    required String actionId,
  });

  Future<MemoryCenterSnapshot> memoryCenter();
}

final class HubSharedSessionTransport
    implements SharedSessionTransport, ProductActionTransport {
  HubSharedSessionTransport(this.client, {this.actorDeviceId = 'windows-demo'});

  final HubRestClient client;
  final String actorDeviceId;

  @override
  Future<HealthStatus> health() => client.health();

  @override
  Future<ConversationCreation> createDemoConversation() =>
      client.createConversation(
        title: 'Data Steward Shared Session Demo',
        conversationId: demoConversationId,
        continueIfAlreadyExists: true,
      );

  @override
  Future<ReplayPage> replay({required int afterSeq, required int limit}) =>
      client.replayEvents(
        conversationId: demoConversationId,
        afterSeq: afterSeq,
        limit: limit,
      );

  @override
  Future<AppendMessageResult> append({
    required String clientMessageId,
    required String content,
  }) => client.appendMessage(
    conversationId: demoConversationId,
    clientMessageId: clientMessageId,
    actorDeviceId: actorDeviceId,
    role: 'user',
    content: content,
  );

  @override
  Future<List<ProductAction>> listActions({
    required String assistantMessageId,
  }) => client.listProductActions(
    conversationId: demoConversationId,
    assistantMessageId: assistantMessageId,
  );

  @override
  Future<ProductActionExecution> executeAction({
    required String assistantMessageId,
    required String actionId,
  }) => client.executeProductAction(
    conversationId: demoConversationId,
    assistantMessageId: assistantMessageId,
    actionId: actionId,
  );

  @override
  Future<MemoryCenterSnapshot> memoryCenter() =>
      client.memoryCenter(conversationId: demoConversationId);

  @override
  void close() => client.close();
}

typedef TransportFactory =
    SharedSessionTransport Function(DemoHubConfig config);
typedef SocketFactory =
    HubWebSocketClient Function(
      DemoHubConfig config,
      SessionProjection projection,
    );
typedef ClientMessageIdFactory = String Function();

final class SharedSessionController implements MemoryCenterController {
  SharedSessionController({
    required this.config,
    required this.cursorStore,
    required this.transportFactory,
    required this.socketFactory,
    ClientMessageIdFactory? clientMessageIdFactory,
    this.pageSize = 100,
    this.maxPages = 100,
    this.maxEvents = 5000,
  }) : _clientMessageIdFactory =
           clientMessageIdFactory ?? _secureClientMessageId;

  final DemoHubConfig? config;
  final ResettableCursorStore cursorStore;
  final TransportFactory transportFactory;
  final SocketFactory socketFactory;
  final ClientMessageIdFactory _clientMessageIdFactory;
  final int pageSize;
  final int maxPages;
  final int maxEvents;

  SharedSessionViewState _state = SharedSessionViewState.unconfigured;
  SessionProjection _projection = SessionProjection(
    conversationId: demoConversationId,
  );
  SharedSessionTransport? _transport;
  HubWebSocketClient? _socket;
  StreamSubscription<WireEvent>? _eventSubscription;
  StreamSubscription<HubWebSocketState>? _stateSubscription;
  bool _started = false;
  bool _busy = false;
  bool _terminal = false;
  bool _disposed = false;
  bool _transportNeedsRecovery = false;
  bool _actionBusy = false;
  String? _safeError;
  _PendingMessage? _pending;
  int _persistedAtStart = 0;
  int _lifecycleGeneration = 0;
  int _operationSerial = 0;
  int? _activeOperation;
  Future<void>? _closeFuture;
  final Set<void Function()> _listeners = <void Function()>{};

  SharedSessionViewState get state => _state;

  @override
  bool get canLoadMemory =>
      !_disposed && _state == SharedSessionViewState.ready;
  bool get busy => _busy;
  @override
  bool get actionBusy => _actionBusy;
  bool get canSend =>
      _state == SharedSessionViewState.ready && !_busy && !_terminal;
  String? get safeError => _safeError;
  String? get pendingContent => _pending?.content;
  bool get canRetry => _pending != null && !_busy && canSend;
  int get lastConversationSeq => _projection.lastConversationSeq;
  int get persistedAtStart => _persistedAtStart;
  List<WireEvent> get events => _projection.events;
  String get semanticProjectionHash => _projection.semanticProjectionHash;

  @override
  void addListener(void Function() listener) => _listeners.add(listener);

  @override
  void removeListener(void Function() listener) => _listeners.remove(listener);

  Future<void> start() async {
    if (_disposed || _terminal || _started || _activeOperation != null) {
      throw const ProjectionException('controller_busy');
    }
    _started = true;
    if (config == null) {
      _setState(SharedSessionViewState.unconfigured);
      return;
    }
    final operation = _beginOperation();
    _safeError = null;
    _setState(SharedSessionViewState.connecting);
    var startupStage = 'health';
    try {
      final transport = transportFactory(config!);
      if (!_isOperationCurrent(operation)) {
        transport.close();
        return;
      }
      _transport = transport;
      final health = await transport.health();
      if (!_isOperationCurrent(operation)) return;
      if (!health.databaseReady || health.protocolVersion != 1) {
        throw const ProtocolIntegrityException();
      }
      startupStage = 'conversation';
      await transport.createDemoConversation();
      if (!_isOperationCurrent(operation)) return;
      startupStage = 'local_cursor';
      final storedCursor = await cursorStore.read(demoConversationId);
      if (!_isOperationCurrent(operation)) return;
      _setState(SharedSessionViewState.replaying);

      startupStage = 'replay';
      final projection = SessionProjection(conversationId: demoConversationId);
      var cursor = 0;
      var pages = 0;
      var eventCount = 0;
      while (true) {
        if (pages >= maxPages) {
          throw const ProjectionException('replay_limit');
        }
        final page = await transport.replay(afterSeq: cursor, limit: pageSize);
        if (!_isOperationCurrent(operation)) return;
        pages += 1;
        for (final event in page.events) {
          projection.apply(event);
          eventCount += 1;
          if (eventCount > maxEvents) {
            throw const ProjectionException('replay_limit');
          }
        }
        if (page.events.isEmpty) break;
        cursor = page.lastConversationSeq;
      }

      if (!_isOperationCurrent(operation)) return;
      if (storedCursor > projection.lastConversationSeq) {
        await _enterFailure(
          SharedSessionViewState.cursorAhead,
          '本地同步游标超前，必须由用户确认后重置。',
        );
        return;
      }
      await cursorStore.write(
        demoConversationId,
        projection.lastConversationSeq,
      );
      if (!_isOperationCurrent(operation)) return;
      _persistedAtStart = storedCursor;
      _projection = projection;

      startupStage = 'realtime';
      final socket = socketFactory(config!, projection);
      if (!_isOperationCurrent(operation)) {
        await socket.close();
        return;
      }
      _socket = socket;
      final lifecycle = operation.lifecycle;
      _eventSubscription = socket.appliedEvents.listen(
        (event) => _onSocketEvent(event, lifecycle),
      );
      _stateSubscription = socket.states.listen(
        (state) => _onSocketState(state, lifecycle),
      );
      await socket.connect();
      if (!_isOperationCurrent(operation)) {
        await socket.close();
        return;
      }
      await socket.waitForState(HubWebSocketState.ready);
      if (!_isOperationCurrent(operation)) return;
      _setState(SharedSessionViewState.ready);
    } on ProjectionException catch (error) {
      if (!_isOperationCurrent(operation)) return;
      if (error.code == 'local_state_corrupt') {
        await _enterFailure(
          SharedSessionViewState.localStateCorrupt,
          '应用私有同步状态损坏，必须由用户确认后重置。',
        );
      } else {
        await _enterProtocolFailure(startupStage);
      }
    } on HubApiException catch (error) {
      if (!_isOperationCurrent(operation)) return;
      if (_isAuthorizationChange(error.code)) {
        await _enterAuthorizationFailure(error.code);
      } else if (error.code == 'cursor_ahead') {
        await _enterFailure(
          SharedSessionViewState.cursorAhead,
          'Hub 拒绝了超前游标，必须由用户确认后重置。',
        );
      } else {
        await _enterProtocolFailure(startupStage);
      }
    } on TransportException catch (error) {
      if (!_isOperationCurrent(operation)) return;
      await _enterFailure(SharedSessionViewState.offline, switch (error.code) {
        'auth_unavailable' => 'Hub 认证服务暂时不可用；请等待状态稳定后单次重连。',
        'transient_network' => '无法连接当前电脑地址；请确认同一 Wi-Fi 与本机 Demo 状态。',
        _ => 'Hub 当前离线，请确认本机 Demo 已启动。',
      });
    } on Object {
      if (!_isOperationCurrent(operation)) return;
      await _enterProtocolFailure(startupStage);
    } finally {
      _finishOperation(operation);
    }
  }

  Future<void> send(String rawContent) async {
    final content = rawContent.trim();
    if (!canSend ||
        _activeOperation != null ||
        content.isEmpty ||
        content.length > 2000) {
      throw const ProjectionException('send_not_allowed');
    }
    _pending = _PendingMessage(_clientMessageIdFactory(), content);
    final operation = _beginOperation();
    await _sendPending(operation, recoverTransport: false);
  }

  Future<List<ProductAction>> actionsFor(String assistantMessageId) async {
    final transport = _transport;
    if (_disposed || transport is! ProductActionTransport) return const [];
    try {
      return await (transport as ProductActionTransport).listActions(
        assistantMessageId: assistantMessageId,
      );
    } on Object {
      return const [];
    }
  }

  @override
  Future<ProductActionExecution> executeAction(ProductAction action) async {
    final transport = _transport;
    if (_disposed ||
        _terminal ||
        _state != SharedSessionViewState.ready ||
        _actionBusy ||
        action.status != 'available' ||
        transport is! ProductActionTransport) {
      throw const ProjectionException('action_not_allowed');
    }
    final actionTransport = transport as ProductActionTransport;
    _actionBusy = true;
    _safeError = null;
    _notify();
    try {
      final execution = await actionTransport.executeAction(
        assistantMessageId: action.assistantMessageId,
        actionId: action.actionId,
      );
      try {
        _projection.apply(execution.event);
        await cursorStore.write(
          demoConversationId,
          _projection.lastConversationSeq,
        );
      } on ProtocolIntegrityException {
        await _enterProtocolFailure();
        rethrow;
      } on ProjectionException {
        await _enterProtocolFailure();
        rethrow;
      } on Object {
        await _enterFailure(
          SharedSessionViewState.localStateCorrupt,
          '消息已由 Hub 接受，但应用私有同步状态写入失败。重启后将从 Hub 恢复。',
        );
        rethrow;
      }
      _notify();
      return execution;
    } on Object {
      _safeError ??= '操作未确认，系统没有自动重试。请刷新状态后再决定。';
      rethrow;
    } finally {
      _actionBusy = false;
      _notify();
    }
  }

  @override
  Future<MemoryCenterSnapshot?> memoryCenter() async {
    if (_disposed || _terminal || _activeOperation != null || config == null) {
      return null;
    }
    if (_transportNeedsRecovery) {
      final operation = _beginOperation();
      try {
        await _recoverTransport(operation);
      } on Object {
        if (_isOperationCurrent(operation)) _discardTransportForRetry();
        return null;
      } finally {
        _finishOperation(operation);
      }
    }
    final transport = _transport;
    if (transport is! ProductActionTransport) return null;
    try {
      return await (transport as ProductActionTransport).memoryCenter();
    } on TransportException {
      _discardTransportForRetry();
      return null;
    } on Object {
      return null;
    }
  }

  Future<void> retryPending() async {
    if (!canRetry || _activeOperation != null) {
      throw const ProjectionException('send_not_allowed');
    }
    final operation = _beginOperation();
    await _sendPending(operation, recoverTransport: _transportNeedsRecovery);
  }

  Future<void> _sendPending(
    _OperationToken operation, {
    required bool recoverTransport,
  }) async {
    final pending = _pending;
    if (pending == null) {
      _finishOperation(operation);
      throw const ProjectionException('send_not_allowed');
    }
    _safeError = null;
    _notify();
    try {
      if (recoverTransport) {
        await _recoverTransport(operation);
        if (!_isOperationCurrent(operation)) return;
      }
      final transport = _transport;
      if (transport == null) {
        throw const TransportException();
      }
      final result = await transport.append(
        clientMessageId: pending.clientMessageId,
        content: pending.content,
      );
      if (!_isOperationCurrent(operation)) return;
      pending.confirm();
      _pending = null;
      try {
        _projection.apply(result.event);
      } on ProtocolIntegrityException {
        await _enterProtocolFailure();
        rethrow;
      } on ProjectionException {
        await _enterProtocolFailure();
        rethrow;
      }
      if (!_isOperationCurrent(operation)) return;
      try {
        await cursorStore.write(
          demoConversationId,
          _projection.lastConversationSeq,
        );
      } on Object {
        if (_isOperationCurrent(operation)) {
          await _enterFailure(
            SharedSessionViewState.localStateCorrupt,
            '消息已由 Hub 接受，但应用私有同步状态写入失败。重启后将从 Hub 恢复。',
          );
        }
        rethrow;
      }
    } on TransportException {
      if (!_isOperationCurrent(operation)) return;
      _discardTransportForRetry();
      if (!pending.confirmed) {
        try {
          await pending.confirmation.timeout(const Duration(seconds: 2));
        } on TimeoutException {
          // A bounded reconciliation window is not a retry. If no validated
          // WebSocket event arrives, delivery remains explicitly uncertain.
        }
      }
      if (pending.confirmed || _pending == null) {
        _safeError = null;
        _notify();
        return;
      }
      _safeError = '消息未确认，可显式重试。';
      rethrow;
    } on HubApiException catch (error) {
      if (!_isOperationCurrent(operation)) return;
      if (_isAuthorizationChange(error.code)) {
        await _enterAuthorizationFailure(error.code);
      } else if (error.code == 'persistence_unavailable') {
        _safeError = '消息未确认，可显式重试。';
      } else {
        await _enterProtocolFailure();
      }
      rethrow;
    } on ProtocolIntegrityException {
      if (_isOperationCurrent(operation)) {
        await _enterProtocolFailure();
      }
      rethrow;
    } on ProjectionException {
      if (_isOperationCurrent(operation)) {
        await _enterProtocolFailure();
      }
      rethrow;
    } on Object {
      if (_isOperationCurrent(operation)) {
        await _enterProtocolFailure();
      }
      rethrow;
    } finally {
      _finishOperation(operation);
    }
  }

  Future<void> resetCursor() async {
    if (_disposed || _terminal || _activeOperation != null) {
      throw const ProjectionException('controller_busy');
    }
    final operation = _beginOperation();
    _markTerminal();
    await _releaseResources();
    if (!_isResetCurrent(operation)) return;
    await cursorStore.reset(demoConversationId);
    if (!_isResetCurrent(operation)) return;
    _busy = false;
    _state = SharedSessionViewState.closed;
    _notify();
  }

  Future<void> close() {
    final existing = _closeFuture;
    if (existing != null) return existing;
    _markTerminal(forceInvalidate: true);
    _state = SharedSessionViewState.closed;
    _notify();
    return _closeFuture = _releaseResources();
  }

  Future<void> _onSocketEvent(WireEvent event, int lifecycle) async {
    if (!_isLifecycleCurrent(lifecycle)) return;
    try {
      await cursorStore.write(demoConversationId, event.conversationSeq);
      if (!_isLifecycleCurrent(lifecycle)) return;
      final pending = _pending;
      if (pending != null &&
          event.payload.role == 'user' &&
          event.payload.clientMessageId == pending.clientMessageId) {
        pending.confirm();
        _pending = null;
        _safeError = null;
      }
      _notify();
    } on Object {
      if (_isLifecycleCurrent(lifecycle)) {
        await _enterFailure(
          SharedSessionViewState.localStateCorrupt,
          '应用私有同步状态损坏，必须由用户确认后重置。',
        );
      }
    }
  }

  void _onSocketState(HubWebSocketState state, int lifecycle) {
    if (!_isLifecycleCurrent(lifecycle)) return;
    switch (state) {
      case HubWebSocketState.connecting:
        _setState(SharedSessionViewState.connecting);
      case HubWebSocketState.replaying:
        _setState(SharedSessionViewState.replaying);
      case HubWebSocketState.ready:
        _setState(SharedSessionViewState.ready);
      case HubWebSocketState.reconnecting:
        _setState(SharedSessionViewState.reconnecting);
      case HubWebSocketState.authorizationChanged:
        unawaited(_enterAuthorizationFailure('authorization_changed'));
      case HubWebSocketState.protocolError:
        _setState(SharedSessionViewState.protocolError);
      case HubWebSocketState.disconnected:
      case HubWebSocketState.closed:
        if (_state != SharedSessionViewState.closed) {
          _setState(SharedSessionViewState.offline);
        }
    }
  }

  Future<void> _recoverTransport(_OperationToken operation) async {
    final transport = transportFactory(config!);
    if (!_isOperationCurrent(operation)) {
      transport.close();
      return;
    }
    _transport = transport;
    final health = await transport.health();
    if (!_isOperationCurrent(operation)) return;
    if (!health.databaseReady || health.protocolVersion != 1) {
      throw const ProtocolIntegrityException();
    }
    await transport.createDemoConversation();
    if (!_isOperationCurrent(operation)) return;
    _transportNeedsRecovery = false;
  }

  void _discardTransportForRetry() {
    final transport = _transport;
    _transport = null;
    _transportNeedsRecovery = true;
    try {
      transport?.close();
    } on Object {
      // Cleanup stays sanitized.
    }
  }

  Future<void> _enterProtocolFailure([String? startupStage]) => _enterFailure(
    SharedSessionViewState.protocolError,
    switch (startupStage) {
      'health' => '电脑服务身份或版本校验失败，已停止连接。',
      'conversation' => '会话建立响应校验失败，已停止连接。',
      'local_cursor' => '本地会话状态校验失败，已停止连接。',
      'replay' => '历史消息回放校验失败，已停止连接。',
      'realtime' => '实时同步通道校验失败，已停止连接。',
      _ => '共享会话协议校验失败，已停止发送。',
    },
  );

  Future<void> _enterAuthorizationFailure(String code) => _enterFailure(
    SharedSessionViewState.authorizationChanged,
    code == 'auth_revoked'
        ? '设备授权已撤销，已停止重连。请在“安全配对”页重新连接。'
        : '设备权限已变更，旧授权版本已停止重连。请重新安全配对。',
  );

  Future<void> _enterFailure(
    SharedSessionViewState state,
    String safeError,
  ) async {
    _lifecycleGeneration += 1;
    final failureGeneration = _lifecycleGeneration;
    _activeOperation = null;
    _busy = false;
    _pending = null;
    _transportNeedsRecovery = false;
    await _releaseResources();
    if (_disposed || _terminal || failureGeneration != _lifecycleGeneration) {
      return;
    }
    _safeError = safeError;
    _state = state;
    _notify();
  }

  Future<void> _releaseResources() async {
    final eventSubscription = _eventSubscription;
    final stateSubscription = _stateSubscription;
    final socket = _socket;
    final transport = _transport;
    _eventSubscription = null;
    _stateSubscription = null;
    _socket = null;
    _transport = null;
    try {
      transport?.close();
    } on Object {
      // Cleanup stays sanitized.
    }
    try {
      await eventSubscription?.cancel();
    } on Object {
      // Cleanup stays sanitized.
    }
    try {
      await stateSubscription?.cancel();
    } on Object {
      // Cleanup stays sanitized.
    }
    try {
      await socket?.close();
    } on Object {
      // Cleanup stays sanitized.
    }
  }

  _OperationToken _beginOperation() {
    final serial = ++_operationSerial;
    _activeOperation = serial;
    _busy = true;
    _notify();
    return _OperationToken(_lifecycleGeneration, serial);
  }

  void _finishOperation(_OperationToken operation) {
    if (!_isOperationCurrent(operation)) return;
    _activeOperation = null;
    _busy = false;
    _notify();
  }

  bool _isOperationCurrent(_OperationToken operation) =>
      !_disposed &&
      !_terminal &&
      operation.lifecycle == _lifecycleGeneration &&
      operation.serial == _activeOperation;

  bool _isLifecycleCurrent(int lifecycle) =>
      !_disposed && !_terminal && lifecycle == _lifecycleGeneration;

  bool _isResetCurrent(_OperationToken operation) =>
      !_disposed &&
      _terminal &&
      operation.lifecycle + 1 == _lifecycleGeneration;

  void _markTerminal({bool forceInvalidate = false}) {
    if (!_terminal || forceInvalidate) {
      _lifecycleGeneration += 1;
    }
    _terminal = true;
    _activeOperation = null;
    _busy = false;
  }

  void _setState(SharedSessionViewState value) {
    if (_disposed || _terminal) return;
    _state = value;
    _notify();
  }

  void _notify() {
    if (_disposed) return;
    for (final listener in List<void Function()>.of(_listeners)) {
      listener();
    }
  }

  void dispose() {
    if (_disposed) return;
    _markTerminal(forceInvalidate: true);
    _disposed = true;
    _listeners.clear();
    _closeFuture ??= _releaseResources();
  }
}

bool _isAuthorizationChange(String code) => const {
  'auth_invalid',
  'auth_revoked',
  'capability_denied',
  'capability_epoch_stale',
}.contains(code);

final class _OperationToken {
  const _OperationToken(this.lifecycle, this.serial);

  final int lifecycle;
  final int serial;
}

String _secureClientMessageId() {
  final bytes = List<int>.generate(16, (_) => Random.secure().nextInt(256));
  return base64UrlEncode(bytes).replaceAll('=', '');
}

final class _PendingMessage {
  _PendingMessage(this.clientMessageId, this.content);

  final String clientMessageId;
  final String content;
  final Completer<void> _confirmation = Completer<void>();

  bool get confirmed => _confirmation.isCompleted;
  Future<void> get confirmation => _confirmation.future;

  void confirm() {
    if (!_confirmation.isCompleted) _confirmation.complete();
  }
}

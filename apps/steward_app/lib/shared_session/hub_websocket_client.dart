import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'hub_rest_client.dart';
import 'protocol_codec.dart';
import 'protocol_models.dart';
import 'session_projection.dart';
import 'shared_session_errors.dart';

enum HubWebSocketState {
  disconnected,
  connecting,
  replaying,
  ready,
  reconnecting,
  authorizationChanged,
  protocolError,
  closed,
}

abstract interface class HubSocket {
  Stream<Object?> get frames;
  int? get closeCode;

  Future<void> close([int? code, String? reason]);
}

typedef HubSocketConnector = Future<HubSocket> Function(Uri uri);
typedef DelayFunction = Future<void> Function(Duration duration);
typedef RandomFunction = double Function();

final class IoHubSocket implements HubSocket {
  IoHubSocket(this._socket, this._client);

  final WebSocket _socket;
  final HttpClient _client;
  bool _closed = false;

  @override
  int? get closeCode => _socket.closeCode;

  @override
  Stream<Object?> get frames => _socket;

  @override
  Future<void> close([int? code, String? reason]) async {
    if (_closed) return;
    _closed = true;
    try {
      await _socket.close(code, reason);
    } finally {
      _client.close(force: true);
    }
  }
}

Future<HubSocket> connectDirectWebSocket(
  Uri uri, {
  Duration timeout = const Duration(seconds: 5),
}) async {
  final validated = validateLoopbackBaseUri(
    uri,
    scheme: 'ws',
    allowPathAndQuery: true,
  );
  final client = HttpClient()..findProxy = (_) => 'DIRECT';
  try {
    final socket = await WebSocket.connect(
      validated.toString(),
      headers: const <String, dynamic>{},
      compression: CompressionOptions.compressionOff,
      customClient: client,
    ).timeout(timeout);
    return IoHubSocket(socket, client);
  } on Object {
    client.close(force: true);
    throw const TransportException();
  }
}

final class HubWebSocketClient {
  HubWebSocketClient({
    required Uri baseUri,
    required this.conversationId,
    required this.projection,
    HubSocketConnector? connector,
    this.authenticatedPrivateLan = false,
    DelayFunction? delay,
    RandomFunction? random,
    this.connectTimeout = const Duration(seconds: 5),
    this.maxFrameBytes = 1024 * 1024,
    this.maxReconnectAttempts = 3,
  }) : baseUri = authenticatedPrivateLan
           ? validateAuthenticatedPrivateBaseUri(baseUri, scheme: 'wss')
           : validateLoopbackBaseUri(baseUri, scheme: 'ws'),
       _connector =
           connector ??
           ((uri) => connectDirectWebSocket(uri, timeout: connectTimeout)),
       _delay = delay ?? Future<void>.delayed,
       _random = random ?? _zeroRandom;

  final Uri baseUri;
  final String conversationId;
  final bool authenticatedPrivateLan;
  final SessionProjection projection;
  final Duration connectTimeout;
  final int maxFrameBytes;
  final int maxReconnectAttempts;
  final HubSocketConnector _connector;
  final DelayFunction _delay;
  final RandomFunction _random;
  final StreamController<HubWebSocketState> _states =
      StreamController<HubWebSocketState>.broadcast();
  final StreamController<WireEvent> _events =
      StreamController<WireEvent>.broadcast();

  HubWebSocketState _state = HubWebSocketState.disconnected;
  _SocketConnection? _activeConnection;
  int? cursorAheadServerWatermark;
  int _reconnectAttempt = 0;
  bool _terminalClosed = false;
  Future<void>? _closeFuture;

  HubWebSocketState get state => _state;
  Stream<HubWebSocketState> get states => _states.stream;
  Stream<WireEvent> get appliedEvents => _events.stream;

  Future<void> connect() async {
    if (_terminalClosed) {
      throw const ProjectionException('websocket_closed');
    }
    if (_state != HubWebSocketState.disconnected) {
      throw const ProjectionException('websocket_already_active');
    }
    await _openConnection(isReconnect: false);
  }

  Future<void> _openConnection({required bool isReconnect}) async {
    if (_terminalClosed) {
      throw const ProjectionException('websocket_closed');
    }
    if ((!isReconnect && _state != HubWebSocketState.disconnected) ||
        (isReconnect && _state != HubWebSocketState.reconnecting)) {
      throw const ProjectionException('websocket_already_active');
    }
    _setState(HubWebSocketState.connecting);
    final path =
        '/v1/conversations/${Uri.encodeComponent(conversationId)}/events/ws';
    final uri = baseUri.replace(
      path: path,
      queryParameters: <String, String>{
        'after_seq': '${projection.lastConversationSeq}',
      },
    );
    final Future<HubSocket> pendingSocket;
    try {
      pendingSocket = _connector(uri);
    } on Object {
      _setState(HubWebSocketState.protocolError);
      throw const TransportException();
    }

    HubSocket socket;
    try {
      socket = await pendingSocket.timeout(connectTimeout);
    } on TimeoutException {
      unawaited(pendingSocket.then(_releaseOrphanSocket, onError: (_) {}));
      _setState(HubWebSocketState.protocolError);
      throw const TransportException();
    } on Object {
      _setState(HubWebSocketState.protocolError);
      throw const TransportException();
    }
    if (_terminalClosed) {
      await _releaseOrphanSocket(socket);
      throw const TransportException();
    }

    final connection = _SocketConnection(socket);
    _activeConnection = connection;
    _setState(HubWebSocketState.replaying);
    try {
      connection.subscription = socket.frames.listen(
        (frame) {
          try {
            processFrame(frame);
          } on Object {
            unawaited(_failProtocol(connection));
          }
        },
        onError: (_) => unawaited(_handleStreamError(connection)),
        onDone: () => unawaited(_handleSocketDone(connection)),
        cancelOnError: false,
      );
    } on Object {
      await _releaseConnection(connection);
      if (!_terminalClosed) {
        _setState(HubWebSocketState.protocolError);
      }
      throw const TransportException();
    }
  }

  void processFrame(Object? frame) {
    if (frame is! String || utf8.encode(frame).length > maxFrameBytes) {
      throw const ProtocolIntegrityException();
    }
    final decoded = decodeWebSocketFrame(
      frame,
      expectedConversationId: conversationId,
    );
    if (decoded is EventFrame) {
      if ((_state == HubWebSocketState.replaying &&
              decoded.delivery != 'replay') ||
          (_state == HubWebSocketState.ready && decoded.delivery != 'live')) {
        throw const ProtocolIntegrityException();
      }
      if (_state != HubWebSocketState.replaying &&
          _state != HubWebSocketState.ready) {
        throw const ProtocolIntegrityException();
      }
      if (projection.apply(decoded.event)) {
        _events.add(decoded.event);
      }
      return;
    }
    if (decoded is ReadyFrame) {
      if (_state != HubWebSocketState.replaying ||
          decoded.lastConversationSeq != projection.lastConversationSeq) {
        throw const ProtocolIntegrityException();
      }
      _reconnectAttempt = 0;
      _setState(HubWebSocketState.ready);
      return;
    }
    if (decoded is ErrorFrame && decoded.code == 'cursor_ahead') {
      cursorAheadServerWatermark = decoded.serverLastConversationSeq;
      _setState(HubWebSocketState.protocolError);
      throw HubApiException(
        statusCode: 409,
        code: decoded.code,
        serverLastConversationSeq: decoded.serverLastConversationSeq,
      );
    }
    throw const ProtocolIntegrityException();
  }

  Future<bool> handleCloseCode(int? code, {required int attempt}) async {
    if (_terminalClosed) return false;
    if (code == 1008 && authenticatedPrivateLan) {
      _setState(HubWebSocketState.authorizationChanged);
      return false;
    }
    if (code == 1008 || code == 1011) {
      _setState(HubWebSocketState.protocolError);
      return false;
    }
    if (code == 1013 && attempt < maxReconnectAttempts) {
      _setState(HubWebSocketState.reconnecting);
      final exponent = attempt.clamp(0, 10);
      final baseMilliseconds = 100 * (1 << exponent);
      final jitter = (baseMilliseconds * 0.25 * _random()).round();
      await _delay(Duration(milliseconds: baseMilliseconds + jitter));
      if (_terminalClosed) return false;
      return true;
    }
    _setState(HubWebSocketState.closed);
    return false;
  }

  Future<void> waitForState(
    HubWebSocketState expected, {
    Duration timeout = const Duration(seconds: 5),
  }) async {
    if (_state == expected) return;
    await states.firstWhere((state) => state == expected).timeout(timeout);
  }

  Future<void> waitForSequence(
    int sequence, {
    Duration timeout = const Duration(seconds: 5),
  }) async {
    if (projection.lastConversationSeq >= sequence) return;
    await appliedEvents
        .firstWhere((event) => event.conversationSeq >= sequence)
        .timeout(timeout);
  }

  Future<void> close() => _closeFuture ??= _close();

  void _setState(HubWebSocketState value) {
    _state = value;
    if (!_states.isClosed) _states.add(value);
  }

  Future<void> _close() async {
    _terminalClosed = true;
    final connection = _activeConnection;
    if (connection != null) {
      await _releaseConnection(connection, code: 1000, reason: 'client closed');
    }
    _setState(HubWebSocketState.closed);
    await _events.close();
    await _states.close();
  }

  Future<void> _failProtocol(_SocketConnection connection) async {
    if (!_terminalClosed) {
      _setState(HubWebSocketState.protocolError);
    }
    await _releaseConnection(connection, code: 1008, reason: 'protocol error');
  }

  Future<void> _handleStreamError(_SocketConnection connection) async {
    await _releaseConnection(connection);
    if (!_terminalClosed) {
      _setState(HubWebSocketState.protocolError);
    }
  }

  Future<void> _handleSocketDone(_SocketConnection connection) async {
    if (connection.released) return;
    final closeCode = connection.socket.closeCode;
    await _releaseConnection(connection);
    if (_terminalClosed || _state == HubWebSocketState.protocolError) return;
    final reconnect = await handleCloseCode(
      closeCode,
      attempt: _reconnectAttempt,
    );
    if (!reconnect || _terminalClosed) return;
    _reconnectAttempt += 1;
    try {
      await _openConnection(isReconnect: true);
    } on Object {
      if (!_terminalClosed) {
        _setState(HubWebSocketState.protocolError);
      }
    }
  }

  Future<void> _releaseConnection(
    _SocketConnection connection, {
    int? code,
    String? reason,
  }) async {
    if (connection.released) return;
    connection.released = true;
    if (identical(_activeConnection, connection)) {
      _activeConnection = null;
    }
    try {
      await connection.subscription?.cancel();
    } on Object {
      // Resource cleanup remains fail-closed and intentionally sanitized.
    }
    try {
      await connection.socket.close(code, reason);
    } on Object {
      // Underlying close failures must not leak transport details.
    }
  }

  Future<void> _releaseOrphanSocket(HubSocket socket) async {
    try {
      await socket.close();
    } on Object {
      // A connector that completes after timeout is still released silently.
    }
  }
}

double _zeroRandom() => 0;

final class _SocketConnection {
  _SocketConnection(this.socket);

  final HubSocket socket;
  StreamSubscription<Object?>? subscription;
  bool released = false;
}

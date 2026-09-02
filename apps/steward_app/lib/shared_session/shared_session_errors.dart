sealed class SharedSessionException implements Exception {
  const SharedSessionException(this.code);

  final String code;

  @override
  String toString() => 'SharedSessionException($code)';
}

final class NetworkBoundaryException extends SharedSessionException {
  const NetworkBoundaryException() : super('network_boundary');
}

final class TransportException extends SharedSessionException {
  const TransportException([super.code = 'transport_error']);
}

final class ProtocolIntegrityException extends SharedSessionException {
  const ProtocolIntegrityException() : super('protocol_integrity');
}

final class ProjectionException extends SharedSessionException {
  const ProjectionException(super.code);
}

final class HubApiException extends SharedSessionException {
  const HubApiException({
    required this.statusCode,
    required String code,
    this.serverLastConversationSeq,
  }) : super(code);

  final int statusCode;
  final int? serverLastConversationSeq;
}

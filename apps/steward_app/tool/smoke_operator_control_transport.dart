import 'dart:convert';
import 'dart:io';

import 'package:steward_app/pairing_ui/operator_control_transport.dart';
import 'package:steward_app/secure_pairing/pairing_errors.dart';

Future<void> main() async {
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  var loopbackRequestVerified = false;
  try {
    final served = server.first.then((request) async {
      final requestBody = await utf8.decoder.bind(request).join();
      loopbackRequestVerified =
          request.method == 'POST' &&
          request.headers.value('x-datasteward-protocol') == 'pairing_auth/1' &&
          requestBody == '{}';
      request.response.headers.contentType = ContentType.json;
      final body = utf8.encode('{"ok":true}');
      request.response.contentLength = body.length;
      request.response.add(body);
      await request.response.close();
    });
    const transport = IoOperatorControlTransport();
    final response = await transport.send(
      uri: Uri.parse(
        'http://127.0.0.1:${server.port}/v1/operator/pairing/sessions',
      ),
      expectedFingerprint: 'a' * 64,
      method: 'POST',
      headers: const {'X-DataSteward-Protocol': 'pairing_auth/1'},
      body: '{}',
    );
    await served;
    final loopbackResponseVerified =
        response.statusCode == 200 && response.body == '{"ok":true}';

    var lanHttpRejected = false;
    try {
      await transport.send(
        uri: Uri.parse('http://192.168.50.25:9443/v1/operator/devices'),
        expectedFingerprint: 'a' * 64,
        method: 'GET',
        headers: const {},
      );
    } on SecurePairingException catch (error) {
      lanHttpRejected = error.code == 'protocol_integrity_error';
    }
    final pass =
        loopbackRequestVerified && loopbackResponseVerified && lanHttpRejected;
    stdout.writeln(
      jsonEncode({
        'status': pass ? 'PASS' : 'FAIL',
        'loopback_request_verified': loopbackRequestVerified,
        'loopback_response_verified': loopbackResponseVerified,
        'lan_http_rejected': lanHttpRejected,
      }),
    );
    if (!pass) exitCode = 1;
  } finally {
    await server.close(force: true);
  }
}

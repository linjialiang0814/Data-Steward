import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:steward_app/shared_session/file_cursor_store.dart';
import 'package:steward_app/shared_session/shared_session_errors.dart';

void main() {
  late Directory temporary;
  late FileCursorStore store;

  setUp(() async {
    temporary = await Directory.systemTemp.createTemp('cursor-store-test-');
    store = FileCursorStore(temporary);
  });

  tearDown(() async {
    if (await temporary.exists()) await temporary.delete(recursive: true);
  });

  test('first read is zero', () async {
    expect(await store.read('conversation-a'), 0);
  });

  test('atomic write reads back without next or backup', () async {
    await store.write('conversation-a', 3);

    expect(await store.read('conversation-a'), 3);
    expect(await _file(temporary, 'conversation-a', '.next').exists(), isFalse);
    expect(
      await _file(temporary, 'conversation-a', '.backup').exists(),
      isFalse,
    );
  });

  test('same sequence is idempotent', () async {
    await store.write('conversation-a', 2);
    await store.write('conversation-a', 2);

    expect(await store.read('conversation-a'), 2);
  });

  test('cursor regression is rejected', () async {
    await store.write('conversation-a', 4);

    await expectLater(
      store.write('conversation-a', 3),
      throwsA(
        isA<ProjectionException>().having(
          (error) => error.code,
          'code',
          'cursor_regression',
        ),
      ),
    );
    expect(await store.read('conversation-a'), 4);
  });

  test('checksum tampering is rejected', () async {
    await store.write('conversation-a', 1);
    final file = _file(temporary, 'conversation-a');
    final value = jsonDecode(await file.readAsString()) as Map<String, dynamic>;
    value['checksum_sha256'] = '0' * 64;
    await file.writeAsString(jsonEncode(value), flush: true);

    await _expectCorrupt(store.read('conversation-a'));
  });

  test('conversation hash mismatch is rejected', () async {
    await store.write('conversation-a', 1);
    final file = _file(temporary, 'conversation-a');
    final value = jsonDecode(await file.readAsString()) as Map<String, dynamic>;
    value['conversation_id_sha256'] = '0' * 64;
    await file.writeAsString(jsonEncode(value), flush: true);

    await _expectCorrupt(store.read('conversation-a'));
  });

  test('unknown and missing fields are rejected', () async {
    for (final mutate in <void Function(Map<String, dynamic>)>[
      (value) => value['unknown'] = true,
      (value) => value.remove('schema_version'),
    ]) {
      await store.reset('conversation-a');
      await store.write('conversation-a', 1);
      final file = _file(temporary, 'conversation-a');
      final value =
          jsonDecode(await file.readAsString()) as Map<String, dynamic>;
      mutate(value);
      await file.writeAsString(jsonEncode(value), flush: true);
      await _expectCorrupt(store.read('conversation-a'));
    }
  });

  test('negative sequence is rejected', () async {
    await store.write('conversation-a', 1);
    final file = _file(temporary, 'conversation-a');
    final value = jsonDecode(await file.readAsString()) as Map<String, dynamic>;
    value['conversation_seq'] = -1;
    await file.writeAsString(jsonEncode(value), flush: true);

    await _expectCorrupt(store.read('conversation-a'));
  });

  test('valid backup restores missing final', () async {
    await store.write('conversation-a', 5);
    final finalFile = _file(temporary, 'conversation-a');
    final backup = _file(temporary, 'conversation-a', '.backup');
    await finalFile.rename(backup.path);

    expect(await store.read('conversation-a'), 5);
    expect(await finalFile.exists(), isTrue);
    expect(await backup.exists(), isFalse);
  });

  test('conflicting final and backup fail closed', () async {
    await store.write('conversation-a', 1);
    final finalFile = _file(temporary, 'conversation-a');
    final oldBytes = await finalFile.readAsBytes();
    await store.write('conversation-a', 2);
    await _file(
      temporary,
      'conversation-a',
      '.backup',
    ).writeAsBytes(oldBytes, flush: true);

    await _expectCorrupt(store.read('conversation-a'));
  });

  test('concurrent writes preserve maximum confirmed cursor', () async {
    final results = await Future.wait(
      <Future<void>>[
        store.write('conversation-a', 2),
        store.write('conversation-a', 7),
        store.write('conversation-a', 4),
      ].map((future) => future.catchError((_) {})),
    );

    expect(results, hasLength(3));
    expect(await store.read('conversation-a'), 7);
  });

  test('reset affects only target conversation', () async {
    await store.write('conversation-a', 2);
    await store.write('conversation-b', 4);

    await store.reset('conversation-a');

    expect(await store.read('conversation-a'), 0);
    expect(await store.read('conversation-b'), 4);
  });
}

File _file(Directory directory, String conversation, [String suffix = '']) {
  final hash = sha256.convert(utf8.encode(conversation)).toString();
  return File('${directory.path}/cursor-$hash.json$suffix');
}

Future<void> _expectCorrupt(Future<int> operation) => expectLater(
  operation,
  throwsA(
    isA<ProjectionException>().having(
      (error) => error.code,
      'code',
      'local_state_corrupt',
    ),
  ),
);

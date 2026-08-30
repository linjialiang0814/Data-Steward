import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import 'session_projection.dart';
import 'shared_session_errors.dart';

final class FileCursorStore implements ResettableCursorStore {
  FileCursorStore(this.directory);

  final Directory directory;
  Future<void> _writeTail = Future<void>.value();

  @override
  Future<int> read(String conversationId) async {
    final paths = _paths(conversationId);
    final finalExists = await paths.finalFile.exists();
    final backupExists = await paths.backupFile.exists();
    if (!finalExists && !backupExists) return 0;

    _CursorRecord? finalRecord;
    _CursorRecord? backupRecord;
    try {
      if (finalExists) {
        finalRecord = await _readRecord(
          paths.finalFile,
          paths.conversationHash,
        );
      }
      if (backupExists) {
        backupRecord = await _readRecord(
          paths.backupFile,
          paths.conversationHash,
        );
      }
    } on Object {
      throw const ProjectionException('local_state_corrupt');
    }
    if (finalRecord != null && backupRecord != null) {
      if (finalRecord.sequence != backupRecord.sequence) {
        throw const ProjectionException('local_state_corrupt');
      }
      return finalRecord.sequence;
    }
    if (finalRecord != null) return finalRecord.sequence;
    if (backupRecord != null) {
      await directory.create(recursive: true);
      await backupRecord.file.rename(paths.finalFile.path);
      return backupRecord.sequence;
    }
    throw const ProjectionException('local_state_corrupt');
  }

  @override
  Future<void> write(String conversationId, int conversationSeq) {
    if (conversationSeq < 0) {
      throw const ProjectionException('local_state_corrupt');
    }
    final operation = _writeTail.then(
      (_) => _write(conversationId, conversationSeq),
    );
    _writeTail = operation.catchError((_) {});
    return operation;
  }

  @override
  Future<void> reset(String conversationId) async {
    await _writeTail;
    final paths = _paths(conversationId);
    for (final file in <File>[
      paths.nextFile,
      paths.finalFile,
      paths.backupFile,
    ]) {
      if (await file.exists()) await file.delete();
    }
  }

  Future<void> _write(String conversationId, int sequence) async {
    final current = await read(conversationId);
    if (sequence < current) {
      throw const ProjectionException('cursor_regression');
    }
    if (sequence == current) return;

    final paths = _paths(conversationId);
    await directory.create(recursive: true);
    final content = _encode(paths.conversationHash, sequence);
    final sink = paths.nextFile.openWrite(mode: FileMode.writeOnly);
    sink.write(content);
    await sink.flush();
    await sink.close();

    if (await paths.backupFile.exists()) await paths.backupFile.delete();
    if (await paths.finalFile.exists()) {
      await paths.finalFile.rename(paths.backupFile.path);
    }
    try {
      await paths.nextFile.rename(paths.finalFile.path);
      if (await paths.backupFile.exists()) await paths.backupFile.delete();
    } on Object {
      throw const ProjectionException('local_state_corrupt');
    }
  }

  Future<_CursorRecord> _readRecord(File file, String expectedHash) async {
    final bytes = await file.readAsBytes();
    if (bytes.length > 4096) {
      throw const ProjectionException('local_state_corrupt');
    }
    final decoded = jsonDecode(utf8.decode(bytes, allowMalformed: false));
    if (decoded is! Map<String, dynamic> ||
        decoded.keys.toSet().length != 4 ||
        !decoded.keys.toSet().containsAll(const <String>{
          'schema_version',
          'conversation_id_sha256',
          'conversation_seq',
          'checksum_sha256',
        })) {
      throw const ProjectionException('local_state_corrupt');
    }
    final schema = decoded['schema_version'];
    final conversationHash = decoded['conversation_id_sha256'];
    final sequence = decoded['conversation_seq'];
    final checksum = decoded['checksum_sha256'];
    if (schema != 'data-steward.cursor/v1' ||
        conversationHash != expectedHash ||
        sequence is! int ||
        sequence < 0 ||
        checksum is! String ||
        !RegExp(r'^[0-9a-f]{64}$').hasMatch(checksum)) {
      throw const ProjectionException('local_state_corrupt');
    }
    final expectedChecksum = _checksum(expectedHash, sequence);
    if (checksum != expectedChecksum) {
      throw const ProjectionException('local_state_corrupt');
    }
    return _CursorRecord(file, sequence);
  }

  _CursorPaths _paths(String conversationId) {
    final hash = sha256.convert(utf8.encode(conversationId)).toString();
    final base = '${directory.path}/cursor-$hash.json';
    return _CursorPaths(
      conversationHash: hash,
      finalFile: File(base),
      nextFile: File('$base.next'),
      backupFile: File('$base.backup'),
    );
  }

  String _encode(String conversationHash, int sequence) {
    final value = <String, Object>{
      'schema_version': 'data-steward.cursor/v1',
      'conversation_id_sha256': conversationHash,
      'conversation_seq': sequence,
      'checksum_sha256': _checksum(conversationHash, sequence),
    };
    return jsonEncode(value);
  }

  String _checksum(String conversationHash, int sequence) {
    final stable = jsonEncode(<String, Object>{
      'conversation_id_sha256': conversationHash,
      'conversation_seq': sequence,
      'schema_version': 'data-steward.cursor/v1',
    });
    return sha256.convert(utf8.encode(stable)).toString();
  }
}

final class _CursorPaths {
  const _CursorPaths({
    required this.conversationHash,
    required this.finalFile,
    required this.nextFile,
    required this.backupFile,
  });

  final String conversationHash;
  final File finalFile;
  final File nextFile;
  final File backupFile;
}

final class _CursorRecord {
  const _CursorRecord(this.file, this.sequence);

  final File file;
  final int sequence;
}

import 'dart:convert';

import 'pairing_errors.dart';

Object? decodeStrictJson(String source, {int maxUtf8Bytes = 16384}) {
  if (utf8.encode(source).length > maxUtf8Bytes) {
    securePairingFailure('payload_too_large', PairingFailureKind.permanent);
  }
  try {
    return _StrictJsonParser(source).parse();
  } on SecurePairingException {
    rethrow;
  } on Object {
    securePairingFailure(
      'protocol_integrity_error',
      PairingFailureKind.integrity,
    );
  }
}

Map<String, Object?> decodeStrictJsonObject(
  String source, {
  int maxUtf8Bytes = 16384,
}) {
  final value = decodeStrictJson(source, maxUtf8Bytes: maxUtf8Bytes);
  if (value is! Map<String, Object?>) {
    securePairingFailure(
      'protocol_integrity_error',
      PairingFailureKind.integrity,
    );
  }
  return value;
}

void requireExactKeys(Map<String, Object?> value, Set<String> expected) {
  if (value.length != expected.length ||
      !value.keys.toSet().containsAll(expected)) {
    securePairingFailure(
      'protocol_integrity_error',
      PairingFailureKind.integrity,
    );
  }
}

final class _StrictJsonParser {
  _StrictJsonParser(this.source);

  final String source;
  int index = 0;

  Object? parse() {
    _space();
    final value = _value();
    _space();
    if (index != source.length) _fail();
    return value;
  }

  Object? _value() {
    _space();
    if (index >= source.length) _fail();
    return switch (source.codeUnitAt(index)) {
      0x7B => _object(),
      0x5B => _array(),
      0x22 => _string(),
      0x74 => _literal('true', true),
      0x66 => _literal('false', false),
      0x6E => _literal('null', null),
      _ => _number(),
    };
  }

  Map<String, Object?> _object() {
    index++;
    final result = <String, Object?>{};
    _space();
    if (_take(0x7D)) return result;
    while (true) {
      _space();
      if (index >= source.length || source.codeUnitAt(index) != 0x22) _fail();
      final key = _string();
      if (result.containsKey(key)) _fail();
      _space();
      if (!_take(0x3A)) _fail();
      result[key] = _value();
      _space();
      if (_take(0x7D)) return result;
      if (!_take(0x2C)) _fail();
    }
  }

  List<Object?> _array() {
    index++;
    final result = <Object?>[];
    _space();
    if (_take(0x5D)) return result;
    while (true) {
      result.add(_value());
      _space();
      if (_take(0x5D)) return result;
      if (!_take(0x2C)) _fail();
    }
  }

  String _string() {
    final start = index;
    index++;
    var escaped = false;
    while (index < source.length) {
      final c = source.codeUnitAt(index++);
      if (c == 0x22 && !escaped) {
        final token = source.substring(start, index);
        final decoded = jsonDecode(token);
        if (decoded is! String) _fail();
        return decoded;
      }
      if (c < 0x20) _fail();
      if (escaped) {
        if (!const {
          0x22,
          0x5C,
          0x2F,
          0x62,
          0x66,
          0x6E,
          0x72,
          0x74,
          0x75,
        }.contains(c)) {
          _fail();
        }
        if (c == 0x75) {
          if (index + 4 > source.length ||
              !RegExp(
                r'^[0-9a-fA-F]{4}$',
              ).hasMatch(source.substring(index, index + 4))) {
            _fail();
          }
          index += 4;
        }
        escaped = false;
      } else {
        escaped = c == 0x5C;
      }
    }
    _fail();
  }

  Object? _literal(String text, Object? value) {
    if (!source.startsWith(text, index)) _fail();
    index += text.length;
    return value;
  }

  num _number() {
    final remaining = source.substring(index);
    final match = RegExp(
      r'^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?',
    ).firstMatch(remaining);
    if (match == null) _fail();
    final token = match.group(0)!;
    index += token.length;
    final value = num.parse(token);
    if (!value.isFinite) _fail();
    return value;
  }

  bool _take(int codeUnit) {
    if (index < source.length && source.codeUnitAt(index) == codeUnit) {
      index++;
      return true;
    }
    return false;
  }

  void _space() {
    while (index < source.length &&
        const {0x20, 0x09, 0x0A, 0x0D}.contains(source.codeUnitAt(index))) {
      index++;
    }
  }

  Never _fail() => securePairingFailure(
    'protocol_integrity_error',
    PairingFailureKind.integrity,
  );
}

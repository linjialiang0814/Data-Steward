import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:steward_app/main.dart';
import 'package:steward_app/saf_bridge.dart';

void main() {
  testWidgets('initial state is not authorized and keeps baseline texts', (
    tester,
  ) async {
    final bridge = FakeSafBridge();
    await pumpSafApp(tester, bridge);

    expect(find.text('Data Steward'), findsWidgets);
    expect(find.text('Environment Ready'), findsOneWidget);
    expect(find.text('SAF 独立验证环境'), findsOneWidget);
    expect(find.text('Android SAF 风险验证页（非最终产品）'), findsOneWidget);
    expect(find.text('授权状态：未授权'), findsOneWidget);
    expect(actionButton(tester, '写入/覆盖探针').onPressed, isNull);
    expect(actionButton(tester, '读取探针').onPressed, isNull);
    expect(actionButton(tester, '删除探针').onPressed, isNull);
  });

  testWidgets('picker cancellation is stable and explicit', (tester) async {
    final bridge = FakeSafBridge(
      selectFailure: const SafFailure('picker_cancelled'),
    );
    await pumpSafApp(tester, bridge);

    await tester.tap(find.text('选择专用目录'));
    await tester.pumpAndSettle();

    expect(find.text('授权状态：选择器已取消'), findsOneWidget);
    expect(find.text('安全错误：picker_cancelled'), findsOneWidget);
  });

  testWidgets('successful selection shows only sanitized permission data', (
    tester,
  ) async {
    final bridge = FakeSafBridge(selectResult: authorizedPermission());
    await pumpSafApp(tester, bridge);

    await tester.tap(find.text('选择专用目录'));
    await tester.pumpAndSettle();

    expect(find.text('授权状态：已授权'), findsOneWidget);
    expect(
      find.text('provider：com.android.externalstorage.documents'),
      findsOneWidget,
    );
    expect(find.text('脱敏 URI hash：ABCDEF012345'), findsOneWidget);
    expect(find.text('持久授权恢复：否'), findsOneWidget);
    expect(actionButton(tester, '写入/覆盖探针').onPressed, isNotNull);
  });

  testWidgets('persisted permission restoration is visible', (tester) async {
    final bridge = FakeSafBridge(
      permission: authorizedPermission(restored: true),
    );
    await pumpSafApp(tester, bridge);

    expect(find.text('授权状态：已授权'), findsOneWidget);
    expect(find.text('持久授权恢复：是'), findsOneWidget);
  });

  testWidgets('lost permission disables probe operations', (tester) async {
    final bridge = FakeSafBridge(
      permissionFailure: const SafFailure('permission_lost'),
    );
    await pumpSafApp(tester, bridge);

    expect(find.text('授权状态：权限失效'), findsOneWidget);
    expect(find.text('安全错误：permission_lost'), findsOneWidget);
    expect(actionButton(tester, '写入/覆盖探针').onPressed, isNull);
  });

  testWidgets('write success shows command ID and read-back hash', (
    tester,
  ) async {
    final bridge = FakeSafBridge(
      permission: authorizedPermission(),
      writeResult: const SafOperationResult(
        status: 'write_success',
        commandId: 'command-123',
        sha256: 'WRITEHASH',
      ),
    );
    await pumpSafApp(tester, bridge);

    await tester.tap(find.text('写入/覆盖探针'));
    await tester.pumpAndSettle();

    expect(find.text('授权状态：写入成功'), findsOneWidget);
    expect(find.text('command ID：command-123'), findsOneWidget);
    expect(find.text('读回 SHA-256：WRITEHASH'), findsOneWidget);
  });

  testWidgets('read success shows stored command and hash', (tester) async {
    final bridge = FakeSafBridge(
      permission: authorizedPermission(),
      readResult: const SafOperationResult(
        status: 'read_success',
        commandId: 'command-read',
        sha256: 'READHASH',
      ),
    );
    await pumpSafApp(tester, bridge);

    await tester.tap(find.text('读取探针'));
    await tester.pumpAndSettle();

    expect(find.text('授权状态：读取成功'), findsOneWidget);
    expect(find.text('command ID：command-read'), findsOneWidget);
    expect(find.text('读回 SHA-256：READHASH'), findsOneWidget);
  });

  testWidgets('delete success and already absent states are explicit', (
    tester,
  ) async {
    final bridge = FakeSafBridge(permission: authorizedPermission());
    await pumpSafApp(tester, bridge);

    await tester.tap(find.text('删除探针'));
    await tester.pumpAndSettle();
    expect(find.text('授权状态：删除成功'), findsOneWidget);

    bridge.deleteResult = const SafOperationResult(status: 'already_absent');
    await tester.tap(find.text('删除探针'));
    await tester.pumpAndSettle();
    expect(find.text('授权状态：探针已不存在'), findsOneWidget);
  });

  testWidgets('unsafe directory blocks further file operations', (
    tester,
  ) async {
    final bridge = FakeSafBridge(
      selectFailure: const SafFailure('unsafe_directory'),
    );
    await pumpSafApp(tester, bridge);

    await tester.tap(find.text('选择专用目录'));
    await tester.pumpAndSettle();

    expect(find.text('授权状态：安全错误'), findsOneWidget);
    expect(find.text('安全错误：unsafe_directory'), findsOneWidget);
    expect(actionButton(tester, '写入/覆盖探针').onPressed, isNull);
  });

  testWidgets('unsafe probe restoration shows ownership error', (tester) async {
    final bridge = FakeSafBridge(
      permissionFailure: const SafFailure('unsafe_probe'),
    );
    await pumpSafApp(tester, bridge);

    expect(find.text('授权状态：探针归属异常'), findsOneWidget);
    expect(find.text('安全错误：unsafe_probe'), findsOneWidget);
    expect(find.text('同名文件未通过归属校验，应用拒绝读取、覆盖或删除。'), findsOneWidget);
  });

  testWidgets('unsafe probe disables read write and delete operations', (
    tester,
  ) async {
    final bridge = FakeSafBridge(
      permission: authorizedPermission(),
      readFailure: const SafFailure('unsafe_probe'),
    );
    await pumpSafApp(tester, bridge);

    await tester.tap(find.text('读取探针'));
    await tester.pumpAndSettle();

    expect(actionButton(tester, '写入/覆盖探针').onPressed, isNull);
    expect(actionButton(tester, '读取探针').onPressed, isNull);
    expect(actionButton(tester, '删除探针').onPressed, isNull);
    expect(actionButton(tester, '选择专用目录').onPressed, isNotNull);
  });

  testWidgets('unsafe probe platform details never reach the UI', (
    tester,
  ) async {
    const channel = MethodChannel(safChannelName);
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(channel, (call) async {
      if (call.method == 'getPermissionState') {
        return <String, Object>{
          'authorized': true,
          'canRead': true,
          'canWrite': true,
          'restored': true,
          'provider': 'com.android.externalstorage.documents',
          'uriSha256': 'ABCDEF012345',
        };
      }
      if (call.method == 'readProbe') {
        throw PlatformException(
          code: 'unsafe_probe',
          message:
              r'forged-content content://provider/tree/private C:\Users\private',
        );
      }
      return <String, Object>{'status': 'already_absent'};
    });
    addTearDown(() {
      messenger.setMockMethodCallHandler(channel, null);
    });

    await tester.pumpWidget(
      const StewardApp(safBridge: MethodChannelSafBridge()),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.text('读取探针'));
    await tester.pumpAndSettle();

    expect(find.text('授权状态：探针归属异常'), findsOneWidget);
    expect(find.textContaining('forged-content'), findsNothing);
    expect(find.textContaining('content://'), findsNothing);
    expect(find.textContaining(r'C:\Users\private'), findsNothing);
  });

  testWidgets('selecting a safe directory clears unsafe probe block', (
    tester,
  ) async {
    final bridge = FakeSafBridge(
      permission: authorizedPermission(),
      readFailure: const SafFailure('unsafe_probe'),
      selectResult: authorizedPermission(),
    );
    await pumpSafApp(tester, bridge);

    await tester.tap(find.text('读取探针'));
    await tester.pumpAndSettle();
    expect(actionButton(tester, '写入/覆盖探针').onPressed, isNull);

    await tester.tap(find.text('选择专用目录'));
    await tester.pumpAndSettle();

    expect(find.text('授权状态：已授权'), findsOneWidget);
    expect(find.text('安全错误：unsafe_probe'), findsNothing);
    expect(actionButton(tester, '写入/覆盖探针').onPressed, isNotNull);
    expect(actionButton(tester, '读取探针').onPressed, isNotNull);
    expect(actionButton(tester, '删除探针').onPressed, isNotNull);
  });

  testWidgets('busy operation prevents duplicate actions', (tester) async {
    final completer = Completer<SafOperationResult>();
    final bridge = FakeSafBridge(
      permission: authorizedPermission(),
      writeCompleter: completer,
    );
    await pumpSafApp(tester, bridge);

    final callback = actionButton(tester, '写入/覆盖探针').onPressed!;
    callback();
    callback();
    await tester.pump();

    expect(bridge.writeCalls, 1);
    expect(actionButton(tester, '读取探针').onPressed, isNull);
    expect(find.byType(LinearProgressIndicator), findsOneWidget);

    completer.complete(
      const SafOperationResult(
        status: 'write_success',
        commandId: 'command-busy',
        sha256: 'BUSYHASH',
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('授权状态：写入成功'), findsOneWidget);
  });

  testWidgets('missing MethodChannel plugin reports unsupported', (
    tester,
  ) async {
    const channel = MethodChannel(safChannelName);
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(channel, (_) async {
      throw MissingPluginException();
    });
    addTearDown(() {
      messenger.setMockMethodCallHandler(channel, null);
    });

    await tester.pumpWidget(
      const StewardApp(safBridge: MethodChannelSafBridge()),
    );
    await tester.pumpAndSettle();

    expect(find.text('授权状态：当前平台不支持'), findsOneWidget);
    expect(find.text('安全错误：unsupported'), findsOneWidget);
  });

  testWidgets('UI never exposes content URI or absolute path', (tester) async {
    final bridge = FakeSafBridge(
      permission: authorizedPermission(restored: true),
    );
    await pumpSafApp(tester, bridge);

    expect(find.textContaining('content://'), findsNothing);
    expect(find.textContaining(r'C:\Users\example'), findsNothing);
    expect(find.textContaining('primary:Documents'), findsNothing);
  });
}

Future<void> pumpSafApp(WidgetTester tester, SafBridge bridge) async {
  await tester.pumpWidget(StewardApp(safBridge: bridge));
  await tester.pumpAndSettle();
}

FilledButton actionButton(WidgetTester tester, String label) {
  return tester.widget<FilledButton>(find.widgetWithText(FilledButton, label));
}

SafPermissionState authorizedPermission({bool restored = false}) {
  return SafPermissionState(
    authorized: true,
    canRead: true,
    canWrite: true,
    restored: restored,
    provider: 'com.android.externalstorage.documents',
    uriSha256: 'ABCDEF012345',
  );
}

class FakeSafBridge implements SafBridge {
  FakeSafBridge({
    this.permission = const SafPermissionState.notAuthorized(),
    this.permissionFailure,
    this.selectResult,
    this.selectFailure,
    this.writeResult = const SafOperationResult(status: 'write_success'),
    this.readResult = const SafOperationResult(status: 'read_success'),
    this.readFailure,
    this.deleteResult = const SafOperationResult(status: 'delete_success'),
    this.writeCompleter,
  });

  SafPermissionState permission;
  SafFailure? permissionFailure;
  SafPermissionState? selectResult;
  SafFailure? selectFailure;
  SafOperationResult writeResult;
  SafOperationResult readResult;
  SafFailure? readFailure;
  SafOperationResult deleteResult;
  Completer<SafOperationResult>? writeCompleter;
  int writeCalls = 0;

  @override
  Future<SafPermissionState> getPermissionState() async {
    final failure = permissionFailure;
    if (failure != null) {
      throw failure;
    }
    return permission;
  }

  @override
  Future<SafPermissionState> selectDirectory() async {
    final failure = selectFailure;
    if (failure != null) {
      throw failure;
    }
    return selectResult ?? authorizedPermission();
  }

  @override
  Future<SafOperationResult> writeProbe() {
    writeCalls += 1;
    return writeCompleter?.future ?? Future.value(writeResult);
  }

  @override
  Future<SafOperationResult> readProbe() async {
    final failure = readFailure;
    if (failure != null) {
      throw failure;
    }
    return readResult;
  }

  @override
  Future<SafOperationResult> deleteProbe() async => deleteResult;
}

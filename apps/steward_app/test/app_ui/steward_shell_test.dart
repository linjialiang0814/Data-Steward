import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:steward_app/app_ui/steward_home_page.dart';
import 'package:steward_app/app_ui/steward_shell.dart';
import 'package:steward_app/app_ui/steward_theme.dart';

const _destinations = <StewardShellDestination>[
  StewardShellDestination(
    label: '首页',
    icon: Icons.home_outlined,
    selectedIcon: Icons.home,
  ),
  StewardShellDestination(
    label: '会话',
    icon: Icons.forum_outlined,
    selectedIcon: Icons.forum,
  ),
  StewardShellDestination(
    label: '设备',
    icon: Icons.devices_outlined,
    selectedIcon: Icons.devices,
  ),
  StewardShellDestination(
    label: '记忆',
    icon: Icons.psychology_alt_outlined,
    selectedIcon: Icons.psychology_alt,
  ),
];

void main() {
  tearDown(() {
    TestWidgetsFlutterBinding.instance.platformDispatcher.clearAllTestValues();
  });

  testWidgets('mobile shell keeps draft while switching four destinations', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(360, 800);
    tester.view.devicePixelRatio = 1;
    await tester.pumpWidget(
      MaterialApp(theme: StewardTheme.light(), home: const _ShellHarness()),
    );

    expect(find.byType(NavigationBar), findsOneWidget);
    expect(find.byType(NavigationRail), findsNothing);
    await tester.enterText(find.byKey(const Key('shell-draft')), '保留的会话草稿');
    await tester.tap(find.text('会话'));
    await tester.pump();
    expect(find.text('会话内容'), findsOneWidget);
    await tester.tap(find.text('首页'));
    await tester.pump();
    expect(find.text('保留的会话草稿'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('shell is responsive at 800 and 1440 with 1.3 text scale', (
    tester,
  ) async {
    for (final size in [const Size(800, 600), const Size(1440, 900)]) {
      tester.view.physicalSize = size;
      tester.view.devicePixelRatio = 1;
      await tester.pumpWidget(
        MaterialApp(
          theme: StewardTheme.light(),
          darkTheme: StewardTheme.dark(),
          themeMode: ThemeMode.dark,
          builder: (context, child) => MediaQuery(
            data: MediaQuery.of(
              context,
            ).copyWith(textScaler: const TextScaler.linear(1.3)),
            child: child!,
          ),
          home: const _ShellHarness(),
        ),
      );
      await tester.pump();
      expect(
        find.byType(size.width >= 920 ? NavigationRail : NavigationBar),
        findsOneWidget,
      );
      expect(
        Theme.of(tester.element(find.byType(Scaffold).first)).brightness,
        Brightness.dark,
      );
      expect(tester.takeException(), isNull);
    }
  });

  testWidgets('home exposes product actions and honest memory entry', (
    tester,
  ) async {
    var session = 0;
    var today = 0;
    var memory = 0;
    var diagnostics = 0;
    String? intent;
    await tester.pumpWidget(
      MaterialApp(
        theme: StewardTheme.light(),
        home: StewardHomePage(
          connectionLabel: '电脑已安全连接',
          connectionTone: StewardStatusTone.positive,
          onOpenSession: () => session += 1,
          onOpenToday: () => today += 1,
          onOpenMemory: () => memory += 1,
          onStartIntent: (value) => intent = value,
          onOpenDiagnostics: () => diagnostics += 1,
        ),
      ),
    );

    expect(find.text('你的资料，始终由你掌控'), findsOneWidget);
    expect(find.text('生成跨设备资料包'), findsOneWidget);
    await tester.tap(find.text('进入智能会话'));
    await tester.tap(find.text('汇总今日跨设备资料'));
    expect(intent, contains('汇总今天'));
    await tester.tap(find.text('今日资料'));
    await tester.tap(find.text('暂无新建议'));
    await tester.tap(find.text('尚未形成习惯'));
    await tester.tap(find.byKey(const Key('open-developer-diagnostics')));
    expect((session, today, memory, diagnostics), (1, 2, 1, 1));
  });

  testWidgets('home renders a one-shot live overview snapshot', (tester) async {
    var loads = 0;
    await tester.pumpWidget(
      MaterialApp(
        theme: StewardTheme.light(),
        home: StewardHomePage(
          connectionLabel: '安全在线',
          connectionTone: StewardStatusTone.positive,
          onOpenSession: () {},
          onOpenToday: () {},
          onOpenMemory: () {},
          onStartIntent: (_) {},
          snapshotLoader: () async {
            loads += 1;
            return const StewardHomeSnapshot(
              todayLabel: '7 项资料',
              pendingLabel: '1 项建议',
              memoryLabel: '1 个已启用习惯',
            );
          },
          snapshotKey: 'snapshot-1',
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(loads, 1);
    expect(find.text('7 项资料'), findsOneWidget);
    expect(find.text('1 项建议'), findsOneWidget);
    expect(find.text('1 个已启用习惯'), findsOneWidget);
  });

  testWidgets('home coalesces an explicit newer snapshot while loading', (
    tester,
  ) async {
    final first = Completer<StewardHomeSnapshot>();
    var loads = 0;

    Future<StewardHomeSnapshot> load() {
      loads += 1;
      if (loads == 1) return first.future;
      return Future.value(
        const StewardHomeSnapshot(
          todayLabel: '8 项最新资料',
          pendingLabel: '暂无新建议',
          memoryLabel: '1 个已启用习惯',
        ),
      );
    }

    Widget app(String key) => MaterialApp(
      home: StewardHomePage(
        connectionLabel: '安全在线',
        connectionTone: StewardStatusTone.positive,
        onOpenSession: () {},
        onOpenToday: () {},
        onOpenMemory: () {},
        onStartIntent: (_) {},
        snapshotLoader: load,
        snapshotKey: key,
      ),
    );

    await tester.pumpWidget(app('old'));
    await tester.pump();
    await tester.pumpWidget(app('new'));
    first.complete(
      const StewardHomeSnapshot(
        todayLabel: '7 项旧资料',
        pendingLabel: '1 条旧建议',
        memoryLabel: '旧记忆',
      ),
    );
    await tester.pumpAndSettle();

    expect(loads, 2);
    expect(find.text('8 项最新资料'), findsOneWidget);
    expect(find.text('7 项旧资料'), findsNothing);
  });

  testWidgets('home clears a snapshot when its trusted identity changes', (
    tester,
  ) async {
    Widget app({
      required String? identity,
      required String key,
      required StewardHomeSnapshotLoader? loader,
    }) => MaterialApp(
      home: StewardHomePage(
        connectionLabel: '安全状态',
        connectionTone: StewardStatusTone.neutral,
        onOpenSession: () {},
        onOpenToday: () {},
        onOpenMemory: () {},
        onStartIntent: (_) {},
        snapshotLoader: loader,
        snapshotIdentityKey: identity,
        snapshotKey: key,
      ),
    );

    await tester.pumpWidget(
      app(
        identity: 'hub-a:device-a:1',
        key: 'hub-a:device-a:1:0',
        loader: () async => const StewardHomeSnapshot(
          todayLabel: '7 项旧设备资料',
          pendingLabel: '1 条旧设备建议',
          memoryLabel: '旧设备习惯',
        ),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('7 项旧设备资料'), findsOneWidget);

    await tester.pumpWidget(
      app(
        identity: 'hub-b:device-b:1',
        key: 'hub-b:device-b:1:0',
        loader: () => Future<StewardHomeSnapshot>.error(
          StateError('new identity unavailable'),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('7 项旧设备资料'), findsNothing);
    expect(find.text('暂不可用'), findsOneWidget);
    expect(find.text('尚未形成习惯'), findsOneWidget);
  });

  testWidgets('home clears a snapshot when pairing becomes unavailable', (
    tester,
  ) async {
    Widget app({
      required String? identity,
      required StewardHomeSnapshotLoader? loader,
    }) => MaterialApp(
      home: StewardHomePage(
        connectionLabel: '安全状态',
        connectionTone: StewardStatusTone.neutral,
        onOpenSession: () {},
        onOpenToday: () {},
        onOpenMemory: () {},
        onStartIntent: (_) {},
        snapshotLoader: loader,
        snapshotIdentityKey: identity,
        snapshotKey: identity,
      ),
    );

    await tester.pumpWidget(
      app(
        identity: 'hub-a:device-a:1',
        loader: () async => const StewardHomeSnapshot(
          todayLabel: '7 项旧设备资料',
          pendingLabel: '1 条旧设备建议',
          memoryLabel: '旧设备习惯',
        ),
      ),
    );
    await tester.pumpAndSettle();
    await tester.pumpWidget(app(identity: null, loader: null));
    await tester.pump();

    expect(find.text('7 项旧设备资料'), findsNothing);
    expect(find.text('暂不可用'), findsOneWidget);
  });

  testWidgets(
    'home preserves the last snapshot on same-identity refresh failure',
    (tester) async {
      Widget app(String key, StewardHomeSnapshotLoader loader) => MaterialApp(
        home: StewardHomePage(
          connectionLabel: '安全在线',
          connectionTone: StewardStatusTone.positive,
          onOpenSession: () {},
          onOpenToday: () {},
          onOpenMemory: () {},
          onStartIntent: (_) {},
          snapshotLoader: loader,
          snapshotIdentityKey: 'hub-a:device-a:1',
          snapshotKey: key,
        ),
      );

      await tester.pumpWidget(
        app(
          'refresh-1',
          () async => const StewardHomeSnapshot(
            todayLabel: '7 项可信资料',
            pendingLabel: '暂无新建议',
            memoryLabel: '1 个已启用习惯',
          ),
        ),
      );
      await tester.pumpAndSettle();
      await tester.pumpWidget(
        app(
          'refresh-2',
          () => Future<StewardHomeSnapshot>.error(StateError('offline')),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('7 项可信资料'), findsOneWidget);
      expect(find.text('1 个已启用习惯'), findsOneWidget);
    },
  );
}

class _ShellHarness extends StatefulWidget {
  const _ShellHarness();

  @override
  State<_ShellHarness> createState() => _ShellHarnessState();
}

class _ShellHarnessState extends State<_ShellHarness> {
  var index = 0;

  @override
  Widget build(BuildContext context) => StewardAdaptiveShell(
    selectedIndex: index,
    onDestinationSelected: (value) => setState(() => index = value),
    destinations: _destinations,
    statusLabel: '电脑已安全连接',
    statusTone: StewardStatusTone.positive,
    pages: const [
      Scaffold(
        body: Center(child: TextField(key: Key('shell-draft'))),
      ),
      Scaffold(body: Center(child: Text('会话内容'))),
      Scaffold(body: Center(child: Text('设备内容'))),
      Scaffold(body: Center(child: Text('记忆内容'))),
    ],
  );
}

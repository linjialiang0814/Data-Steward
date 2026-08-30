import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../pairing_ui/pairing_host_page.dart';
import '../shared_session_ui/device_authorization_panel.dart';
import '../shared_session_ui/pc_file_scope_panel.dart';
import '../shared_session_ui/windows_c3_bootstrap.dart';
import 'steward_theme.dart';

class WindowsDeviceCenterPage extends StatefulWidget {
  const WindowsDeviceCenterPage({required this.workspace, super.key});

  final WindowsC3Workspace? workspace;

  @override
  State<WindowsDeviceCenterPage> createState() =>
      _WindowsDeviceCenterPageState();
}

class _WindowsDeviceCenterPageState extends State<WindowsDeviceCenterPage> {
  var _section = 0;

  @override
  Widget build(BuildContext context) {
    final workspace = widget.workspace;
    return Scaffold(
      appBar: AppBar(title: const Text('设备中心')),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 4, 20, 12),
            child: SegmentedButton<int>(
              segments: const [
                ButtonSegment(
                  value: 0,
                  icon: Icon(Icons.add_link),
                  label: Text('连接设备'),
                ),
                ButtonSegment(
                  value: 1,
                  icon: Icon(Icons.admin_panel_settings_outlined),
                  label: Text('授权管理'),
                ),
              ],
              selected: {_section},
              onSelectionChanged: (value) =>
                  setState(() => _section = value.single),
            ),
          ),
          Expanded(
            child: IndexedStack(
              index: _section,
              children: [
                PairingHostPage(
                  embedded: true,
                  sharedHubConnection: switch (workspace) {
                    final value? => PairingHostConnection(
                      controlUrl: value.ready.localUrl,
                      advertisedUrl: value.ready.serviceUrl,
                      certFingerprint: value.ready.certFingerprint,
                      operatorToken: value.ready.operatorToken,
                    ),
                    null => null,
                  },
                ),
                _AuthorizationCenter(workspace: workspace),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _AuthorizationCenter extends StatelessWidget {
  const _AuthorizationCenter({required this.workspace});

  final WindowsC3Workspace? workspace;

  @override
  Widget build(BuildContext context) {
    final value = workspace;
    if (value == null) {
      return const Center(
        child: Padding(
          padding: EdgeInsets.all(24),
          child: Text('安全 Hub 启动后即可管理设备授权与 PC 文件范围。'),
        ),
      );
    }
    return ListView(
      padding: const EdgeInsets.fromLTRB(24, 8, 24, 32),
      children: [
        Card(
          child: ListTile(
            leading: Icon(
              value.ready.lanDiscoveryAvailable
                  ? Icons.wifi_find
                  : Icons.wifi_off_outlined,
            ),
            title: Text(
              value.ready.lanDiscoveryAvailable ? '已发布局域网发现服务' : '自动发现暂不可用',
            ),
            subtitle: Text(
              value.ready.lanDiscoveryAvailable
                  ? '支持的手机可先验证电脑身份并自动更新地址；若发现受限，请使用下方服务码。'
                  : '仍可使用下方服务码更新地址；不会清除设备凭据或扩大权限。',
            ),
          ),
        ),
        const SizedBox(height: StewardSpacing.sm),
        Card(
          child: ExpansionTile(
            leading: const Icon(Icons.qr_code_2),
            title: const Text('更新已配对手机的电脑地址'),
            subtitle: const Text('网络地址变化且自动发现失败时使用；无需重新配对'),
            childrenPadding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
            children: [
              Wrap(
                spacing: 24,
                runSpacing: 16,
                crossAxisAlignment: WrapCrossAlignment.center,
                children: [
                  QrImageView(
                    key: const Key('s4-service-address-qr'),
                    data: value.ready.serviceDescriptorJson,
                    size: 148,
                    backgroundColor: Colors.white,
                  ),
                  const SizedBox(
                    width: 360,
                    child: Text(
                      '服务码仅包含局域网地址、Hub 标识与证书指纹。'
                      '它不会生成新长期凭据，也不会扩大设备权限。',
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
        const SizedBox(height: StewardSpacing.sm),
        DeviceAuthorizationPanel(controller: value.authorizationController),
        const SizedBox(height: StewardSpacing.sm),
        PcFileScopePanel(controller: value.fileScopeController),
      ],
    );
  }
}

# Data Steward APP Demo 最终交付包

> 状态：S6-G 合并后交付收口  
> 更新日期：2026-08-06  
> 交付类型：Windows + Android APP Demo

## 1. 交付口径

最终交付包包含：

- Windows Flutter Release 完整运行目录；
- Android Release APK；
- 与 Git commit 绑定的 `manifest.json`；
- 包内逐文件 `SHA256SUMS.txt` 与外层 ZIP SHA-256。

Android APK 使用 Android Debug 证书签名，仅用于训练营 Demo 安装，不宣称为应用商店生产签名。Windows 的完整跨设备能力仍依赖仓库内受控启动的本地 Hub、Hermes 运行时、Python 虚拟环境和 LocalAppData TLS 身份；这些机器绑定资源不会进入交付 ZIP。

## 2. 安全边界

打包前必须满足：

- Git 工作区和暂存区为空；
- Windows/Android 产物与本轮审计 SHA-256 完全一致；
- Windows bundle 不含 PDB、ILK、LIB、EXP 或重解析点；
- Android APK 通过 `apksigner verify` 与 `aapt dump badging`；
- 产物不含开发者个人路径、真实模型 endpoint、API Key、TLS 私钥或禁止存储权限；
- 不打包 `.venv`、SQLite/WAL/SHM、LocalAppData 身份、用户资料、缓存和日志。

为了避免 Flutter AOT 产物记录开发者用户目录，两端 Release 均从带严格 CurrentUser/SYSTEM/Administrators ACL 的一次性中性路径构建；只复制最终产物后精确删除临时源码目录。

## 3. 生成方式

在仓库根目录、工作区干净且最终 Release 产物已经通过审计后执行：

```powershell
.\tool\package_app_demo.ps1
```

脚本输出到被 Git 忽略的 `dist/`，且已有同名包时 fail-closed，不会覆盖历史交付物。

## 4. 运行方式

Android：安装包内 `android/DataSteward-Android-Demo.apk`。

Windows：完整复制包内 `windows/` 目录。仅查看 Flutter UI 可直接启动 `steward_app.exe`；完整安全配对、目录、共享会话、记忆与 Hermes 能力应在已准备好的源码工作区中通过以下脚本启动：

```powershell
.\apps\steward_app\tool\start_c3_windows_demo.ps1 `
  -HermesProvider volcengine `
  -HermesModel '<your-endpoint-id>'
```

Provider 凭据只设置在当前 PowerShell 进程环境中，不写入脚本、仓库或交付包。

## 5. 明确不属于本交付

- Windows MSI/MSIX 安装器或自包含 Python/Hermes sidecar；
- Android 商店生产签名；
- API Key、模型 endpoint、真实个人资料或持久 TLS 私钥；
- Pad/iOS、录音转写、扫描 PDF OCR、向量数据库和跨设备写入 Saga。

## 6. 辅助提交资料

除 APP Demo ZIP 外，交付目录还应放置：

- 独立的 `DataSteward-安装与使用指南.docx`，包含新电脑/手机安装、完整模式配置、安全配对、目录授权、自然语言示例、Action Card、记忆与故障排查；
- `DataSteward-Project-Documents-<commit>.zip`，按项目与产品、架构与协议、安全与验证、执行过程四类整理参考资料；
- 提交目录级 SHA-256 清单。

安装指南不嵌入参考资料 ZIP，便于评审者直接打开。参考资料包通过 `tool/package_submission_docs.ps1` 生成，并对 Windows 用户目录、私网 IPv4 和模型 endpoint ID 做副本级脱敏；源文档保持不变。

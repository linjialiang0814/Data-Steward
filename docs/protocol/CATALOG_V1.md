# Data Steward Catalog V1

> 状态：`S5-A CONTRACT ACCEPTED / LOCAL GATE ONLY`  
> Schema：`data-steward.catalog-state/v1`、`data-steward.catalog-snapshot/v1`

## 1. 目的与边界

Catalog V1 定义 Windows 与 Android 授权资料目录进入统一目录前的本地资产投影。S5-A 只实现 Android 本地 Gate；不上传 Hub、不读取正文、不调用 Provider、不迁移设备 capability，也不修改文件。

现有 `io.datasteward.app/saf` 与 `DataStewardDemo` 固定探针协议保持不变。资料目录使用独立通道 `io.datasteward.app/catalog`、独立 Preferences 和独立 Android Keystore HMAC key，不允许复用或放宽探针目录的空目录语义。

## 2. 安全不变量

1. 目录必须由用户通过 `ACTION_OPEN_DOCUMENT_TREE` 明确选择；只持久化 read grant；
2. 只枚举授权根目录的直接子项；目录和 `FLAG_VIRTUAL_DOCUMENT` 项被计数后跳过；
3. 原始 tree/document URI 只保存在 Android 应用私有存储，不进入 Dart、UI、日志、证据、Hub 或 Provider；
4. `catalogRootId` 与 `locatorToken` 使用 Android Keystore Current App HMAC-SHA256 派生，格式为 64 位小写十六进制；
5. 一次快照最多读取 512 个 provider 行，投影前元数据最多 512 KiB，私有 locator map 最多 768 KiB；
6. 重复 document locator、token collision、非法名称/MIME、负数大小/时间、provider cursor 异常全部 fail-closed；
7. S5-A 固定 `contentAnalysisEnabled=false`，不得打开正文；
8. 忘记目录只清除授权记录和 locator map、释放可释放的 read grant，不删除或修改任何用户文件。

## 3. 本地 MethodChannel

### 3.1 `getCatalogState`

输入：无。

未授权响应：

```json
{
  "schemaVersion": "data-steward.catalog-state/v1",
  "status": "not_authorized",
  "authorized": false,
  "canRead": false,
  "restored": false,
  "contentAnalysisEnabled": false
}
```

已授权响应额外包含：

```json
{
  "status": "authorized",
  "authorized": true,
  "canRead": true,
  "restored": true,
  "provider": "com.android.externalstorage.documents",
  "catalogRootId": "<64 lowercase hex>",
  "contentAnalysisEnabled": false
}
```

恢复时必须重新确认 persisted read grant、根 document 仍为目录、根 ID 与 Keystore HMAC 一致。任一不符都不返回授权成功。

### 3.2 `selectCatalogDirectory`

由 Activity 启动系统目录选择器。资料目录只请求 read + persistable + prefix flags；旧 SAF probe 仍单独请求 read/write。两个 picker 共用一个 busy gate，不能并行打开。

禁止选择明显的外部存储卷根。选择新目录成功后原资料目录 read grant 尽力释放；提交本地新状态失败则释放新 grant 并返回安全错误。

### 3.3 `buildCatalogSnapshot`

响应：

```json
{
  "schemaVersion": "data-steward.catalog-snapshot/v1",
  "catalogRootId": "<64 lowercase hex>",
  "snapshotSha256": "<64 lowercase hex>",
  "generatedAtMillis": 0,
  "itemCount": 0,
  "skippedCount": 0,
  "contentAnalysisEnabled": false,
  "items": []
}
```

每个 item 精确包含：

```json
{
  "locatorToken": "<64 lowercase hex>",
  "displayName": "课堂笔记.md",
  "extension": "md",
  "mimeFamily": "text",
  "sizeBytes": 123,
  "modifiedAtMillis": 1785805200000,
  "revision": "<64 lowercase hex>",
  "contentEligible": true
}
```

`sizeBytes` 与 `modifiedAtMillis` 可为 `null`；存在时必须非负。`contentEligible` 只表示格式可能在 S5-D 支持，不代表已读取或已同意内容分析。

允许的 `mimeFamily`：`image/audio/video/text/document/archive/other`。名称 NFC 规范化、UTF-8 不超过 255 字节，不得为空、`.`、`..`，不得包含控制字符、路径分隔符、零宽方向字符或双向文本覆盖字符。

item 按 `locatorToken` 升序。Android 生成 `snapshotSha256`，Dart 使用相同 canonical projection 重新计算；字段、顺序、计数或 hash 不一致即 `protocol_integrity_error`。

Canonical field 编码为 UTF-8 字节长度、冒号与正文：`<byte_length>:<value>`。顺序为：

1. snapshot schema、catalog root ID；
2. 每个 item 的 locator token、display name、extension、mime family、size 或 `null`、modified 或 `null`、revision、content eligible；
3. `skipped` 与 skipped count；
4. 每组 fields 末尾换行；整体 SHA-256 小写十六进制。

### 3.4 `forgetCatalogDirectory`

返回 `status=forgotten` 和 `permissionReleased`。即使 provider 已经收回授权，本地记录仍可安全忘记；`permissionReleased=false` 不能被解释为文件删除失败，因为本操作从不删除文件。

## 4. 错误码

| Code | 含义 |
|---|---|
| `unsupported` | 平台或系统 picker 不可用 |
| `picker_cancelled` | 用户取消；旧授权不变 |
| `busy` | 已有 picker/操作进行中 |
| `not_authorized` | 尚未授权资料目录 |
| `invalid_directory` | 非 tree URI、非目录或明显存储卷根 |
| `permission_lost` | persisted read grant 不可用 |
| `catalog_state_corrupt` | 本地 URI/root ID/Keystore 绑定异常 |
| `catalog_too_large` | 行数、元数据或 locator map 超限 |
| `catalog_duplicate_entry` | provider 返回重复 locator 或 token collision |
| `catalog_invalid_entry` | provider 返回非法名称、MIME、ID、大小或时间 |
| `protocol_integrity_error` | Dart 二次校验不通过；只在 Dart 层产生 |
| `io_error` | 其他脱敏 I/O 失败 |

Platform exception 的 message/details 不进入 Flutter 状态或 UI；未知 native code 统一映射为 `io_error`。

## 5. Capability 预留

Catalog V1 冻结两个后续 capability，但 S5-A 不修改当前手机请求或 grant：

- `catalog.sync`：把授权目录的受控元数据上传到已认证 Hub；不含正文和写能力；
- `content.analyze`：在 per-root 用户开关开启后读取有界内容，并允许进入受控 AI 理解流程；不含写能力。

S5-B 才允许通过迁移式安全配对请求 `catalog.sync`；S5-D 才允许请求 `content.analyze`。服务端不得因为客户端升级而静默扩大旧 credential 的 requested/granted capabilities。

## 6. S5-B 扩展点

S5-B 在不改变本地快照投影的前提下增加设备认证、`catalog_seq`、批量同步、Hub snapshot/asset/tombstone 存储和 Android 持久 outbox。原始 locator 映射继续留在设备侧；Hub 只能把不透明 token 路由回拥有该文件的设备 Executor。

# Catalog Sync V1

## 1. 用途

Catalog Sync V1 用于在受信任 Hub 中汇总多设备已授权目录的 metadata-only 文件清单。
协议不传输文件正文、绝对路径、Android content URI 或用户凭据。

## 2. 权限与传输

- LAN 路由必须使用现有 HTTPS certificate pinning 和设备凭据认证。
- 所有 `/v1/catalog/*` 请求要求已激活的 `catalog.sync` capability。
- 设备撤销、能力降级或 capability epoch 过期必须 fail-closed。
- Windows operator 路由仅绑定 loopback，不作为手机可访问的公开 API。

## 3. 数据模型

### Catalog root

- `catalog_version`：固定为 `1`。
- `device_id`：已认证设备 ID；Windows 使用 Hub identity 的稳定投影。
- `root_id`：设备内稳定、不可逆的 64 位小写十六进制摘要。
- `display_name`：安全展示名，不得包含绝对路径。
- `platform`：`android` 或 `windows`。
- `sequence`：Hub 为该 root 分配的单调正整数。
- `snapshot_sha256`：规范化 snapshot JSON 的 SHA-256。
- `asset_count`、`skipped_count`、`captured_at`：受限统计与 UTC 时间。

### Catalog asset

- `locator_token`：设备内稳定的不可逆定位摘要，不可由 Hub 还原本地 URI/路径。
- `display_name`、`extension`、`size_bytes`、`modified_at`。
- 可选受控提示：`mime_type`、`media_kind`、`content_eligible`。
- `deleted`：完整快照收敛时由 Hub 生成的 tombstone 状态。

### Snapshot

- `base_sequence`：客户端提交前读取的服务端 watermark。
- `idempotency_key`：一次逻辑提交的稳定键。
- `snapshot_sha256`：覆盖 root 与按 locator 稳定排序的全部 assets。
- 同一幂等键和相同 payload 返回原 receipt；同一键不同 payload 拒绝。
- `base_sequence` 落后或超前均返回冲突，不静默覆盖其他提交。

## 4. HTTP 契约

### `POST /v1/catalog/snapshots`

提交一个完整 metadata-only snapshot。成功返回精确 receipt，包括 `device_id`、
`root_id`、`accepted_sequence`、`snapshot_sha256`、计数和是否去重。

### `GET /v1/catalog/roots`

返回当前认证设备可见的 root 摘要，包含平台、安全展示名、watermark、文件数和最后同步时间。

### `GET /v1/catalog/assets`

按稳定顺序返回统一资产 projection，最多 512 项，并返回 projection SHA-256。
响应不得包含 locator 的本地映射、绝对路径、URI、凭据、正文或内容摘要。

## 5. 严格校验

- JSON 顶层及嵌套对象均拒绝未知字段和重复 key。
- `Content-Type` 必须是 JSON；请求正文最大 768 KiB，总 deadline 为 10 秒。
- 单 snapshot 最多 512 个 asset；文件名 UTF-8 最大 255 bytes。
- digest 必须是 64 位小写十六进制；计数、排序和 snapshot hash 必须可重算一致。
- API 的 device ID 必须来自认证上下文，不接受正文覆盖。
- 持久化记录损坏返回 `catalog_integrity_error`，不得返回部分 projection。

## 6. Android outbox

- outbox 位于应用私有存储，只保留最新完整 snapshot 和自身 SHA-256。
- 客户端在任何网络调用前保存待发项。
- 网络错误只发生一次尝试，不自动循环重试。
- 显式重试先重新读取服务端 watermark；只有成功 receipt 与待发摘要完全一致才清除。
- 新快照可替换旧待发快照，避免离线队列无界增长。

## 7. 稳定错误码

- `catalog_validation_error`
- `catalog_cursor_conflict`
- `catalog_idempotency_conflict`
- `catalog_integrity_error`
- `catalog_rate_limited`
- `catalog_unavailable`
- 既有认证错误：`auth_invalid`、`auth_revoked`、`capability_denied`、
  `capability_epoch_stale`、`auth_unavailable`

## 8. 非目标

V1 不实现内容读取、内容 embedding、语音转写、自动整理、增量 diff、多 Hub 同步或公网中继。

# Shared Session Dart Client v1

状态：P0-S1-T02C-A、P0-S1-T02C-B `PASS`。本协议定义 Windows/Android Flutter
可复用的 Dart 客户端核心、Windows UI 编排和持久游标；P0-S1-T02 仍为
`PASS`。后续阶段已在该 loopback 核心之上增加 TLS pinning、设备认证、私有 WLAN
传输、endpoint 恢复与服务码兜底；这些扩展不改变本协议的游标和严格校验语义。

## 边界

- REST 与 WebSocket 仅允许 `127.0.0.1` 和显式端口。
- 拒绝 `localhost`、`0.0.0.0`、IPv6 loopback、LAN/公网地址、userinfo、
  fragment、隐式端口及 HTTPS/WSS 绕过。
- 默认 HTTP 与 WebSocket `HttpClient` 强制 `DIRECT`，不继承系统代理。
- REST 使用有界 timeout、响应大小、UTF-8 与 JSON Content-Type；错误不包含响应正文、
  完整 URL 或底层 socket 异常。
- WebSocket 使用 `dart:io`、关闭压缩、不带 cookie/auth/header，只接受有界文本 JSON 帧。

## Wire Event

客户端只接受 `protocol_version=1` 和
`event_type=conversation.message.accepted`。事件 conversation 必须与当前连接相同，
sequence 必须为正整数，event/actor ID 非空，时间必须为 RFC3339 UTC `Z`。

payload 必须严格包含：

- `accepted_seq`
- `client_message_id`
- `content`
- `message_id`
- `role`

`accepted_seq` 必须等于外层 `conversation_seq`；role 只允许
`user/assistant/system/tool`。客户端按以上键顺序生成无空格 UTF-8 JSON，计算 SHA-256，
并要求与 64 位小写 hex `payload_sha256` 完全相等。任何字段、类型、hash 或跨字段不一致
均抛出脱敏 `protocol_integrity`，事件不得进入投影。

## 投影与游标

`SessionProjection` 保存 conversation、最后 sequence、有序事件和 event ID 指纹：

1. `sequence == last + 1` 才能应用；
2. 已见 event ID 且完整指纹一致时幂等忽略；
3. 同 event ID 不同内容、未知 stale sequence、sequence gap 或 conversation 不一致均
   fail-closed；
4. 只有事件完整校验并成功更新投影后才推进 cursor。

`semanticProjectionHash` 与 Python 定义一致，包含 protocol/event type、sequence、
actor、causation、correlation 以及 payload 的 accepted sequence、client message ID、
content、role；排除随机 event/message ID 与时间。

T02C-B 增加可注入 `FileCursorStore`。默认目录由 Flutter
`getApplicationSupportDirectory()` 适配层提供；纯 Dart 测试和 Harness 可注入临时目录。
文件名使用 conversation ID SHA-256，严格验证 schema/hash/checksum/非负 sequence，
写入串行单调并使用 flush 与 next/final/backup 原子替换。损坏、冲突或倒退均 fail-closed，
reset 只能由用户明确确认并且只影响当前 conversation 的应用私有游标文件。

## REST 与 WebSocket

REST 映射稳定错误：`validation_error`、`conversation_not_found`、
`conversation_already_exists`、`idempotency_conflict`、`cursor_ahead`、
`persistence_unavailable`。只有创建固定会话时可显式接受
`conversation_already_exists`；`cursor_ahead` 保留服务端 watermark，不自动改写投影。
消息 `200/201` 响应中的事件仍执行完整 Wire 校验。

S6-G-R1 将用户消息确认与 Agent 派生结果解耦：Hub 先持久化并发布
用户事件，REST `200/201` 不等待 Hermes、PC 查询或归档建议。派生任务由
Hub 生命周期托管、相同幂等键复用且仅允许一项正在执行。若已饱和，Hub
会持久化脱敏的“本次派生任务未执行”结果，不静默丢弃、不自动重试。

若 REST 回执在 Hub 接受消息后丢失，客户端只接受已经通过完整 Wire 校验、
conversation 匹配且 `client_message_id` 与本地 pending 完全一致的 WebSocket
用户事件作为权威确认。客户端最多等待 2 秒做回执对账；命中后清除 pending，
未命中仍显示“消息未确认”并等待用户显式重试。该机制不发送第二次请求。

记忆读取超时会关闭并丢弃对应 REST transport，不自动重试。下一次用户明确
点击刷新时才重建一次认证 transport；仍失败则再次停止。最近一次已验证记忆
快照仅保留在本次 App 生命周期，失败刷新不得用 `null` 覆盖；离线展示必须禁用
所有记忆操作，完整 App 重启后不得把旧内存快照冒充实时状态。缓存必须绑定
`hub_id + device_id + capability_epoch`；WLAN endpoint 变化不改变身份，但 Hub、设备
或权限版本变化必须立即隔离旧快照。旧身份的迟到响应不得登记到新身份下。
会话 Controller 的运行凭据键还包含当前 endpoint 与证书指纹：这些值或
设备/Hub/epoch 变化时，先释放旧 Controller，再且仅再启动一次。异步
创建期间发生切换时不得发布旧 Controller；普通启动或网络失败仍停止
等待用户明确恢复，不因该机制形成自动重试。
Controller 的 listener 在发布 `ready` 或处理 `authorizationChanged` 前也必须
重新核对运行凭据键；这一检查先于 `start()` Future 返回，防止凭据刷新与
WebSocket `ready` 同时发生时的短暂跨身份发布。

WebSocket 状态为 disconnected、connecting、replaying、ready、reconnecting、
protocolError、closed。replay 只能出现在 ready 前，live 只能出现在 ready 后；ready
cursor 必须等于投影 cursor。`1008/1011` 停止自动重试，`1013` 使用有上限指数退避与
jitter；delay/random 可注入测试替身。

## 契约证据

Dart↔Python Smoke 启动两个真实 loopback Hub，使用同一临时 SQLite，验证 ready/live、
重启后 replay gap、幂等提交、直接数据库重开投影以及 PID/临时文件清理。最终 REST、
Dart 和数据库 semantic hash 均为
`e401210631d2c3deea65a338b6d2152b88dd4fe8e77aa8c3ee7c153bcaf043bd`。

## T02C-B 前置条件

后续 UI 接入需选择磁盘 `CursorStore`、定义生命周期和可见错误状态，并在开放远程设备前
实现认证、配对、凭据保护和 TLS/指纹校验。不得直接把本 loopback spike 暴露到 LAN。

## R1 生命周期与 REST 契约加固

WebSocket 建连新增默认 5 秒、可注入的总 timeout，覆盖注入 connector 与真实
`WebSocket.connect`。connecting/replaying/ready 或终止关闭后再次 connect 均
fail-closed；connector timeout/异常统一映射为脱敏 transport error。每个连接由单一
connection context 持有 socket/subscription，onError、onDone、协议错误、正常关闭和
重连都通过同一幂等释放路径，`IoHubSocket` 至多关闭一次自定义 `HttpClient`。

只有 close code `1013` 可在旧连接释放后触发有界指数退避重连，并使用当前已验证 projection
cursor；`1008/1011` 停止重试。等待或建连期间调用 close 会终止后续重连，close 本身幂等。

REST 与 Python `transport_models.py` 对齐：

- health、conversation、append、replay 和 error 的 JSON 字段集合必须精确；
- conversation ID/title/next sequence/UTC Z 时间执行跨字段检查；
- append 顶层 message ID 必须等于事件 payload，HTTP `200/201` 必须分别对应
  `deduplicated=true/false`；
- replay 必须从 `after_seq + 1` 连续递增，last metadata 必须与末项或空页 cursor 相等；
- error code 与 HTTP status 必须匹配，只有 `cursor_ahead` 可带非负 watermark；
- 请求体和响应体均有明确字节上限；单一总 deadline 覆盖 send 与完整响应流，连续慢分块
  不能延长时限。总 deadline 超时后该 REST client 被关闭，不得复用。

## T02C-B Windows UI 与持久游标

`SharedSessionController` 保持纯 Dart，并由 Flutter bootstrap 注入磁盘 store、REST client
及 WebSocket client。启动顺序固定为 health、创建/恢复固定 Demo conversation、读取本地
cursor、从 `after_seq=0` 有界分页重建完整投影、比较 Hub 最终 cursor、持久化，再从最新
projection cursor 建立 WebSocket。

本地 cursor 大于 Hub cursor 时进入 `cursor_ahead`，禁止 WebSocket 与发送且不自动
clamp/reset；本地文件损坏时进入 `local_state_corrupt`。每个 WebSocket 事件只在完整校验
和投影成功后排队持久化；持久化失败先关闭 socket，再禁用发送。

Windows 发送使用固定 `windows-demo` actor，生产 client message ID 由 `Random.secure`
生成至少 128 bit 随机值。失败后的显式 retry 复用进程内 pending ID；REST/WS 同一事件由
event ID 幂等消除。进程崩溃后的 durable outbox 不在 v1 范围。

UI 仅显示脱敏状态、sequence、role 和来源。phone-sim/pad-sim 必须标为模拟端；页面不展示
完整 conversation/event/message ID、URL、端口、磁盘路径或底层异常。当前协议仍未认证且
只允许 loopback，不得暴露到 LAN。

## T02C-B-R1 Controller fail-closed 规则

发送失败必须按阶段和类型分类：

- TransportException 表示结果不确定；保留进程内 pending 和原 client message ID，只允许
  用户显式 retry。旧 transport 关闭后，新 transport 必须先 health、恢复固定 conversation，
  再使用原 ID。
- `persistence_unavailable` 可保留原 ID 显式 retry；
  `idempotency_conflict`、validation/conversation/cursor 错误及未知合法 Hub 错误均
  fail-closed。
- ProtocolIntegrityException 或 ProjectionException 关闭 REST/WS、清除 pending 并进入
  protocol error，不推进 cursor。
- REST 已返回合法接受事件后，pending 立即不再可重试；若 cursor 写失败，事件在投影中最多
  出现一次，进入 local state corrupt，后续重启依靠 Hub replay 收敛。

Controller 以 lifecycle generation 和 operation token 管理异步边界。start/send/retry/reset
互斥；close/dispose 在第一个 await 前标记 terminal、使 generation 失效并禁止创建资源。
每个 health/replay/append/connect/cursor await 后必须验证 token；迟到结果只释放资源，不得
修改 UI、投影或 cursor。startup offline/protocol/local failure 同样释放订阅、socket 和
REST transport。

Flutter Bootstrap 的 Application Support 初始化失败不得永久 loading；只显示脱敏本地错误
和 busy 保护的显式重试。dispose 后完成的 controller factory 结果必须立即释放。

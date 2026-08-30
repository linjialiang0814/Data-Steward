# 官方要求与 Showcase MVP 需求追踪

> 状态：S6-G Release Candidate 已完成  
> 更新日期：2026-08-06  
> 原则：只声明已经由自动测试、Windows 实机或华为真机证明的能力。

## 1. 当前交付结论

当前交付是 **Windows PC + 华为 Android 手机** 的双设备 APP Demo。协议和 Flutter 布局保留扩展 Pad 的能力，但没有 Pad 真机证据，因此不把 Pad 计为已交付主体。

当前最强闭环是：手机与 PC 安全配对并恢复持久会话 → 两端授权资料目录并形成统一目录 → 按时间/文件名生成“今日资料” → PC 多格式安全提取与 Android 端侧 OCR 形成加密投影 → Hermes/Volcengine 自主编排只读工具生成带来源资料包或主动建议 → 用户预览并确认后整理 PC 文件或导出 Markdown → 双端同步回执并可安全撤销 → 明确接受形成可批准、停用和重新启用的跨会话习惯。

## 2. 官方要求映射

| ID | 官方要求 | 当前实现 | 主要证据 | 状态 |
|---|---|---|---|---|
| OR-01 | 可视化交互界面 | Windows 与 Android Flutter UI；首页、会话、安全配对、设备授权、目录、今日资料、资料包、Action Card、记忆和恢复状态均可视 | S4-B、S6-A～S6-F 双端人工 Gate；Flutter Widget/Controller 测试 | PASS（双端） |
| OR-02 | AI 理解访问意图 | Hermes 0.18.2 Adapter 调用 Volcengine Provider；可在课程、项目、会议等自然语言问题下选择七个只读工具，生成有来源约束的资料简报、资料包和 typed Action 建议 | S5-E Provider Gate；S6-D/S6-E Windows+Android 真人 Gate | PASS（受控资料意图） |
| OR-03 | 任务拆分与编排 | Hermes 在八次预算内自主选择目录清单、搜索、聚类、内容摘录、记忆上下文和最终草稿/Action；Host 校验权限、参数、快照、citation 和输出 | S5-E 多步 Gate；S6-E 主动建议与去重/冷却回归 | PASS（单 Hub、只读多步自治） |
| OR-04 | 多设备准确执行 | 手机发起、PC 执行；`files.read`、`files.organize` 与 `session.sync` 分权；epoch 降级、撤销、TLS pinning、幂等、有序回放和执行前确认 | C3/C4、S2、S4-C 真机检查点 | PASS（手机+PC） |
| OR-05 | 自主识别分类及整理习惯 | PC 授权目录只读取本级元数据并生成类别统计；三次独立“接受建议”形成 candidate，显示 1/3、2/3、3/3 证据 | S3-C 三轮真机流程；Archive Memory tests | PASS（category-v1） |
| OR-06 | 智能归档建议 | 元数据先形成跨设备虚拟分组；对当前分组单独预览，只有二次确认后才移动其中的 PC 直接子文件，手机资料保持虚拟；固定目标、不覆盖、不删除、可撤销 | S5-F `student-materials` 三文件整理/撤销与集合哈希复核 | PASS（cluster-selected 真实纵切） |
| OR-07 | 自主学习与记忆 | candidate 必须显式批准才变 active；跨会话 recall、停用阻断和重新启用已闭环；物理整理仍需再次确认 | S4-C 双端 Memory Center 与真机流程；Archive Memory tests | PASS（单条偏好规则） |
| OR-08 | APP Demo | Windows Release bundle + 可安装 Android Release APK（Debug 证书签名）；Windows 本地 Hub 与 Hermes sidecar；双端目录、OCR、多格式理解、资料包、主动建议、整理/导出/撤销 UI | S6-A～S6-G 双端真人 Gate；最终中性路径构建、签名与敏感信息审计 | PASS（开发者 Demo） |

## 3. Showcase 指令覆盖

| 指令 | 当前行为 | 结论 |
|---|---|---|
| 手机：“看下桌面有几个图片文件” | 在 PC 明确授权目录的本级范围执行图片计数；两端消息唯一有序 | 已实现并真机通过（S2 结果 2） |
| 手机：“帮我找有关 xxx 的文件” | 文件名关键词搜索；返回数量和安全结果，不展示绝对路径 | 已实现并真机通过（关键词“训练营”，结果 1） |
| 手机：“整理桌面” | 对 PC 明确授权的默认工作区生成预览；用户确认后按固定类别真实整理，可撤销 | 已实现并真机通过；不能越过授权目录或静默执行 |
| PC：“汇总所有设备关于 xx 的信息” | Windows 多格式正文、Android OCR 投影、双端元数据和记忆可形成带来源资料包；确认后可导出 Markdown | 已实现受控纵切；不是向量知识库或自动写入正式办公系统 |
| PC：“把今天交互记录写入手机和 Pad” | 没有手机/Pad 文件写入 Executor | 未实现，后续路线 |

## 4. 准确执行与安全边界

- 模型只输出受限 JSON 计划，内置工具集为 0；不把 Shell、任意路径或文件内容暴露给 Provider。
- 只有 PC 用户显式授权的目录可作为 root；MVP 只处理该目录本级元数据。
- 手机设备必须完成证书指纹校验、一次性配对、双端短码确认和设备凭据认证。
- REST/WS 权限由 granted capabilities 和 capability epoch 决定；降权关闭旧连接，撤销后停止重连。
- `files.read` 与 `files.organize` 分权；整理仅移动授权根直接子文件，不覆盖、不删除、不递归、不跨盘，并保留最近一次密封撤销记录。
- 对话先落 SQLite，再通过 WebSocket 通知；游标回放保证重连后的唯一有序投影。

## 5. 学习与记忆的可验证语义

```text
目录元数据 → 归档预览 → 用户确认后整理/可撤销 → 用户接受建议（独立证据）
          3 次接受 → candidate → 用户显式批准 → active
          active → 跨会话 recall（引用 memory/version/evidence）
          active → 用户停用 → disabled（内部兼容值 forgotten），新调用拒绝
          disabled → 用户明确重新启用 → active
```

“自主”是系统主动从已接受行为累计证据、提出候选并在后续会话引用；“受控”是候选不会自动生效，文件移动必须单独确认，习惯可停用并重新启用。长期记忆不保存文件名、绝对路径、文件正文、凭据或模型密钥。

## 6. 官方综合场景覆盖判断

| 场景能力 | 当前状态 |
|---|---|
| 手机发起任务、PC 执行并双端同步 | 已实现 |
| PC 授权目录元数据检索、固定类别整理、撤销 | 已实现 |
| 从确认行为学习单条整理偏好并跨会话引用 | 已实现 |
| 读取手机本地授权资料并建立双设备目录 | 已实现（Android 本级元数据；无 Pad） |
| 录音转写、OCR、笔记/课件正文理解 | 部分实现（Android JPG/PNG 端侧 OCR；PC TXT/MD/DOCX/PPTX/文本 PDF；无录音与扫描 PDF OCR） |
| 按课程、项目、会议、时间段聚类 | 部分实现（确定性时间/文件名聚类；非向量语义聚类） |
| 从多设备材料生成复习要点或工作简报 | 已实现带 citation 的受控资料包与确认式 Markdown 导出；不写正式待办、日历或邮件 |
| 多设备写入 Saga 与部分失败恢复 | 未实现 |

因此当前 Demo 已能证明 Windows+Android 双设备目录、时间/文件名聚类、PC 多格式受控理解、Android 端侧 OCR、Hermes 多步只读资料包/主动建议、PC 分组整理与 Markdown 导出/撤销。它仍不能宣称完整实现学生或职场的所有数据源：没有录音转写、Pad、扫描 PDF OCR、正式待办/日历写入或跨设备写入 Saga。

## 7. 明确未实现

- Android Pad/iPad/iPhone 真机主体；
- 录音转写、扫描 PDF OCR、向量检索、复杂版面/表格理解、重复/版本关系；
- 任意工具自治、后台持续自治与跨设备 Saga 写入；
- 写入手机、跨设备批量整理与 Saga 补偿；
- 公网中继、多用户；WLAN 自动发现为 best-effort，并保留服务码 endpoint 刷新；
- Windows 独立安装包与自包含 Python sidecar；当前 Windows Demo 依赖仓库内固定虚拟环境。

这些能力不能在答辩中用未来时设计冒充已完成结果。

## 8. S5-F checkpoint 门禁

- 聚焦 Hub/Hermes/Flutter 回归通过；
- Windows/Android Debug 构建通过并记录大小、SHA-256；
- Provider 真实能力复用 S5-E 脱敏证据；S5-F 仅增加离线项目/会议泛化回归，避免无意义重复计费；
- Archive Memory 演示数据可默认只读检查，显式确认后安全重置；
- 工作区无数据库、密钥、证书、APK、缓存或用户隐私进入 Git；
- README、PRD 交付注记与本矩阵口径一致；最终交付仍仅为 APP Demo。

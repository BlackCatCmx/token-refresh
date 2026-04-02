# Codex 轻量级凭证刷新服务方案

## 结论

本项目的新方案定为一套独立的 Rust 刷新服务，职责只包含四件事：

- 读取并刷新 Codex OAuth 凭证。
- 按原有 `CLIProxyAPI`(指参考项目docs_and_ref/CLIProxyAPI) 的多文件 JSON 格式落盘。
- 提供一个内置的、带鉴权的轻量管理页面。
- 支持可选的 SOCKS5 出站代理列表。

这套服务不再承担 `/v1/...` 这类 API 网关转发，也不再复用现有的重型前后端工程。管理页面保留，但不再单独维护一个 React 管理台，而是改为 Rust 内置的本地页面。

## 1. 项目定位

### 1.1 目标

- 通过 `refresh_token` 发起 refresh，请求成功后更新 `access_token` 与轮换后的 `refresh_token`；如果响应包含新的 `id_token`，则同步更新，以保持凭证和账号元信息可用。
- 继续兼容当前 `<email>.json` 这类单账号凭证文件。
- 尽量贴近官方 Codex CLI 的请求头、`originator`、`User-Agent` 和错误分类。
- 保留管理页面，并且管理页面可以设置 SOCKS5 代理列表、代理模式、提前刷新窗口、账号间随机刷新间隔区间等核心参数。
- 本地环境可完成 Rust 基础编译与简单测试；正式部署面向源码部署平台，如 Zeabur。

### 1.2 非目标

- 不做通用 OpenAI 兼容代理。
- 不做模型路由、响应转发、配额管理。
- 不伪装浏览器整包指纹。
- 不直接采用官方 `auth.json` 作为主存储。
- 不继续沿用 `CLIProxyAPI` 和 `Cli-Proxy-API-Management-Center` 这套重工程。

## 2. 核心决策

### 2.1 为什么改为 Rust

本项目采用 Rust，依据如下：

- 官方 Codex 的认证刷新逻辑、`originator` 约定和 `User-Agent` 生成逻辑位于 Rust 实现中。
- 本项目是独立服务，不继承 `CLIProxyAPI` 的技术栈约束。
- 采用 Rust 有利于直接参考官方实现并减少跨语言偏差。

### 2.2 和 `CLIProxyAPI` 的边界

这里只保留一层兼容：凭证文件格式兼容。除此之外，旧项目里的模型代理、转发、管理台都不再继承。

“代理”要分成两类来看：

- 保留的是出站代理，也就是本服务自己发刷新请求时可以走 SOCKS5。
- 不保留的是 API 转发代理，也就是不接收外部客户端的模型请求后再转发给 OpenAI。

## 3. 凭证兼容与目录模型

本项目继续使用 `CLIProxyAPI` 风格的多文件 JSON 存储。默认约定如下：

- 文件命名保持 `<email>.json` 习惯。
- 递归扫描配置目录下的 `.json` 文件。
- 只处理 `type == "codex"` 的文件。
- 标准字段之外的未知字段必须原样保留，不能因为刷新而丢失。

当前需要兼容的核心字段包括：

- `id_token`
- `access_token`
- `refresh_token`
- `account_id`
- `email`
- `type`
- `last_refresh`
- `expired`

官方 Rust 默认围绕 `CODEX_HOME/auth.json` 和 keyring 工作，这一层只借鉴语义，不直接照搬存储方式。

## 4. 官方 Codex 对齐策略

新服务对齐的是官方 Codex CLI 的 refresh 行为，不是浏览器行为。

### 4.1 默认请求身份

V1 在当前本机开发环境下，将以下值作为默认请求身份，并写入配置文件初始值：

- `originator: codex_cli_rs`
- `User-Agent: codex_cli_rs/0.118.0 (Windows 10.0.19045; x86_64) WindowsTerminal`

这组默认值对应当前本机环境：

- 操作系统：`Windows 10.0.19045`
- 架构：`x86_64`
- 终端标识：`WindowsTerminal`

服务启动时不再按部署环境自动重算默认 `User-Agent`。后续如果运行环境变化，例如改为后台服务、Zeabur、VS Code 终端或其他终端，统一通过配置文件或管理页面显式调整。

### 4.2 refresh 请求头范围

refresh 请求遵循以下规则：

- 使用官方同一套 `client_id`。
- 默认发送 `originator: codex_cli_rs`。
- 默认发送 `User-Agent: codex_cli_rs/0.118.0 (Windows 10.0.19045; x86_64) WindowsTerminal`。
- 固定发送 `Content-Type: application/json`。
- `x-openai-internal-codex-residency` 仅在明确配置 residency 要求时才发送，V1 默认不发送。
- 刷新请求采用和官方 Rust 一致的 JSON body。
- 刷新失败时按官方思路区分 `refresh_token_expired`、`refresh_token_reused`、`refresh_token_invalidated`。

### 4.3 请求身份配置策略

默认值固定，不等于实现硬编码。

- `originator` 与 `User-Agent` 必须进入配置文件，并在管理页面中可编辑。
- 配置变更后，后续 refresh 请求立即使用新值。
- `Content-Type: application/json` 属于协议固定项，不作为页面可配项。
- `originator` 和 `User-Agent` 保存前必须做 HTTP header value 合法性校验；校验失败时直接报错，不做静默修正。

以下内容不做：

- 不发送 `sec-ch-ua`、`sec-fetch-*`、`referer`、`origin` 这类浏览器头。
- 不复制浏览器指纹。
- 不把官方 `auth.json` 路径语义直接塞进当前多文件模式。

## 5. 刷新协议与失败处理

刷新接口固定为：

```text
POST https://auth.openai.com/oauth/token
```

请求体采用 JSON：

```json
{
  "client_id": "app_EMoamEEZ73f0CkXaXp7hrann",
  "grant_type": "refresh_token",
  "refresh_token": "<stored_refresh_token>"
}
```

默认 refresh 请求头如下：

```text
originator: codex_cli_rs
User-Agent: codex_cli_rs/0.118.0 (Windows 10.0.19045; x86_64) WindowsTerminal
Content-Type: application/json
```

官方 refresh 响应按字段级处理，而不是假设每次都会返回完整三件套。

- 一次 refresh 的发起凭据是旧 `refresh_token`。
- 长期可用性的核心在于 `access_token` 与轮换后的 `refresh_token`。
- `id_token` 主要承载邮箱、套餐、workspace/account 等账号元信息。
- 如果 refresh 响应返回新的 `id_token`，就更新它。
- 如果 refresh 响应没有返回 `id_token`，则保留旧 `id_token`，不能清空。
- 同理，任何未出现在 refresh 响应里的 token 字段都保留旧值，不做空值覆盖。

V1 不启用 form body 静默回退，也不在同一轮中自动重试。`refresh_token` 具有一次性消费语义。请求已到达服务端但客户端在收响应前超时的情况下，旧 token 可能已经失效；继续复用旧 token 重试会增加 `refresh_token_reused` 风险。

因此失败处理原则如下：

- 如果在发出请求前就失败，例如 DNS、TCP、TLS 明确未建立，请求可留到下一轮再尝试。
- 如果请求已经发出，但发生读超时、连接中断、响应不完整，本轮直接失败，不复用旧 `refresh_token` 重试。
- 如果服务端返回明确的永久错误，直接记录失败并等待人工处理。

## 6. 调度策略

### 6.1 总体策略

- 单进程串行刷新，同一时刻只处理一个账号。
- 启动时先全量扫描，之后按最近到期时间动态休眠，不做固定 5 秒死循环。
- 默认提前刷新窗口为 `24h`。
- 调度优先依据最近一次刷新响应返回的 `expires_in`。
- 进程重启后的恢复阶段，优先从 `access_token` 的 JWT `exp` 恢复过期时间。
- 兼容读取历史文件中的 `expired` 字段，但该字段不作为新项目的主调度依据。

### 6.2 账号间随机间隔

账号间随机间隔采用可配置区间。

- 默认值为 `30s ~ 90s`。
- 小规模账号和稳定网络环境可手动调低。
- 大规模账号或出现 Cloudflare 风控时，可提高至 `30s ~ 120s` 或更高。

该区间同时出现在配置文件和管理页面中，不写死在程序内部。

### 6.3 触发条件

以下任一条件满足，就进入候选刷新队列：

- 当前时间已达到基于 `expires_in` 或 JWT `exp` 计算出的刷新窗口
- 兼容导入旧文件时，历史 `expired` 已进入刷新窗口

候选队列按到期时间从近到远排序。每次完成一个账号后，随机睡眠一个位于区间内的延迟，再继续下一个账号。

凭证导入后的触发规则如下：

- 服务运行中导入新凭证后，立即触发一次目录重扫。
- 新导入凭证如果已经进入刷新窗口，则在当前调度轮次中尽快处理。
- 新导入凭证如果尚未进入刷新窗口，则等待下一次应到时间自动触发。

开始与停止的调度语义如下：

- `停止` 只暂停自动刷新调度，不修改凭证文件和分区状态。
- `开始` 触发一次全量重扫，并基于当前状态重新构建候选队列。
- 系统不持久化“上一次刷到哪个凭证”的游标。
- 进程重启、手动停止后再开始、导入新凭证、删除凭证、异常区恢复等场景下，统一按最新扫描结果重新排序。

## 7. 管理页面

管理页面纳入 V1 范围。

### 7.1 形态

- 不单独维护 React 管理台项目。
- 服务内置轻量页面，采用服务端渲染 HTML 或少量静态资源加简单脚本。
- 本地开发可监听 `127.0.0.1`；部署到源码平台时通过环境变量指定监听地址与端口。

### 7.2 页面功能

V1 管理页面至少提供以下能力：

- 登录和退出。
- 查看正常凭证区和异常凭证区的列表、邮箱、文件路径、最近刷新时间、过期时间、当前状态、最近异常类型、最近异常原因、连续异常次数。
- 上传多个 JSON 凭证文件。
- 导入 ZIP 凭证包。
- 手动触发正常区单个账号刷新。
- 手动将异常区凭证恢复回正常区。
- 启动自动刷新和停止自动刷新。
- 删除单个或批量凭证。
- 下载单个凭证原始 JSON。
- 按区 ZIP 打包下载全部凭证。
- 查看全局运行状态和最近错误。
- 查看运行日志与审计日志的最新内容。
- 下载运行日志、审计日志，或按 ZIP 打包下载全部日志。
- 清空运行日志或审计日志。
- 查看当前 refresh 请求头预览。
- 修改并保存核心配置。

可通过页面修改的配置至少包括：

- `request_identity.originator`
- `request_identity.user_agent`
- `log_level`
- `logging.max_file_size`
- `proxy.mode`
- `proxy.list`
- `credential_management.abnormal_threshold`
- `refresh.lead_time`
- `refresh.inter_refresh_delay_min`
- `refresh.inter_refresh_delay_max`
- `refresh.failure_backoff`
- `network.timeout`

其中：

- `originator` 与 `User-Agent` 在页面中采用独立输入项。
- 日志区至少区分 `runtime` 与 `audit` 两类日志。
- 页面默认展示日志尾部内容，而不是一次性加载完整日志文件。
- 清空日志只影响所选日志种类的当前文件，不影响 `credential_status.json`。
- 页面应实时展示当前生效的 refresh 请求头预览。
- `Content-Type` 为协议固定项，不提供编辑入口。

### 7.3 鉴权方式

为了保持实现轻量，V1 采用单管理员模型：

- 管理页采用单字段密码登录，密码仅通过环境变量提供。
- 登录成功后使用持久化签名 cookie。
- 改配置、手动刷新这类写操作接口都必须带有效会话。

鉴权来源保持简单：

1. 只读取 `WEB_PASSWORD`。
2. `WEB_PASSWORD` 不存在或为空时，服务启动失败。

该设计满足以下要求：

- 适配源码部署平台，通过环境变量注入密钥。
- 不将密码写入仓库。
- 不引入平台耦合，适用于任意支持环境变量的平台。

管理页面不提供在线改密并落盘能力。

登录态不设置应用层过期时间。有效会话在以下情况失效：

- 用户手动退出登录。
- `WEB_PASSWORD` 发生变化。
- `WEB_SESSION_SECRET` 发生变化。

## 8. 一次刷新事务与崩溃恢复

一次成功刷新必须按下面顺序执行：

1. 读取旧文件，并解析标准字段和未知字段。
2. 判断该文件是否需要刷新。
3. 只发起一次 refresh 请求。
4. 收到 refresh 响应后，按字段级合并出完整的新 JSON；响应里返回了哪个 token 就更新哪个，未返回的字段保留旧值。
5. 计算新的 `expired` 和 `last_refresh`。
6. 先写恢复日志文件并落盘。
7. 再原子替换正式凭证文件。
8. 正式文件写入成功后，删除恢复日志文件。

恢复日志文件用于覆盖以下故障场景：刷新已经成功，但正式 JSON 尚未替换时进程崩溃。缺少恢复日志时，新 token 仅存在于内存中，而旧 `refresh_token` 可能已经失效。

恢复文件位于原凭证同目录，命名为：

```text
<credential>.refresh-recovery.json
```

其内容为已经合并好的完整新凭证内容，并附带目标文件名和时间戳。服务重启后据此继续完成正式替换。

启动流程要先扫描所有 `*.refresh-recovery.json`：

- 如果恢复文件合法，就优先完成恢复。
- 如果恢复文件已经对应到最新正式文件，可以删除。
- 如果恢复文件损坏，就记录错误并保留原文件，等待人工处理。

## 9. 持久化、锁与运行态状态

V1 采用基于文件系统的持久化模型，不引入数据库。凭证、配置和运行状态分别保存在持久化目录中。

### 9.1 原子写入

正式凭证文件的写入规则如下：

- 临时文件必须写在同目录，避免跨盘替换。
- 临时文件写完后要 `flush/fsync`。
- 再用同目录原子替换覆盖正式文件。

### 9.2 单实例锁

同一套凭证目录只能有一个守护进程在跑。

锁文件位于 `state/service.lock`。启动时获取锁失败，程序直接报错退出，不允许多实例并存，以避免两个实例同时消费同一个一次性 `refresh_token`。

### 9.3 运行态状态

以下信息不写回 credential JSON：

- 最后一次错误
- 当前退避截止时间
- 临时统计信息
- 当前轮询代理下标
- 连续异常次数
- 最近异常原因
- 当前所在分区

这些都属于运行态，应当放在内存或独立状态文件里，避免污染源凭证。

推荐使用独立状态文件持久化这些信息：

```text
state/credential_status.json
```

状态文件按凭证文件名或相对路径建立索引，至少保存以下字段：

- `zone`
- `consecutive_failure_count`
- `last_failure_code`
- `last_failure_reason`
- `last_failure_at`
- `moved_to_abnormal_at`
- `last_success_at`

`credential_status.json` 不是日志文件。

- 它只保存当前状态索引，用于页面展示和调度判断。
- 它不承担历史审计、文本检索、问题排查或日志下载功能。
- 页面里的日志查看、下载、清空能力必须基于独立日志文件，而不是基于 `credential_status.json`。

### 9.4 持久化目录布局

部署时应挂载一个持久化数据目录，并在目录内划分以下内容：

- `credentials_dir`：存放 `<email>.json` 凭证文件。
- `abnormal_credentials_dir`：存放被隔离的异常凭证文件。
- `state_dir`：存放 `service.lock`、恢复日志、日志文件、运行态状态文件。
- `config.yaml`：配置文件模式下的持久化配置文件。

目录布局如下：

```text
/data/
├─ credentials/
├─ credentials_abnormal/
├─ state/
│  ├─ logs/
│  │  ├─ runtime.log
│  │  ├─ audit.log
│  └─ credential_status.json
└─ config.yaml
```

对应运行参数：

- `credentials_dir=/data/credentials`
- `abnormal_credentials_dir=/data/credentials_abnormal`
- `state_dir=/data/state`
- `config_path=/data/config.yaml`

在该布局下，持久化目录保留时，服务重启或重新部署后，凭证、恢复日志和配置均可继续使用。

日志文件规则如下：

- `state/logs/runtime.log`：运行日志，记录启动、扫描、刷新、恢复、异常等系统行为。
- `state/logs/audit.log`：审计日志，记录针对具体凭证的刷新动作和结果。
- 默认单文件上限为 `1 MiB`。
- 日志达到上限后直接截断当前文件并继续写入，不保留归档文件。
- 管理页面清空日志时，只清空选定日志种类的当前文件，不删除 `state/credential_status.json`。

### 9.5 配置如何持久化

系统同时支持环境变量模式和配置文件模式，优先级为环境变量高于配置文件。

环境变量模式适用于源码部署平台。敏感信息不落盘，重启后由平台重新注入。被环境变量覆盖的字段，在管理页面中应显示为只读或显示为“由环境变量控制”。

配置文件模式适用于需要通过管理页面修改配置并在重启后继续保留的场景。管理页面修改后，应将新配置原子写回 `config.yaml`。该文件必须位于持久化目录中。

### 9.6 凭证分区与异常区

系统维护两个凭证分区：

- 正常凭证区：参与刷新调度。
- 异常凭证区：不参与刷新调度。

异常账号的主标记方式是文件所在目录：

- 位于 `credentials_dir` 的文件视为正常凭证。
- 位于 `abnormal_credentials_dir` 的文件视为异常凭证。

管理页面展示的异常类型、异常原因、连续异常次数、迁移时间等信息来自 `state/credential_status.json`，而不是来自 credential JSON 本身。

异常凭证区与正常凭证区复用相同的删除和下载逻辑。下载单个凭证时，返回原始 JSON 文件。ZIP 导出规则如下：

- `zone=normal`：ZIP 根目录直接放置 JSON 文件，导出结果可直接重新导入 `CLIProxyAPI`。
- `zone=abnormal`：ZIP 根目录直接放置异常区 JSON 文件。
- `zone=all`：ZIP 内分别使用 `normal/` 和 `abnormal/` 目录，避免重名冲突。

凭证在正常区与异常区之间移动时，不写入项目私有字段，不改变 `CLIProxyAPI` 可处理的 JSON 结构。

异常区凭证可通过管理页面手动恢复回正常区。恢复时只移动文件并重置状态记录，不修改凭证 JSON 结构。

### 9.7 异常判定与迁移规则

异常计数仅针对凭证本身的确定性异常，不针对网络瞬时故障。

计入异常次数的情况包括：

- refresh 返回 401，且错误码为 `refresh_token_expired`、`refresh_token_reused` 或 `refresh_token_invalidated`。
- 凭证文件无法解析为合法 JSON。
- 凭证缺少刷新所必需的 `refresh_token`。

不计入异常次数的情况包括：

- 代理故障、DNS 失败、TCP/TLS 失败、请求超时。
- 上游 5xx。
- 限流或临时不可用。
- 本地磁盘写入失败。

当同一凭证的连续异常次数达到 `credential_management.abnormal_threshold` 时，系统将该文件从正常凭证区移动到异常凭证区，并停止后续自动刷新。

迁移到异常区时，同时更新状态文件：

- `zone = abnormal`
- `consecutive_failure_count = 当前累计值`
- `last_failure_code = 当前异常类型`
- `last_failure_reason = 当前异常原因`
- `last_failure_at = 当前时间`
- `moved_to_abnormal_at = 当前时间`

刷新成功时，状态文件同步更新：

- `zone = normal`
- `consecutive_failure_count = 0`
- `last_failure_reason = ""`
- `last_success_at = 当前时间`

## 10. 数据模型

Rust 数据结构如下：

```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
struct CodexCredentialFile {
    id_token: String,
    access_token: String,
    refresh_token: String,
    account_id: Option<String>,
    email: Option<String>,
    #[serde(rename = "type")]
    provider_type: String,
    last_refresh: Option<String>,
    expired: Option<String>,
    label: Option<String>,
    #[serde(flatten)]
    extra: std::collections::BTreeMap<String, serde_json::Value>,
}
```

写回规则保持简单：

- 非 `codex` 文件直接跳过。
- 未知字段统一放进 `extra`，写回时原样保留。
- refresh 写回采用字段级更新策略：返回了新的 `access_token`、`refresh_token`、`id_token` 才覆盖对应旧值；未返回的字段保留旧值。
- `expired` 和 `last_refresh` 统一写成 RFC3339。
- 项目私有状态不写回 credential JSON。

`expired` 作为兼容输出字段保留。该字段由最近一次成功刷新返回的 `expires_in` 推导得到。

## 11. 出站代理设计

### 11.1 代理协议与默认形式

V1 只支持 SOCKS5 出站代理。

代理项支持以下两种格式：

```text
socks5://ip:port
socks5://username:pass@ip:port
```

代理只作用于服务自己发出的刷新请求，不承担任何监听型反向代理或请求转发功能。

### 11.2 管理页面中的代理配置区

管理页面中的代理配置区采用多行内容编辑区，而不是单行输入框。

- 一行一个代理。
- 空行自动忽略。
- 所有非空行都必须符合 `socks5://ip:port` 或 `socks5://username:pass@ip:port` 格式。
- 保存配置时如果存在非法行，应直接报错，不做静默跳过。

### 11.3 代理模式

代理模式只提供两种：

- `fixed`
- `round_robin`

行为定义如下：

- 如果代理编辑区为空，则默认不使用代理，直接连接。
- `fixed` 模式下，只使用第一条代理。
- `round_robin` 模式下，按编辑区从上到下逐条使用，走到最后一条后再从第一条重新开始。

轮询下标只保存在运行内存中，进程重启后从第一条重新开始即可。

## 12. 服务入口与本地 HTTP 接口

### 12.1 服务入口

服务以守护进程方式启动，由部署平台负责拉起。

### 12.2 本地 HTTP 接口

管理页面背后提供最小 HTTP 接口。本地开发可监听 `127.0.0.1`，部署到源码平台时应监听 `0.0.0.0` 并使用平台分配端口。接口如下：

- `POST /api/session/login`
- `POST /api/session/logout`
- `GET /api/credentials?zone=normal|abnormal`
- `POST /api/credentials/import-json`
- `POST /api/credentials/import-zip`
- `POST /api/credentials/refresh`
- `POST /api/credentials/restore`
- `POST /api/credentials/delete`
- `GET /api/credentials/download?zone=normal|abnormal&name=<filename>`
- `GET /api/credentials/archive.zip?zone=normal|abnormal|all`
- `POST /api/scheduler/start`
- `POST /api/scheduler/stop`
- `GET /api/scheduler/status`
- `GET /api/logs?kind=runtime|audit&limit=<n>`
- `GET /api/logs/download?kind=runtime|audit|all`
- `POST /api/logs/clear`
- `GET /api/settings`
- `PUT /api/settings`
- `GET /api/health`

它们只服务本地管理页面，不承担网关职责。

## 13. 模块划分

目录如下：

```text
codex-refresh-rs/
├─ Cargo.toml
├─ config.example.yaml
├─ src/
│  ├─ main.rs
│  ├─ cli.rs
│  ├─ config.rs
│  ├─ credential.rs
│  ├─ credential_store.rs
│  ├─ import.rs
│  ├─ archive.rs
│  ├─ refresh_client.rs
│  ├─ user_agent.rs
│  ├─ originator.rs
│  ├─ scheduler.rs
│  ├─ transaction.rs
│  ├─ recovery.rs
│  ├─ lockfile.rs
│  ├─ proxy.rs
│  ├─ jwt.rs
│  ├─ status.rs
│  ├─ logging.rs
│  ├─ web.rs
│  └─ api.rs
```

职责划分：

- `credential.rs`：凭证结构与未知字段保留。
- `credential_store.rs`：正常区与异常区的目录扫描、读写、原子替换、分区迁移。
- `import.rs`：多 JSON 与 ZIP 导入、导入校验。
- `archive.rs`：凭证 ZIP 导出。
- `refresh_client.rs`：调用 `auth.openai.com/oauth/token`。
- `user_agent.rs`：管理默认 UA 文本、配置覆盖与 header 合法性校验。
- `originator.rs`：管理默认 `originator` 文本、配置覆盖与 header 合法性校验。
- `scheduler.rs`：挑选下一个待刷新账号，并控制串行节奏。
- `transaction.rs`：一次刷新事务和落盘。
- `recovery.rs`：启动恢复逻辑。
- `lockfile.rs`：单实例锁。
- `proxy.rs`：`reqwest` 代理配置。
- `logging.rs`：运行日志、审计日志、滚动策略与日志读取接口。
- `web.rs` 和 `api.rs`：管理页面与本地接口。

## 14. 配置文件

配置如下：

```yaml
credentials_dir: "./credentials"
abnormal_credentials_dir: "./credentials_abnormal"
state_dir: "./state"
log_level: "info"

logging:
  max_file_size: "1MiB"

request_identity:
  originator: "codex_cli_rs"
  user_agent: "codex_cli_rs/0.118.0 (Windows 10.0.19045; x86_64) WindowsTerminal"

proxy:
  mode: "fixed"
  list: |
    socks5://127.0.0.1:10808

credential_management:
  abnormal_threshold: 1

refresh:
  lead_time: "24h"
  min_sleep: "60s"
  max_sleep: "10m"
  inter_refresh_delay_min: "30s"
  inter_refresh_delay_max: "90s"
  failure_backoff: "15m"

network:
  timeout: "30s"

web:
  enabled: true
  listen: "0.0.0.0:9876"
```

`proxy.list` 采用多行文本形式保存，一行一个代理。内容为空时表示不使用代理。

`request_identity` 用于控制 refresh 请求里的身份 header。

- `request_identity.originator` 默认值为 `codex_cli_rs`
- `request_identity.user_agent` 默认值为 `codex_cli_rs/0.118.0 (Windows 10.0.19045; x86_64) WindowsTerminal`
- 默认值固定为当前本机开发环境的实测结果，不在服务启动时自动跟随部署环境变化
- 两个字段在读取配置和保存配置时都必须做 HTTP header value 合法性校验
- `Content-Type: application/json` 是协议固定值，不进入配置文件

`logging` 用于控制文件日志。

- `logging.max_file_size` 表示单个日志文件的滚动上限，默认 `1MiB`
- 该上限同时作用于 `runtime.log` 与 `audit.log`
- `log_level` 控制运行日志级别，不影响审计日志是否记录
- 审计日志默认始终开启，不允许通过页面关闭

采用源码部署且主要依赖环境变量时，可不持久化大部分配置，只挂载凭证目录和状态目录。

需要通过管理页面改配置并在重启后保留时，配置文件本身必须位于持久化目录中。

其中最关键的可调参数是：

- `request_identity.originator`
- `request_identity.user_agent`
- `log_level`
- `logging.max_file_size`
- `proxy.mode`
- `proxy.list`
- `credential_management.abnormal_threshold`
- `refresh.lead_time`
- `refresh.inter_refresh_delay_min`
- `refresh.inter_refresh_delay_max`
- `refresh.failure_backoff`
- `network.timeout`

管理页面修改这些配置后，服务应当原子写回配置文件，并在校验通过后热加载生效。

支持以下环境变量覆盖：

- `CREDENTIALS_DIR`
- `ABNORMAL_CREDENTIALS_DIR`
- `STATE_DIR`
- `CONFIG_PATH`
- `LOG_LEVEL`
- `LOGGING_MAX_FILE_SIZE`
- `REQUEST_IDENTITY_ORIGINATOR`
- `REQUEST_IDENTITY_USER_AGENT`
- `CREDENTIAL_ABNORMAL_THRESHOLD`
- `PROXY_MODE`
- `PROXY_LIST`
- `WEB_PASSWORD`
- `WEB_LISTEN`
- `PORT`
- `WEB_SESSION_SECRET`

管理页密码仅从环境变量读取。其他平台差异化参数可通过环境变量覆盖配置文件。

监听地址优先级如下：

1. `WEB_LISTEN`
2. `PORT`，等价展开为 `0.0.0.0:${PORT}`
3. 配置文件中的 `web.listen`

其中 `PROXY_LIST` 使用多行文本，一行一个代理，格式与管理页面编辑区一致。

## 15. 部署与供应链控制

本项目面向源码部署，仓库内应提供以下文件：

- `.dockerignore`
- `Cargo.lock`
- `rust-toolchain.toml`

以下文件为可选项：

- `Dockerfile`

### 15.1 Dockerfile

`Dockerfile` 为可选项。平台支持“直接拉源码，然后按构建命令编译运行”时，可不提供 `Dockerfile`。容器化部署或需要固定构建环境时，提供 `Dockerfile`。

`Dockerfile` 满足以下要求：

- 使用固定的大版本基础镜像，不跟随 `latest`。
- 采用多阶段构建，前一阶段编译，后一阶段只放最终二进制和运行所需文件。
- 运行镜像尽量精简。
- 默认从环境变量读取监听地址、密码、session secret 和代理等配置。

该设计同时适用于 Zeabur 和其他支持容器的平台。不提供 `Dockerfile` 不影响源码部署方案成立。

### 15.2 Cargo.lock

`Cargo.lock` 必须提交进仓库。本项目属于应用程序，提交 `Cargo.lock` 用于固定依赖解析结果，降低不同时间构建得到不同依赖树的风险。

该措施不能完全消除供应链风险，但可以降低依赖漂移导致的构建结果不一致风险。

### 15.3 rust-toolchain.toml

`rust-toolchain.toml` 应提交进仓库，用于固定 Rust 工具链版本。否则即便依赖相同，不同平台或不同时间拉取的编译器版本也可能不同。

### 15.4 额外边界

V1 不引入私有 crate 镜像、全量 vendor 依赖或复杂 SBOM 流水线。

V1 的供应链控制要求如下：

- 提交 `Cargo.lock`
- 固定 `rust-toolchain.toml`
- 如有容器化需求，再提供正式 `Dockerfile`
- 不使用 `latest` 基础镜像
- 尽量减少依赖数量
- 优先选择成熟、常见的 Rust crate
## 16. 日志、测试与验收

### 16.1 日志

至少保留两类日志：

- 运行日志：启动、扫描、刷新结果、恢复动作。
- 审计日志：哪个文件、什么时候刷新、成功还是失败、错误分类是什么。

日志设计补充如下：

- 运行日志与审计日志分别写入独立文件。
- 两类日志都位于 `state/logs/` 目录下。
- 单文件默认上限 `1 MiB`，达到后直接截断当前文件并继续写入。
- 管理页面默认展示尾部日志内容。
- 管理页面支持下载单类日志和打包下载全部日志。
- 管理页面支持清空单类日志。
- `credential_status.json` 不视为日志，不参与日志展示、下载和清空。

### 16.2 本地自动化测试

本地测试只负责文件系统、状态迁移、接口行为和错误分类，不假设本地可以完成真实 OpenAI refresh 验证。

本地自动化测试至少覆盖以下内容：

- JSON 兼容读写，未知字段不丢失。
- 多 JSON 导入与 ZIP 导入校验逻辑。
- 默认 `originator` 与默认 `User-Agent` 能按配置正确加载。
- 修改 `request_identity.originator` 与 `request_identity.user_agent` 后，后续 refresh 请求会带上新 header。
- 非法 `originator` 或非法 `User-Agent` 配置会被拒绝。
- 日志文件达到 `logging.max_file_size` 后会正确滚动。
- 管理页面日志接口能正确读取尾部日志、下载日志并清空指定日志种类。
- refresh 响应缺失 `id_token` 时保留旧 `id_token`。
- refresh 响应返回新的 `id_token` 时，会同步更新邮箱、套餐、workspace/account 等元信息。
- `expires_in`、JWT `exp` 与兼容 `expired` 字段的过期时间计算逻辑。
- `refresh_token_reused`、`refresh_token_expired`、`refresh_token_invalidated` 的错误分类逻辑。
- 网络中断时不会在同一轮里复用旧 `refresh_token` 重试。
- 崩溃恢复能把恢复日志正确落回正式文件。
- 第二个实例启动时会被锁拒绝。
- 多 JSON 上传和 ZIP 导入后，凭证能够正确落入正常区。
- 正常区和异常区的单个删除、批量删除逻辑都能正常工作。
- 正常区和异常区都能下载单个原始 JSON。
- `zone=normal` 的 ZIP 导出结果可直接重新导入 `CLIProxyAPI`。
- `zone=all` 的 ZIP 导出结果包含 `normal/` 与 `abnormal/` 目录。
- 401 永久错误会累计异常次数，并在达到阈值后移入异常区。
- 网络异常和 5xx 不会触发移入异常区。
- 异常区凭证不参与刷新调度。
- 异常区凭证手动恢复后重新参与刷新调度。
- 调度器停止后不再自动刷新；重新启动后恢复自动刷新。
- 代理编辑区为空时能够直连。
- `fixed` 模式下只使用第一条 SOCKS5 代理。
- `round_robin` 模式下会按顺序轮询全部 SOCKS5 代理。
- 管理页面登录、查看状态、修改配置、手动刷新、删除、下载、ZIP 导出都能正常工作。

### 16.3 Zeabur 真实验证

真实 refresh、真实代理、真实异常迁移必须在 Zeabur 或等价源码部署环境中，使用真实凭证完成验证。

真实验证至少覆盖以下内容：

- 使用真实 Codex 凭证完成一次成功 refresh，并确认 `access_token` 与轮换后的 `refresh_token` 已写回；如果响应包含新的 `id_token`，则同步写回，否则保留旧 `id_token`。
- 通过管理页面修改 `originator` 与 `User-Agent`，确认后续真实 refresh 请求头已经切换到新值。
- 通过管理页面查看日志尾部、下载日志并清空日志，确认日志功能与滚动策略符合预期。
- 通过管理页面上传多个真实 JSON 凭证和 ZIP 凭证包，确认导入成功。
- 使用真实返回的 `expires_in` 验证调度窗口和 `expired` 兼容输出。
- 通过真实代理列表验证 `fixed` 与 `round_robin` 两种模式。
- 制造真实 401 凭证异常，确认凭证按阈值移入异常区。
- 确认异常区凭证不再参与自动刷新。
- 手动恢复异常区凭证，确认其重新回到正常区并恢复自动调度资格。
- 停止自动刷新后确认调度暂停；重新开始后确认调度恢复。
- 从 Zeabur 页面下载正常区 ZIP，并重新导入 `CLIProxyAPI` 验证可读性。
- 验证 `WEB_LISTEN` / `PORT` 下的对外访问、登录态和持久化卷行为。

### 16.4 验收标准

V1 通过验收，至少要满足下面几点：

- 现有 `CLIProxyAPI` 样例凭证文件可以直接读取和刷新。
- 管理页面支持上传多个 JSON 凭证和 ZIP 凭证包。
- 导出的正常区凭证 ZIP 可直接重新导入 `CLIProxyAPI`。
- 正常区与异常区之间的移动不会引入 `CLIProxyAPI` 无法处理的 JSON 结构变化。
- 默认请求头为 `originator: codex_cli_rs` 与 `User-Agent: codex_cli_rs/0.118.0 (Windows 10.0.19045; x86_64) WindowsTerminal`。
- 管理页面可以修改 `originator` 和 `User-Agent`，且修改后后续 refresh 请求立即生效。
- 管理页面可以查看、下载、清空运行日志与审计日志。
- 日志文件默认按 `1 MiB` 单文件上限滚动，`credential_status.json` 与日志职责分离。
- refresh 后能正确写回新的 `access_token` 与轮换后的 `refresh_token`；`id_token` 按响应有无执行更新或保留，不做错误清空。
- 服务本身不包含模型路由和 API 转发。
- 管理页面默认可用，并带鉴权。
- 刷新成功后即使在正式文件替换前崩溃，重启也能恢复。
- 自动刷新默认开启，且支持页面级停止与开始。

## 17. 实施顺序

### 17.1 V1 必须包含的内容

V1 发布必须同时包含：

- 守护刷新。
- 多 JSON 上传与 ZIP 导入。
- 手动触发单账号刷新。
- 正常区与异常区的凭证管理。
- 单个删除、批量删除、单文件下载、ZIP 导出全部凭证。
- 自动刷新停止与开始控制。
- 异常阈值配置与异常区隔离。
- 配置校验与保存。
- 日志查看、下载、清空与滚动。
- 代理支持。
- 单实例锁。
- 恢复日志。
- 带鉴权的本地管理页面。
- 在页面里修改请求身份、代理和随机刷新间隔区间。

### 17.2 开发顺序

开发顺序如下：

1. 先完成配置读取、目录扫描、JSON 兼容读写、单账号刷新逻辑。
2. 再完成串行调度、失败退避、单实例锁、恢复日志。
3. 然后接入默认请求身份配置、`originator`、`User-Agent` 和代理能力。
4. 最后补齐登录页、状态页、设置页、手动刷新按钮以及审计日志。

## 18. 方案依据

### 18.1 当前项目内依据

- `docs_and_ref/anarickards1690@eycfhb.com.json:1`：当前样例文件就是多文件 JSON 形态。
- `docs_and_ref/CLIProxyAPI/internal/auth/codex/token.go:18`：当前 Go 版 Codex 凭证字段结构。
- `docs_and_ref/CLIProxyAPI/internal/auth/codex/openai_auth.go:23`：当前 Go 版使用的官方 `client_id` 和 token endpoint。
- `docs_and_ref/CLIProxyAPI/internal/auth/codex/openai_auth.go:168`：当前 Go 版 refresh 使用表单编码。
- `docs_and_ref/CLIProxyAPI/sdk/auth/filestore.go:21`：当前 Go 版采用多文件扫描和落盘模型。
- `docs_and_ref/CLIProxyAPI/internal/runtime/executor/codex_executor.go:30`：当前 `CLIProxyAPI` 把 Codex UA 固定写成某个 macOS/Apple Terminal 值，这不适合作为新服务的默认策略。
- `docs_and_ref/Cli-Proxy-API-Management-Center/package.json:14`：现有前端依赖较重，不适合直接搬到“只做刷新”的新项目里。

### 18.2 官方 Codex 仓库依据

- `C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/app-server/README.md:1311`：官方推荐的是 ChatGPT managed auth，由 Codex 自己持久化并自动刷新。
- `C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/Cargo.toml:88`：官方当前 workspace 版本为 `0.118.0`。
- `C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/login/src/auth/default_client.rs:34`：官方默认 `originator` 为 `codex_cli_rs`。
- `C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/login/src/auth/default_client.rs:131`：官方 UA 结构为 `originator/version + os_info + terminal token`。
- `C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/terminal-detection/src/lib.rs:173`：终端 token 的格式定义。
- `C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/terminal-detection/src/lib.rs:283`：官方终端探测顺序。
- `C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/terminal-detection/src/lib.rs:357`：当前 Windows Terminal 环境可命中 `WT_SESSION -> WindowsTerminal`。
- `C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/login/src/auth/default_client.rs:226`：官方默认头里包含 `originator`，residency header 为可选项。
- `C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/login/src/auth/manager.rs:627`：官方刷新成功后按字段级持久化新 token，并更新时间。
- `C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/login/src/auth/manager.rs:655`：官方 refresh 请求使用 JSON body，并显式发送 `Content-Type: application/json`。
- `C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/login/src/auth/manager.rs:760`：官方 refresh 响应里的 `id_token`、`access_token`、`refresh_token` 都是 `Option`。
- `C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/login/src/auth/auth_tests.rs:20`：官方测试覆盖了 refresh 响应缺失 `id_token` 时保留旧值。
- `C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/login/src/token_data.rs:26`：官方 `id_token` 承载邮箱、套餐、workspace/account 等账号元信息。
- `C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/login/src/auth/manager.rs:698`：官方对 refresh 失败做错误码分类。
- `C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/login/src/auth/manager.rs:1454`：官方刷新前会做受保护的 reload/刷新流程。
- `C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/login/src/auth/manager.rs:1627`：官方 managed auth 成功刷新后会重新加载新状态。
- `C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/login/src/auth/storage.rs:28`：官方默认主存储是 `CODEX_HOME/auth.json` 或 keyring，不适合直接套到本项目的多文件场景。
- `C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/login/src/token_data.rs:9`：官方会从 token 中解析邮箱、plan、workspace 等信息。

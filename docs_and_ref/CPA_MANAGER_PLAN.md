# CPA管理功能设计方案

## 一、需求摘要

给 token-refresh 新增 **CPA管理** 标签页（第四个Tab），用于与 CLIProxyAPI 的管理 API 交互：

| 操作 | 来源 | 目标 | 备注 |
|------|------|------|------|
| 巡查到"异常凭证"（401） | CPA | 本地 `credentials_abnormal/` | 先下载再删 CPA |
| 巡查到"耗尽凭证"（quota exhausted） | CPA | 本地 `credentials/`（正常区） | 先下载再删 CPA，UI 显示橙黄"耗尽"badge |
| 自动补号 | 本地 `credentials/` 健康凭证 | CPA | 上传后**删除本地**，避免双份 token 冲突 |

正常区"耗尽"凭证：UI 显示橙黄 badge `耗尽（重置于 MM/DD HH:mm）`，仍参与 OAuth token 自动刷新。当重置时间到达后自动清除耗尽标记，恢复为正常凭证。

**补号删本地的原因**：token-refresh 刷新 OAuth token 会使 access_token/refresh_token 轮换，导致 CPA 持有的旧 token 立即失效。因此补号后本地必须清理，凭证归 CPA 独占；若 CPA 后续将其识别为异常或耗尽，再通过巡查移回本地。

---

## 二、凭证 JSON 格式

### 核心 OAuth 字段

```json
{
  "type": "codex",
  "id_token": "eyJ...",
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "account_id": "user-xxxxxx",
  "email": "user@example.com",
  "last_refresh": "2026-04-10T08:00:00Z",
  "expired": "2026-04-10T10:00:00Z"
}
```

### 本项目可附加的字段

| JSON 字段 | Rust 字段 | 说明 |
|---------|---------|------|
| `label` | `label` | 人类可读标签 |
| `user-agent` | `user_agent` | User-Agent 字符串，本项目注入 |

凭证 JSON 可随意新增字段，本项目通过 `extra: BTreeMap<String, Value>` 透明保留所有未知字段。

### 与 CPA 交互时的处理策略

**上传到 CPA（补号）：直接上传本地原始字节，不做任何裁剪。**

理由（已验证 CLIProxyAPI 源码）：
- CPA 的 `writeAuthFile()` 用 `os.WriteFile(dst, data, 0o600)` 将原始字节原封不动写入磁盘，不做任何变换
- CPA 只从 JSON 中提取 `type`、`email`、`last_refresh` 用于元数据索引，其余字段全部进入 `Metadata map[string]any` 保留
- CPA 发出请求时的 User-Agent **不读取**凭证文件中的 `user-agent` 字段，而是使用全局配置 `cfg.CodexHeaderDefaults.UserAgent`，因此本地的 `user-agent` 字段对 CPA 完全透明无影响

**从 CPA 下载（巡查移入本地）：同样直接保存原始字节。**

CPA 返回的是当初上传的原始字节，本地用 `store.write_bytes()` 写入，解析交给 `CodexCredentialFile`（未知字段由 `extra` 吸收）。若下载的凭证缺少 `user-agent`，用户可事后通过现有 UA 补全功能处理。

---

## 三、CLIProxyAPI 管理 API 规范

base_url 格式：`https://xxx.example.com` 或 `http://host:8317`（支持内网 HTTP）

请求头：`Authorization: Bearer <management_key>`

约定：`management_key` 在本项目配置中保存**裸 key**，不带 `Bearer ` 前缀；客户端发送请求时统一拼接 `Bearer `，避免出现 `Bearer Bearer xxx`。

| 端点 | 方法 | 说明 |
|------|------|------|
| `/v0/management/auth-files` | GET | 列出所有凭证 |
| `/v0/management/auth-files/download?name={name}` | GET | 下载原始 JSON |
| `/v0/management/auth-files` | DELETE `?name={name}` | 删除单个 |
| `/v0/management/auth-files?name={name}` | POST body=json | 上传/覆盖凭证 |
| `/v0/management/auth-files/status` | PATCH body=json | 启用/禁用单个凭证 |

GET 响应格式：
```json
{
  "files": [
    {
      "name": "codex-user@example.com.json",
      "type": "codex",
      "provider": "codex",
      "email": "user@example.com",
      "id_token": { "plan_type": "free" },
      "status": "active|error|pending|refreshing|disabled|unknown",
      "status_message": "{\"error\":{\"type\":\"usage_limit_reached\",\"plan_type\":\"free\",\"resets_at\":1776262806}}",
      "disabled": false,
      "unavailable": true,
      "next_retry_after": "2026-04-15T22:20:00Z"
    }
  ]
}
```

`next_retry_after` 字段来源：CLIProxyAPI 收到 OpenAI 429 + `usage_limit_reached` 错误时，优先解析响应体中的 `error.resets_at`（Unix 时间戳）；若缺失则回退 `error.resets_in_seconds`；若二者都缺失则回退 CLIProxyAPI 自身的本地 cooldown/backoff。最终写入 `auth.NextRetryAfter` / `auth.Quota.NextRecoverAt`，并在认证级 `NextRetryAfter` 非零时通过 `buildAuthFileEntry` 条件返回。模型级错误路径会在 `status_message` 中保留原始 JSON；认证级 429 路径可能只返回 `quota exhausted`。

OpenAI 原始错误格式：
```json
{
  "error": {
    "type": "usage_limit_reached",
    "plan_type": "free",
    "resets_at": 1776262806,
    "resets_in_seconds": 440956
  }
}
```

### 凭证识别规则（本期仅实现被动策略）

说明：参考项目 `protocol-registration-py` 同时支持 `passive` / `active` 两种策略；本项目首版**不引入** `/v0/management/api-call` 主动探测，避免新增额外请求流量、实现面和内存观测噪音。后续若被动识别误判率不可接受，再单独追加主动探测方案。

| 条件 | 识别为 |
|------|------|
| `type/provider="codex"` 且 `status="error"` 且 `status_message` 含 `unauthorized`，或含 `account_deactivated`，或序列化 JSON 中含 `"status": 401` | 异常凭证（401） |
| `type/provider="codex"` 且 `status="error"`，并且结构化错误的 `error.type="usage_limit_reached"`，或 `status_message` 包含 `quota exhausted` / `usage limit has been reached` | 耗尽凭证 |

补充约束：
- **不使用** `unavailable=true` 作为耗尽判据。CLIProxyAPI 会把 401、429、404、408、5xx 等多类失败都先标记为 `unavailable=true`，直接使用该字段会误判。
- `next_retry_after` 只用于缺少套餐信息时的长期窗口推测，以及自动恢复时间计算，不单独作为“耗尽”判据。
- 自动巡查从结构化 `status_message` 读取 `error.plan_type`，其优先级高于 CPA 从凭证 `id_token` 解析出的套餐。两处套餐均缺失时，才使用恢复时间超过 7 天的长期窗口推测；明确的非 Free 套餐不使用该推测。
- 长期窗口的时间来源顺序为有效的未来 `error.resets_at`、有效的未来 `next_retry_after`、正数 `error.resets_in_seconds`。
- `status_message` 匹配前统一做 `trim().to_ascii_lowercase()`；401 判定同时兼容纯文本文案与序列化 JSON 错误串，当前规则依赖 CLIProxyAPI 现有输出，若后续版本调整文案或字段，需要同步调整该匹配条件。

---

## 四、CPA 配置持久化

单独的 `state/cpa_config.json`，不加入 `config.yaml`（避免 management_key 出现在用户可见配置文件中）：

```json
{
  "enabled": false,
  "base_url": "http://cliproxyapi:8317",
  "management_key": "xxx",
  "inspect_interval_minutes": 60,
  "auto_supplement_enabled": false,
  "supplement_target": 50,
  "safety_abort_enabled": true,
  "safety_abort_ratio_percent": 50
}
```

---

## 五、"耗尽"状态追踪与自动恢复

在 `src/status.rs` 的 `CredentialStatusRecord` 中新增三个可选字段（`#[serde(default)]` 向后兼容）：

```rust
#[serde(default)]
pub cpa_exhausted: Option<bool>,         // true = 从 CPA 移入的耗尽凭证

#[serde(default)]
pub cpa_imported_at: Option<String>,     // RFC3339，何时从 CPA 移入

#[serde(default)]
pub exhausted_resets_at: Option<String>, // RFC3339，选定的配额重置时间
```

### 自动恢复机制

1. **移入时**：按顺序选择仍在未来的恢复时间并写入 `exhausted_resets_at`：
   - 结构化错误的绝对时间 `error.resets_at`
   - CPA 的绝对时间 `next_retry_after`
   - 两个绝对时间均不可用时，使用 `error.resets_in_seconds` 计算相对时间
   - 均不可用时留空，依赖兜底策略
2. **定期检查**：CPA scheduler 每次唤醒时，扫描所有 `cpa_exhausted=true` 的凭证，判断是否到期：
   - 优先：`exhausted_resets_at` 非空 且 `now >= exhausted_resets_at`
   - 兜底：`exhausted_resets_at` 为空 且 `now >= cpa_imported_at + 721h`
   - 满足任一条件 → 清除 `cpa_exhausted`、`cpa_imported_at` 和 `exhausted_resets_at`，写 cpa.log
3. **兜底说明**：`cpa_imported_at` 代表确认耗尽的时间点；缺少可信恢复时间时采用 `30d + 1h` 的保守兜底，避免月度额度窗口被提前恢复为“正常”。

### UI 显示规则

- `cpa_exhausted=true` 且 `exhausted_resets_at` 非空：显示 `耗尽（重置于 04/15 22:20）`（橙黄）
- `cpa_exhausted=true` 且 `exhausted_resets_at` 为空：显示 `耗尽（约30天1小时后自动恢复）`（橙黄）
- `cpa_exhausted=false/null`：维持现有渲染逻辑

### 新增 status.rs 方法

```rust
pub fn set_cpa_exhausted(
    &self,
    key: &str,
    resets_at: Option<String>,  // RFC3339 or None
) -> Result<CredentialStatusRecord>;

pub fn clear_cpa_exhausted(&self, key: &str) -> Result<CredentialStatusRecord>;

pub struct ExhaustedPendingReset {
    pub key: String,
    pub cpa_imported_at: Option<String>,
    pub exhausted_resets_at: Option<String>,
}

// 返回所有需要检查重置时间的耗尽凭证，供 scheduler 同时使用 exhausted_resets_at 与 cpa_imported_at 判断
pub fn list_exhausted_pending_reset(&self) -> Result<Vec<ExhaustedPendingReset>>;
```

---

## 六、新增 Rust 模块

```
src/
├── cpa_config.rs      # CpaConfig struct + 持久化（load/save）
├── cpa_client.rs      # reqwest HTTP 客户端封装，调用管理 API
├── cpa_manager.rs     # 巡查核心逻辑 + 补号逻辑
├── cpa_scheduler.rs   # 自动巡查 tokio task（类似 scheduler.rs 结构）
└── cpa_log.rs         # CPA 专属日志管理（复用 logging.rs 中的 append 模式）
```

### 6.1 `cpa_config.rs`

```rust
pub struct CpaConfig {
    pub enabled: bool,
    pub base_url: String,
    pub management_key: String,
    pub inspect_interval_minutes: u64,
    pub auto_supplement_enabled: bool,
    pub supplement_target: usize,
    pub safety_abort_enabled: bool,
    pub safety_abort_ratio_percent: u8,
}

pub struct CpaConfigStore {
    path: PathBuf,
    config: Mutex<CpaConfig>,
}

impl CpaConfigStore {
    pub fn load(state_dir: &Path) -> Result<Self>;
    pub fn get(&self) -> CpaConfig;
    pub fn set(&self, config: CpaConfig) -> Result<()>;  // atomic_write_json
}
```

### 6.2 `cpa_client.rs`

```rust
pub struct CpaAuthEntry {
    pub name: String,
    pub email: Option<String>,
    pub plan_type: Option<String>,       // CPA 从 id_token 解析的套餐
    pub status: String,
    pub status_message: String,
    pub disabled: bool,
    pub unavailable: bool,
    pub source: String,              // "file" | "memory"
    pub runtime_only: bool,
    pub next_retry_after: Option<String>,  // RFC3339
}

pub struct CpaClient {
    base_url: String,
    management_key: String,
    http: reqwest::Client,
}

impl CpaClient {
    pub fn new(base_url: &str, management_key: &str) -> Result<Self>; // management_key = raw key, no "Bearer "
    pub async fn list_codex_files(&self) -> Result<Vec<CpaAuthEntry>>;
    pub async fn download_file(&self, name: &str) -> Result<Bytes>;
    pub async fn delete_file(&self, name: &str) -> Result<()>;
    pub async fn upload_file(&self, name: &str, data: &[u8]) -> Result<()>;
    // PATCH /v0/management/auth-files/status  body: {"name":..., "disabled":...}
    pub async fn set_disabled(&self, name: &str, disabled: bool) -> Result<()>;
}
```

`reqwest::Client` 每次巡查新建、结束后 drop，不长期持有连接池。`list_codex_files()` 需要先按 `source=file` 且 `runtime_only=false` 过滤后再返回 `CpaAuthEntry`；若实现上更方便，也可以先解析为 `serde_json::Value` 过滤后再映射，避免误处理 `source=memory` 条目。

### 6.3 `cpa_manager.rs`

```rust
pub struct InspectResult {
    pub started_at: String,
    pub finished_at: String,
    pub ok: bool,
    pub error: Option<String>,

    pub total_codex: usize,
    pub candidates_401: usize,
    pub moved_to_abnormal: usize,
    pub candidates_exhausted: usize,
    pub moved_to_normal_exhausted: usize,

    pub supplement_target: usize,
    pub supplement_before: usize,
    pub supplement_needed: usize,
    pub supplement_done: usize,

    pub moved_abnormal_names: Vec<String>,
    pub moved_exhausted_names: Vec<String>,
    pub supplemented_names: Vec<String>,
    pub errors: Vec<String>,
}

pub struct CpaManager {
    store: Arc<CredentialStore>,
    status_store: Arc<CredentialStatusStore>,
    write_coordinator: Arc<WriteCoordinator>,
    backup: Arc<BackupCoordinator>,
    scheduler: SchedulerHandle,
    cpa_log: Arc<CpaLog>,
    running: Mutex<()>,
    last_result: Mutex<Option<InspectResult>>,
}

impl CpaManager {
    pub async fn inspect_once(&self, cfg: &CpaConfig) -> InspectResult;
}
```

**巡查流程**：

```
1. 获取 running 锁（防并发，若已在运行则立即返回错误）
2. write_coordinator.ensure_writes_allowed()?（不在 restore 期间）
3. 创建 CpaClient
4. list_codex_files()（仅处理 `provider/type=codex` 且 `source=file` 且 `name` 以 `.json` 结尾的条目；跳过 runtime_only/source=memory）
5. 清理 disabled 残留：
   对 disabled=true 的 codex 条目，若本地 Normal 或 Abnormal 区存在同文件名的副本
   → 直接 delete_file(name)，[INFO] 记录（上次操作遗留的禁用副本）
6. 识别 401 候选 + exhausted 候选（排除 disabled=true 的条目，已在步骤5处理）
7. 若 safety_abort_enabled：
   检查 401_count / total_codex >= safety_ratio → 跳过本轮移除，记录警告
8. 处理 401 候选（异常凭证）：
   对每个候选执行 move_from_cpa(entry, Abnormal, resets_at=None)
9. 处理 exhausted 候选：
   对每个候选按 `error.resets_at`、`next_retry_after`、`error.resets_in_seconds` 的顺序计算恢复时间，执行 move_from_cpa(entry, Normal, resets_at)
10. 若 auto_supplement_enabled：
    a. 重新 list_codex_files()（获取巡查后真实剩余数量）
    b. need = supplement_target - remaining（若 <= 0 则跳过）
    c. local_healthy = scan Normal zone，筛选条件：
       - 仅选择可解析的 codex 凭证（排除 parse_error）
       - refresh_token 非空
       - email 非空
       - 过滤 cpa_exhausted=true 的
    d. cpa_emails = CPA 条目的 email 集合（忽略空值）
    e. candidates = local_healthy 中 email 不在 cpa_emails 的（最多取 need 个）
    f. 逐个执行 supplement_to_cpa(local_key)
11. 若本轮成功写入/删除了本地凭证或 status：调用 `backup.mark_dirty()`，并在结束后 `scheduler.wake()`
12. 释放 running 锁，保存 last_result
```

---

**原子移动流程 `move_from_cpa(entry, target_zone, resets_at)`**：

策略：**先禁用 CPA 凭证，再操作**。禁用后 CPA 会从后续选择中排除该 token；已在执行中的上游请求不保证被强制中断，这个残余窗口接受，不再为此引入更重的分布式协调。失败时回滚为“重新启用”，比先删后补更容易恢复。

```
① 生成 local_name
   优先保留 CPA 原文件名 `entry.name`；
   若为空，则解析下载 JSON 后走 `import_key_for("", credential)`，回退为 `{email}.json`

② 冲突检查
   若同 key 已存在于 Normal 或 Abnormal 区 → [WARN] 跳过，不动 CPA

③ set_disabled(entry.name, true)           ← 禁用，CPA 立即停止使用此 token
   失败 → [ERROR] 跳过，CPA 未修改

   ── 禁用成功后：在“本地未成功写入凭证文件”之前，失败均执行 re-enable(entry.name) 回滚 ──

④ download_file(entry.name) → bytes
   失败 → re-enable，[ERROR] 跳过

⑤ 校验 bytes
   - 合法 JSON ✓
   - type == "codex" ✓
   - refresh_token 非空 ✓
   任一失败 → re-enable，[ERROR] 跳过

⑥ 获取 `write_coordinator.lock_activity().await`
   说明：与 `refresh_one()`、`restore` 共用一把全生命周期锁；该锁从这里一直持有到步骤⑩结束，
         防止本地刷新并发，也防止 restore 在“本地提交成功但远端尚未 delete”之间插入

⑦ 记录 `generation = write_coordinator.generation()`
   说明：后续进入 commit 前必须校验 generation 仍然一致，避免 restore 在远程调用期间切换了本地数据代际

⑧ write_coordinator.ensure_writes_allowed()?
   失败（restore 中）→ re-enable，[WARN] 跳过

⑨ 获取 `write_coordinator.lock_commit().await`
   在 commit lock 内再次检查本地冲突，并执行 `write_coordinator.ensure_generation_current(generation)?`
   然后执行：
   - store.write_bytes(target_zone, local_name, &bytes)
   - 若为 exhausted 导入：`status_store.set_cpa_exhausted(local_name, resets_at)`，这是与文件落盘同等重要的本地提交步骤
   - 若 `set_cpa_exhausted` 失败：删除刚写入的本地文件，再 re-enable，整个导入视为失败
   - 成功后释放 commit lock
   - `store.write_bytes` 失败 → re-enable，[ERROR] 跳过
   - `ensure_generation_current(generation)` 失败 → re-enable，[WARN] 跳过（restore 已切换本地数据，丢弃本次旧事务结果）

   ── 本地写入成功后，不再 re-enable ──

⑩ 在仍持有 `activity_lock` 的前提下执行 delete_file(entry.name)
   成功 → 保持步骤⑨已写入的 status，仅记录 [INFO]
   失败 → [WARN] 记录 CPA 禁用残留，不回滚本地（CPA 该凭证已禁用不会被使用，
           本地已有活跃副本，两者无冲突，下次巡查清理残留）
```

关键保证：
- **步骤③禁用后**，CPA 后续不会再选中该 token；已在执行中的请求可能仍会收尾
- **步骤③-⑨在本地提交成功前发生失败** 均通过 re-enable 回滚到初始状态，无副作用
- **步骤⑨一旦本地文件和必要 status 已同时提交成功**：不再 re-enable，避免产生“双活”凭证；后续只允许“CPA 禁用残留 + 下次巡查清理”
- **步骤⑩删除失败** 时 CPA 留有禁用副本（无害），本地有活跃副本，无冲突，无需回滚
- 下次巡查时，`disabled=true` 的残留条目会被识别并补充删除（见巡查流程步骤5）

---

**原子补号流程 `supplement_to_cpa(local_key)`**：

```
① 获取 `write_coordinator.lock_activity().await`
   说明：从读取本地字节开始就持有该锁，直到“上传成功 + 本地删除/status 清理”完成，
   防止刷新事务先读旧文件、后在 CPA 上传完成后又把本地文件写回来；restore 也必须经过同一把锁

② 记录 `generation = write_coordinator.generation()`

③ write_coordinator.ensure_writes_allowed()?
   失败（restore 中）→ [WARN] 跳过

④ read_bytes(Normal, local_key) → bytes
   失败 → [ERROR] 跳过

⑤ 校验 bytes
   - 合法 JSON ✓
   - type == "codex" ✓
   - refresh_token 非空 ✓
   任一失败 → [ERROR] 跳过（不上传 CPA）

⑥ upload_file(local_key 的文件名部分, bytes)
   失败 → [ERROR] 跳过，不动本地

⑦ 获取 `write_coordinator.lock_commit().await`
   在 commit lock 内执行：
   - 分支A：`write_coordinator.ensure_generation_current(generation)` 失败
            → [WARN]
              尝试 delete_file(local_key 的文件名部分) 从 CPA 删回（回滚上传）
              若回滚也失败 → [ERROR] 记录 CPA 侧残留
   - 分支B：generation 校验通过，但 `store.delete(Normal, local_key)` 失败
            → [ERROR]
              尝试 delete_file(local_key 的文件名部分) 从 CPA 删回（回滚上传）
              若回滚也失败 → [ERROR] 记录双份残留，需人工处理
   - 分支C：本地文件删除成功
            → `status_store.remove(local_key)`（best-effort：失败仅记录 [WARN]，不回滚 CPA，不影响补号最终一致性）
   成功 → [INFO] 记录
```

---

local_name 生成：优先保留 `CpaAuthEntry.name`；若为空则解析下载 JSON 并用 `import_key_for("", credential)` 生成，仍失败则 `[ERROR]` 跳过。

### 6.4 `cpa_scheduler.rs`

```rust
pub struct CpaSchedulerHandle {
    manager: Arc<CpaManager>,
    config_store: Arc<CpaConfigStore>,
    notify: Arc<Notify>,
}

impl CpaSchedulerHandle {
    pub fn start(manager: Arc<CpaManager>, config_store: Arc<CpaConfigStore>) -> Self;
    pub fn wake(&self);  // 配置保存后调用，重新计算下次执行时间
}
```

调度逻辑：
- 每次唤醒时（无论 enabled/disabled）：先调用 `check_exhausted_resets(status_store)` — 扫描耗尽凭证，若重置时间已过则清除标记，写 cpa.log
- 若 disabled：等待 notify 或 60s 超时后继续循环
- 若 enabled：计算下次执行时间（上次 + interval），sleep 到时执行巡查，记录 last_result

### 6.5 `cpa_log.rs`

```rust
pub struct CpaLog {
    path: PathBuf,   // state/logs/cpa.log
    max_bytes: u64,  // 1MB
    lock: Mutex<()>,
}

impl CpaLog {
    pub fn new(state_dir: &Path) -> Result<Self>;
    pub fn write(&self, msg: &str) -> Result<()>;
    // 格式: "{timestamp} {msg}\n"，超 max_bytes 时 truncate（同 LogManager 行为）
    pub fn read_tail(&self, limit_lines: usize) -> Result<String>;
    pub fn read_bytes(&self) -> Result<Vec<u8>>;
    pub fn clear(&self) -> Result<()>;
}
```

日志前缀规范：`[INFO]`/`[WARN]`/`[ERROR]`，前端在 `<pre>` 中渲染时对含 `[WARN]`/`[ERROR]` 的行着橙色/红色。
前端展示最近 `50` 行即可，并复用现有“状态”标签页日志面板的渲染逻辑；CPA 只保持独立日志文件、独立接口和独立按钮动作，不另起一套日志渲染基础设施。

不参与 S3 备份：`backup.rs` 的 `build_snapshot_archive` 只打包 credentials/ 和 credential_status.json，logs/ 不在备份范围。

---

## 七、AppState 扩展

在 `src/web.rs` 的 `AppState` 中新增：

```rust
pub cpa_config: Arc<CpaConfigStore>,
pub cpa_manager: Arc<CpaManager>,
pub cpa_scheduler: CpaSchedulerHandle,
pub cpa_log: Arc<CpaLog>,
```

初始化顺序：
1. `CpaLog::new(&state_dir)`
2. `CpaConfigStore::load(&state_dir)`
3. `CpaManager::new(store, status_store, write_coordinator, backup, scheduler, cpa_log)`
4. `CpaSchedulerHandle::start(cpa_manager, cpa_config)`

---

## 八、API 路由（`src/api.rs` 新增）

```
GET    /api/cpa/config            返回配置（`management_key_set` 脱敏标记）
PUT    /api/cpa/config            更新配置（key 为空则不修改）
GET    /api/cpa/status            返回调度状态 + last_result
POST   /api/cpa/inspect-once      立即巡查一次（同步等待结果）
GET    /api/cpa/logs?limit=50     最后 N 行日志（响应结构与现有 `/api/logs` 对齐，便于前端复用）
GET    /api/cpa/logs/download     下载完整日志文件
POST   /api/cpa/logs/clear        清空日志
```

---

## 九、并发与竞态分析

| 场景 | 影响 | 处理方式 |
|------|------|---------|
| CPA 写入文件 vs restore | restore 覆盖本地后，迁移流程再删除 CPA，导致凭证两边都丢；或旧事务跨代落盘 | restore 必须先获取同一把 `activity_lock` 再执行 `begin_restore()`；迁移/补号在持锁期间完成本地提交和远端 delete，commit 前仍用 `generation` 校验兜底 |
| CPA 写入文件 vs 调度器读取 | 该轮未扫到新文件 | 可接受：下轮自动捡起；写入是原子操作 |
| CPA 写入文件 vs 备份 | 备份可能缺少刚写入的文件 | 可接受：下次备份会包含；备份是只读操作 |
| CPA 写入 status vs 调度器写入 status | 状态丢失 | `CredentialStatusStore` 内部 Mutex + 原子 JSON 写入 |
| CPA 巡查并发触发 | 重复操作 | `CpaManager.running: Mutex<()>` 防并发 |
| 补号删本地 vs 自动刷新 / 手动单个刷新 / 手动全量刷新 | 刷新先读旧文件、后又把本地副本写回，形成双份凭证 | 为 `refresh_one()` 与 CPA 本地迁移流程新增共用的 `activity_lock`，补号从“读本地字节”开始持锁直到“上传成功 + 本地删除完成” |
| CPA 从远端导入到正常区 vs 刷新调度 | 新导入文件刚写入就被提前刷新、或 status 尚未写完就被读取 | 在导入本地文件和写 exhausted/status 时使用 `activity_lock + commit_lock`，写完后再 `scheduler.wake()` |
| CPA 禁用远端凭证 vs CPA 正在执行中的上游请求 | 已发出的请求可能继续收尾 | 接受该残余窗口；`disabled=true` 仅保证后续不会再选中该 auth，不新增更重的取消机制 |

结论：维持现有 `commit_lock + restore freeze + generation`，并在 `WriteCoordinator` 中额外增加一把轻量 `activity_lock`，专门串行化“刷新事务”“CPA 本地迁移”“restore”这三类长事务。硬性保证有两条：迁移/补号持锁期间 restore 不得插入；restore 若在远程调用前窗口切换了本地数据代际，旧事务结果不得再落盘。

---

## 十、内存影响

| 新增组件 | 常驻内存 |
|---------|---------|
| `CpaConfigStore` | < 1KB |
| `CpaLog` | < 0.5KB |
| `CpaManager` | Mutex + Option\<InspectResult\>，< 10KB |
| `CpaSchedulerHandle` | 1 个 tokio task |
| 巡查时瞬时 | 凭证列表 JSON（1000 × 500B ≈ 500KB）+ 单文件 bytes，巡查结束后 drop |

`reqwest::Client` 每次巡查新建并在结束后 drop，不新增内存采样点。

---

## 十一、前端变更

### 标签页结构

原：状态 / 凭证 / 设置（3 个）
改：状态 / 凭证 / **CPA管理** / 设置（4 个）

### CPA管理 Tab 布局

```
┌──────────────────────────────────────────────────────────────────┐
│ [卡片] 巡查操作                                   [立即巡查] btn │
│   运行中: 否  下次巡查: 2026-04-10 15:00                        │
│   上次结果: 成功  2026-04-10 14:00 → 14:00:03                   │
│   统计：total=50 | 异常候选=2 | 移入异常区=2                    │
│         耗尽候选=3 | 移入正常区=3 | 补号=5                      │
├──────────────────────────────────────────────────────────────────┤
│ [卡片] CPA 连接配置                                              │
│   □ 开启自动巡查                                                 │
│   CLIProxyAPI Base URL: [http://host:8317          ]             │
│   管理 Key: [password input] 当前：[已设置 tag]                  │
│   巡查间隔（分钟）: [60]                                         │
│   [卡片区] 安全保护                                              │
│     □ 启用异常占比保护  占比达 [50]% 则跳过本次移除             │
│   [卡片区] 自动补号                                              │
│     □ 开启自动补号  目标数量: [50]                               │
│                                            [保存配置] btn        │
├──────────────────────────────────────────────────────────────────┤
│ [卡片] CPA 日志（独立）           [刷新] [清空] [下载]          │
│   <pre> 最近 50 行，[WARN]/[ERROR] 行着色；复用现有日志渲染逻辑 </pre> │
└──────────────────────────────────────────────────────────────────┘
```

### 正常区凭证"耗尽"badge

- `cpa_exhausted=true`：渲染橙黄 badge，含重置时间（若有）
- API `GET /api/credentials?zone=normal` 响应中附加 `cpa_exhausted` / `exhausted_resets_at` 字段（从 status_store 读取）

```css
.badge-exhausted {
    background-color: #f5a623;
    color: #fff;
    font-size: 11px;
    padding: 2px 6px;
    border-radius: 3px;
    font-weight: 600;
}
```

---

## 十二、实施步骤（编码顺序）

1. `src/status.rs` — 添加 `cpa_exhausted` / `cpa_imported_at` / `exhausted_resets_at` 字段及新增方法，`list_exhausted_pending_reset()` 需同时返回恢复兜底所需的 imported_at / resets_at
2. `src/write_coordinator.rs` — 增加 `activity_lock`，供 `refresh_one()`、CPA 本地迁移、restore 共用
3. `src/transaction.rs` — `refresh_one()` 从读取凭证到提交结果全程受 `activity_lock` 保护
4. `src/backup.rs` — restore 流程在 `begin_restore()` 前先获取 `activity_lock`，直到 restore 完成后再释放
5. `src/cpa_config.rs` — CpaConfig + CpaConfigStore
6. `src/cpa_log.rs` — CpaLog
7. `src/cpa_client.rs` — CpaClient + CpaAuthEntry（含 `source` / `runtime_only` 过滤）
8. `src/cpa_manager.rs` — 巡查逻辑 + 补号逻辑（含补号后删本地）+ generation 校验与回滚 + InspectResult + `backup.mark_dirty()/scheduler.wake()`
9. `src/cpa_scheduler.rs` — CpaSchedulerHandle（含耗尽自动恢复检查）
10. `src/lib.rs` — 注册新模块
11. `src/web.rs` — AppState 新增字段，初始化
12. `src/api.rs` — 新增 `/api/cpa/*` 路由
13. `static/dashboard.html` — 新增 CPA管理 Tab
14. `static/dashboard.js` — CPA Tab 逻辑 + 凭证列表耗尽 badge + cpa.log 行着色；复用现有日志加载/渲染函数，改为可传 endpoint/container/limit
15. `static/app.css` — 耗尽 badge 样式

---

## 十三、关键参考文件

### 本项目（token-refresh）

根路径：`C:\Users\Administrator\Desktop\github\_my_project\token-refresh`

| 文件 | 用途 |
|------|------|
| `src/status.rs` | CredentialStatusRecord 结构，需新增三个耗尽字段 |
| `src/credential.rs` | CodexCredentialFile：核心字段与 JSON 序列化名称（`type`、`user-agent`） |
| `src/credential_store.rs` | write_bytes / scan_zone / delete，补号删本地使用 delete() |
| `src/write_coordinator.rs` | ensure_writes_allowed() / begin_restore()；需扩展 `activity_lock` 作为 CPA、刷新事务、restore 的共享协调器 |
| `src/logging.rs` | LogManager.append() 实现，cpa_log.rs 复用相同 truncate-on-overflow 模式 |
| `src/scheduler.rs` | CpaScheduler 结构参考（tokio task + Notify 唤醒模式） |
| `src/transaction.rs` | `refresh_one()` 的真实读写时序；必须纳入 CPA 并发设计 |
| `src/web.rs` | AppState 定义，需扩展 |
| `src/api.rs` | 现有路由模式参考，新增 /api/cpa/* |
| `src/backup.rs` | restore 入口与 build_snapshot_archive 逻辑；需让 restore 也经过 `activity_lock` |
| `static/dashboard.html` | 现有 Tab 结构，新增 CPA管理 Tab |
| `static/dashboard.js` | 凭证列表渲染逻辑，新增耗尽 badge；cpa.log 渲染行着色 |

### CLIProxyAPI 后端

根路径：`C:\Users\Administrator\Desktop\github\2api\CLIProxyAPI`

| 文件 | 用途 |
|------|------|
| `internal/api/handlers/management/auth_files.go` | 管理 API 端点实现；buildAuthFileEntry() 暴露 next_retry_after 字段 |
| `internal/runtime/executor/codex_executor.go` | parseCodexRetryAfter()：解析 error.resets_at / resets_in_seconds |
| `sdk/cliproxy/auth/types.go` | Auth 结构体；QuotaState.NextRecoverAt 字段定义 |
| `sdk/cliproxy/auth/conductor.go` | 429 处理逻辑，NextRetryAfter = resets_at 的赋值位置 |
| `sdk/cliproxy/auth/selector.go` | disabled / unavailable / quota 的实际选路阻断行为 |
| `internal/api/server.go` | 路由注册（/v0/management/auth-files 端点位置） |
| `internal/api/handlers/management/auth_files.go` `PatchAuthFileStatus()` | 禁用/启用端点实现（行 1057-1121），`disabled=true` 立即生效 |
| `internal/runtime/executor/codex_websockets_executor.go` | codexHeaderDefaults()：User-Agent 取自全局 config，不读凭证文件 |
| `sdk/cliproxy/auth/custom_headers.go` | ApplyCustomHeadersFromMetadata()：credential Metadata 字段的实际用途 |

### protocol-registration-py（CPA清理参考实现）

根路径：`C:\Users\Administrator\Desktop\github\_my_project\protocol-registration-py`

| 文件 | 用途 |
|------|------|
| `app/static/index.html` | CPA清理 Tab HTML 结构参考（行 289-429） |
| `app/static/app.js` | CPA清理 Tab JS 逻辑参考（行 956-1188） |
| `app/cpa_cleaner/client.py` | CPAMgmtClient：管理 API 调用封装参考 |
| `app/cpa_cleaner/cleaner.py` | 巡查核心逻辑参考 |
| `app/routers/cpa_cleaner.py` | API 路由定义参考 |

### codex CLI 官方仓库

根路径：`C:\Users\Administrator\Desktop\github\cli\codex`

| 文件 | 用途 |
|------|------|
| `codex-rs/core/src/api_bridge.rs` | UsageErrorResponse 结构体；resets_at 字段解析（行 72-88, 199-210） |
| `codex-rs/codex-api/src/rate_limits.rs` | RateLimitWindow；x-codex-primary-reset-at 等头部解析 |
| `codex-rs/protocol/src/protocol.rs` | RateLimitWindow.resets_at 字段定义（行 1973-1983） |

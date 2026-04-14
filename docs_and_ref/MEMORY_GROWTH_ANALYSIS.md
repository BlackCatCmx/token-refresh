# 内存持续增长分析

## 现象

- **jemalloc 部署前**：Zeabur 监控显示内存阶梯式单调上涨，约 `4MB → 14MB / 12h`，仅重启后回落。
- **jemalloc 部署后**（`a551059`）：
  - UTC+8 22:01–06:36 期间，内存在 `4–8MB` 间波动，不再单调上涨，说明 jemalloc 有释放页面的效果。
  - UTC+8 06:36 左右出现一次明显跳升（`~6MB → ~10MB`），随后继续攀升至 `~12MB`。
  - 同时段 runtime.log 中的 VmRSS 并未同步上涨，后半段反而回落（`14608 → 13152 → 11728 KB`）。
  - **关键矛盾**：Zeabur 面板持续上升 vs 进程 VmRSS 下降，说明面板指标口径 ≠ 进程 RSS，疑似包含容器级页缓存。

## 当前有效提交

| Commit | 内容 | 状态 |
|------|------|------|
| `b2c0224` | 为备份链路加入 RSS 诊断日志、S3 客户端缓存，并同步提交分析文档 | 已部署 |
| `a551059` | Linux 环境切换为 `jemalloc` 全局分配器 | 已部署，VmRSS 波动改善 |

## 已落地改动

### 1. 备份链路 RSS 诊断日志

`src/backup.rs` 已在以下路径插入运行日志：

- `run_backup_once`
- `list_snapshots`
- `restore_snapshot_inner`

当前日志字段包括：

- `backup finished` 成功摘要行
- `backup metrics` 内存调试行
- `cache`
- `rss_before_kb`
- `cg_before_kb`
- `cg_anon_before_kb`
- `cg_file_before_kb`
- `rss_after_archive_kb`
- `rss_after_upload_kb`
- `cg_after_upload_kb`
- `upload_ms`
- `rss_after_list_kb`
- `cg_after_list_kb`
- `list_ms`
- `rss_after_delete_kb`
- `cg_after_delete_kb`
- `delete_ms`
- `rss_after_drop_kb`
- `cg_after_drop_kb`
- `cg_anon_drop_kb`
- `cg_file_drop_kb`
- `archive_size_bytes`
- `snapshots_seen`
- `snapshots_deleted`
- `build_ms`
- `total_ms`

RSS 采集实现以 Linux `/proc/self/status` 中的 `VmRSS` 为准；非 Linux 环境返回 `None`。

### 2. S3 客户端缓存

`src/backup.rs` 已在 `BackupRuntime` 内缓存 `S3CompatibleClient`，按备份远端配置失效并重建。

缓存命中后：

- 不再重复执行 `S3CompatibleClient::new()`
- 不再重复构造 `Bucket::new()`
- 命中路径返回 `Arc<S3CompatibleClient>`

### 3. Linux 分配器切换

`Cargo.toml` 与 `src/main.rs` 已新增 Linux-only `jemalloc` 配置：

- 依赖：`tikv-jemallocator = "0.6"`
- 入口：Linux 环境下设置 `#[global_allocator]`

该改动仅影响 Linux 部署，不影响 Windows 本地开发环境。

## 运行时证据

以下数据来自 `b2c0224` 部署后的历史日志。该批日志时间为 UTC；当前代码已改为按 `UTC+8` 写入，便于与 Zeabur 面板对齐。

| 备份 | 本地时间（UTC+8） | cache | rss_before_kb | rss_after_archive_kb | rss_after_upload_kb | rss_after_kb | 常驻增量 |
|------|------|------|------|------|------|------|------|
| #1 | 2026-04-09 14:36 | `created` | 11368 | 11732 | 12236 | 11948 | `+580 KB` |
| #2 | 2026-04-09 15:03 | `hit` | 11956 | 12308 | 13168 | 13168 | `+1212 KB` |
| #3 | 2026-04-09 15:28 | `hit` | 13168 | 13560 | 14140 | 14140 | `+972 KB` |
| #4 | 2026-04-09 16:01 | `hit` | 14132 | 14152 | 14512 | 14512 | `+380 KB` |

### 关键观察

- 每次 `refresh succeeded` 后约 1 分钟，都会进入 `backup started trigger=after-refresh`。
- Zeabur 图上的内存台阶与上述 4 次备份时间一一对应。
- 第 2 次开始已经是 `cache=hit`，说明 S3 客户端缓存已生效，但 RSS 仍持续上涨。
- `rss_after_archive_kb` 的增幅普遍较小；主要增量出现在上传与旧快照清理之后。
- `archive_size_bytes` 稳定在约 `293 KB`，未触发大文件分块上传。
- `snapshots_seen=2`、`snapshots_deleted=1` 基本稳定，问题不是历史快照不断累积。

## 当前结论

### 已基本确认

- 在阶段 A（仅观察 RSS、尚未引入 cgroup 拆分）的历史样本里，触发 RSS 阶梯上涨的主要是备份链路，不是刷新链路本身。
- “每次新建 S3 客户端导致上涨”不是主因。该假设在 `cache=hit` 后继续上涨的日志下已明显降权。

### 当前最高优先级判断

- 触发 Zeabur 台阶的主增量在 `cg_file_mapped`（file-backed 映射页），而非 `cg_anon`（堆），备份上传路径的分配器碎片化假设已降权。
- jemalloc 大概率已解决匿名堆页不回落问题；Zeabur 面板偏高疑似 cgroup 口径包含 page cache 所致。

## 已排除或降权的假设

| 假设 | 当前判断 | 依据 |
|------|------|------|
| 每次备份都会新建 S3/HTTP client，导致主问题 | 降权 | 缓存生效后 `cache=hit` 仍持续上涨 |
| drop `reqwest::Client` 后会残留 Tokio 后台任务 90 秒 | 排除 | 当前 `reqwest 0.12 + hyper 1.x` 架构不支持该说法 |
| 前端轮询快照列表导致额外叠加 | 排除 | 前端仅在打开恢复弹窗时请求一次 |
| ZIP 文件缓冲长期留在堆中 | 排除 | 当前备份写入 `tempfile`，不是堆内常驻缓冲 |
| `mark_dirty` 的短任务是主因 | 降权 | 任务很短，量级不足以解释当前台阶 |

## 阶段 A 结果：jemalloc 部署后观察

`a551059` 部署后的 runtime.log 显示 `rss_before_kb` 不再单调递增，而是在 12–16MB 间波动，后半段明显回落（14608→13152→13380→11728）。这是 jemalloc 释放脏页的典型表现，说明 jemalloc 大概率已生效。

但 Zeabur 面板在 UTC+8 2026-04-10 06:56 左右仍显示内存攀升，而同时段 VmRSS 并未同步上涨。这表明 Zeabur 监控的指标口径 ≠ 进程 VmRSS，更可能包含容器级页缓存。

## 当前执行方案（阶段 B）

### 已落地改动

1. **cgroup 内存采集**：新增读取 `/sys/fs/cgroup/memory.current`（v2）或 `memory.usage_in_bytes`（v1），同时从 `memory.stat` 提取 `anon`（v2）/ `rss`（v1）和 `file`（v2）/ `cache`（v1）
2. **拆分 upload_trim_ms**：原来合并的上传+裁剪阶段拆为三段独立计时和采样：
   - `put_object_stream` 前后（`upload_ms`）
   - `list_snapshots` 前后（`list_ms`）
   - `delete_object` 前后（`delete_ms`）
3. **tempfile drop 后采样**：显式 drop 临时文件句柄后再采一次完整 MemSample（rss + cg + anon + file）

### 日志字段说明

`backup started` 新增：`cg_before_kb`、`cg_anon_kb`、`cg_file_kb`

`backup finished` 记录成功摘要：

- `archive_size_bytes`
- `snapshots_seen`
- `snapshots_deleted`
- `build_ms`
- `upload_ms`
- `list_ms`
- `delete_ms`
- `total_ms`

`backup metrics` 记录内存调试字段：

| 阶段 | 字段 |
|------|------|
| before | `rss_before_kb` `cg_before_kb` `cg_anon_before_kb` `cg_file_before_kb` |
| after archive | `rss_after_archive_kb` |
| after upload | `rss_after_upload_kb` `cg_after_upload_kb` `upload_ms` |
| after list | `rss_after_list_kb` `cg_after_list_kb` `list_ms` |
| after delete | `rss_after_delete_kb` `cg_after_delete_kb` `delete_ms` |
| after drop | `rss_after_drop_kb` `cg_after_drop_kb` `cg_anon_drop_kb` `cg_file_drop_kb` |

## 阶段 B 结果：cgroup 数据分析（2026-04-14）

### 关键数据点

`2026-04-14 05:59–06:17` 期间（无业务日志的 17 分钟空闲窗口）内存结构发生变化：

| 时间 | rss_kb | cg_kb | gap | cg_anon_kb | cg_file_kb | cg_file_mapped_kb |
|------|--------|-------|-----|-----------|------------|-------------------|
| 05:59 备份结束 | 18,172 | 12,040 | +6,132 | 8,620 | 2,440 | 420 |
| 06:17 刷新前 | 10,460 | 13,280 | −2,820 | 6,636 | 5,868 | 2,396 |
| 06:17 刷新后 | 13,496 | 16,308 | — | 6,656 | 8,636 | 5,428 |
| 06:18 之后稳定 | — | — | ~−2,600 | — | — | ~6,272 |

### 归因

**06:17 台阶（~10MB → ~16MB in Zeabur）的来源：**

- 主增量在 `cg_file_mapped`：420 KB → 6,272 KB（+5.8 MB），不在 `cg_anon`（堆）。
- 本次刷新触发 56 次 major page fault，与 file-backed 映射页（binary、共享库等）在空闲期被内核回收后重新载入的信号一致。
- 变化分两段发生：空闲期已从 420→2,396 KB，刷新执行时再从 2,396→5,428 KB。
- 06:18 之后 `cg_file_mapped` 稳定在 ~6,272 KB，推测映射页保持热态。
- **注意**：以上为日志间接推断，未经 `/proc/self/smaps` 直接验证，无法确认具体是哪些文件。

**备份期间的波动：**

- 每次备份期间 `cg` 会额外上涨 2–4 MB，日志只能直接证明“上涨发生在备份窗口内”；是否主要来自临时 zip 文件页缓存，当前仍属推测。
- 备份后的 `cg` 常在下一次刷新前出现回落，但回落并非总是在备份结束瞬间完成，因此不宜表述为“备份结束后立即回落”。
- `cg_file_drop_kb` 在 `06:33 → 08:37` 这一段从 `9880` 递增到 `9908`，约每次备份 `+4 KB`，7 个增量共 `+28 KB`；量级极小，原因不明，暂可忽略。

### 当前判断

| 问题 | 判断 | 置信度 |
|------|------|--------|
| 是否存在堆泄漏 | 大概率否。`cg_anon` 无单调上涨，jemalloc 已改善匿名页不回落 | 高 |
| 06:17 台阶原因 | 推测为 file-backed 映射页重新载入（pgmajfault=56 为主要依据） | 中 |
| 历史“备份导致台阶”结论是否仍成立 | 对阶段 A 的 RSS 样本仍成立，但不足以解释 2026-04-14 06:17 这次台阶 | 中 |
| Zeabur 面板偏高 | 疑似 cgroup 口径包含 page cache，与 VmRSS 指标不同 | 高 |
| 是否需要改代码 | 当前证据不支持存在值得修的泄漏，建议观察 | 中 |

### 日志插点的边界

- 现有插点已足够判断"是否存在需要修的泄漏"。
- 05:59–06:17 空闲窗口内的内存变化发生在应用代码之外（内核页回收/重载），无法通过增加业务日志捕获。
- 若需精确归因"5MB 映射页来自哪个文件"，需在 `cg_file_mapped` 超阈值时触发 `/proc/self/smaps` 快照，这是另一种采集机制，不是更多 `info!()` 能解决的。

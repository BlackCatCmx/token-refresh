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

- 触发 RSS 阶梯上涨的是备份链路，不是刷新链路本身。
- “每次新建 S3 客户端导致上涨”不是主因。该假设在 `cache=hit` 后继续上涨的日志下已明显降权。

### 当前最高优先级判断

- 最可疑的原因是 Linux 默认分配器在备份上传路径上的页面保留或碎片化。
- 具体触发路径更接近以下阶段：
  - `put_object_stream`
  - `list_snapshots`
  - `delete_object`
- 这更像“临时分配释放后 RSS 不回落”，而不是已经证明存在活对象永久泄漏。

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

### 目标

一轮日志（2–3 次备份）即可判断：

- VmRSS 涨但 cg 不涨 → 不太可能
- cg 涨但 VmRSS 不涨 → 页缓存 / 容器层内存
- `cg_file` 涨明显 → 临时文件页缓存未回收
- `cg_anon` 涨明显 → 堆分配未释放

### 日志字段说明

`backup started` 新增：`cg_before_kb`、`cg_anon_kb`、`cg_file_kb`

`backup finished` 新增（替代原 `upload_trim_ms` 和 `rss_after_kb`）：

| 阶段 | 字段 |
|------|------|
| before | `rss_before_kb` `cg_before_kb` `cg_anon_before_kb` `cg_file_before_kb` |
| after archive | `rss_after_archive_kb` |
| after upload | `rss_after_upload_kb` `cg_after_upload_kb` `upload_ms` |
| after list | `rss_after_list_kb` `cg_after_list_kb` `list_ms` |
| after delete | `rss_after_delete_kb` `cg_after_delete_kb` `delete_ms` |
| after drop | `rss_after_drop_kb` `cg_after_drop_kb` `cg_anon_drop_kb` `cg_file_drop_kb` |

## 当前判断边界

- jemalloc 大概率已解决进程堆级别的 RSS 不回落问题。
- Zeabur 面板攀升的根因尚需 cgroup 数据确认，最大嫌疑是容器页缓存。
- 新日志无需额外依赖，仅读取 procfs / cgroupfs。

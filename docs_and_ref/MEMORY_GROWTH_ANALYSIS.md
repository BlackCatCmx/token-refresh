# 内存持续增长分析

## 现象

- Zeabur 监控显示进程 RSS 随时间阶梯式上涨，约 `4MB -> 14MB / 12h`，仅重启后回落。
- 2026-04-09 的 2 小时观测窗口内，RSS 再次出现 `2MB -> 3MB -> 4MB -> 5MB -> 6MB` 的阶梯上涨。
- 最新运行日志已证明：每一次台阶都与 `after-refresh` 自动备份时间高度一致。

## 当前有效提交

| Commit | 内容 | 状态 |
|------|------|------|
| `b2c0224` | 为备份链路加入 RSS 诊断日志、S3 客户端缓存，并同步提交分析文档 | 已部署并产生日志 |
| `a551059` | Linux 环境切换为 `jemalloc` 全局分配器 | 已提交，待部署验证 |

> 说明：此前用于过渡的本地提交已被整理，以上为当前应参考的有效提交。

## 已落地改动

### 1. 备份链路 RSS 诊断日志

`src/backup.rs` 已在以下路径插入运行日志：

- `run_backup_once`
- `list_snapshots`
- `restore_snapshot_inner`

当前日志字段包括：

- `cache`
- `rss_before_kb`
- `rss_after_archive_kb`
- `rss_after_upload_kb`
- `rss_after_kb`
- `archive_size_bytes`
- `snapshots_seen`
- `snapshots_deleted`
- `build_ms`
- `upload_trim_ms`
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

以下数据来自 `b2c0224` 部署后的实际日志。日志时间为 UTC，Zeabur 面板按 `UTC+8` 显示。

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

## 当前执行方案

### 阶段 A：保留现有日志，部署 `a551059`

目标：

- 验证切换到 `jemalloc` 后，备份结束时 RSS 是否能回落到接近备份前水平。

预期：

- 备份过程中的瞬时 RSS 仍可能升高。
- 若 `jemalloc` 有效，`rss_after_kb` 应明显低于当前日志中的持续抬升趋势。

### 阶段 B：若 `a551059` 部署后仍持续台阶上涨

下一步仅继续细化备份链路日志，不扩大排查范围：

- `put_object_stream` 前后
- `list_snapshots` 前后
- 每次 `delete_object` 前后

目标是区分：

- 上传抬高 RSS
- 列举快照抬高 RSS
- 删除旧快照抬高 RSS

## 当前判断边界

- 现有日志已足以证明“备份链路触发 RSS 台阶上涨”。
- 现有日志尚不足以区分“分配器行为”与“库内部保留对象”各自占比。
- `jemalloc` 是当前成本最低、最适合先行验证的缓解方案。

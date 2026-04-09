# 内存持续增长分析

> 现象：进程 RSS 随时间阶梯式上涨（4MB→14MB/12h），仅重启后恢复。
>
> 分析方法：纯静态代码审查，**未经运行时验证**。下列排序为嫌疑优先级，不等于已确认的根因。

```
Zeabur 平台内存监控（12h 窗口）

14MB |                                              ██
13MB |                                            ██
     |
 9MB |                                      ████
     |
 5MB |                    ████████████████████
 4MB | ███████████████████
     |
     +----------------------------------------------------→
     22:51    00:34    02:17    04:00    05:43    07:26    09:09    重启→4MB
```

---

## Phase 1 — 诊断 + 修复

先插入诊断日志建立 baseline，再实施代码修复，部署后观察 RSS 曲线。

---

### D1 插入备份前后 RSS 诊断日志

在 `run_backup_once` 入口和出口各记录一次进程 RSS，用于验证"每次备份是否抬高 RSS"。

```rust
// 位置：backup.rs run_backup_once 入口/出口
// 注意：/proc/self/statm 仅 Linux 可用，需 cfg(target_os = "linux")
fn rss_kb() -> Option<u64> {
    std::fs::read_to_string("/proc/self/statm").ok()
        .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map(|pages| pages * 4) // 假设 4 KB/page，实际实现应取 sysconf(_SC_PAGESIZE)
}
logger.runtime("info", format!("backup:before trigger={} rss={}KB", trigger, rss_kb().unwrap_or(0)));
// ... 备份逻辑 ...
logger.runtime("info", format!("backup:after trigger={} rss={}KB", trigger, rss_kb().unwrap_or(0)));
```

部署后从日志即可判断：
- 每次 backup:after 比 backup:before 高多少
- 下一次 backup:before 是否回落到上一次 backup:after 附近

---

### F1 缓存 S3 客户端，配置变更时才重建

每次备份 / list_snapshots / restore 都 `S3CompatibleClient::new()`，内部 `Bucket::new()` 创建新的 HTTP 客户端（含 TLS 上下文、连接池结构等）。高频创建/销毁产生大量中小型堆分配，高度怀疑会在 glibc malloc arena 中留下碎片，导致 RSS 高水位逐步上移。

**涉及位置：**
- `backup.rs:267` — `run_backup_once`
- `backup.rs:146` — `list_snapshots`
- `backup.rs:354` — `restore_snapshot_inner`

**修复：** 在 `BackupRuntime` 中持有 `RwLock<Option<S3CompatibleClient>>`，首次使用时 lazy 创建，配置变更时置 None 令下次重建。

---

## Phase 2 — 观察项（Phase 1 无效时再考虑）

以下条目在 Phase 1 修复后若 RSS 曲线仍未改善，再逐个排查。

---

### W1 `mark_dirty` spawn 噪声

每次成功刷新都 `tokio::spawn` 一个只写两个 RwLock 的微型 task（`backup.rs:113–126`）。单个 task 微秒级完成，但批量刷新 N 个凭证时密集 spawn，在分配器层面产生轻微噪声。

**若需优化：** 改为 `pub async fn mark_dirty(&self)` 调用方直接 `.await`，或改为纯 `notify_waiters()` 在 background_loop 中统一处理。

---

### W2 glibc malloc arena 碎片化

备份链路（ZIP 压缩、凭证读取、HTTP 请求/响应 buffer）反复分配/释放较小的对象，glibc arena 通常不会将这些页面归还 OS，RSS 只升不降。

这不是代码 bug，是 glibc 分配器的常见行为。F1 的 S3 client 缓存能降低分配/释放频率。若仍有问题，替换为 jemalloc（`tikv-jemallocator` crate）或设置 `MALLOC_TRIM_THRESHOLD_` / `MALLOC_MMAP_THRESHOLD_` 环境变量。

---

### W3 `read_tail_lines` 全文读入

`logging.rs:203–214` 每次 `/api/logs` 请求都 `fs::read_to_string` 整个日志文件（默认上限 1 MiB），再取最后 N 行。较大的分配通常由 glibc 通过 mmap 处理（free 时归还 OS），但具体阈值取决于运行时配置，影响程度待 D1 日志验证。

**若需优化：** 改为从文件尾部 seek 读取最后 N 行，避免全文分配。

---

### W4 RefreshClient HTTP 客户端缓存永不 evict

`refresh_client.rs:17` — `HashMap<ClientKey, reqwest::Client>` 只增不减。key = `(timeout, proxy_url)`，配置不变时 entry 数固定（bounded）。仅在修改代理/超时配置后残留旧 entry。

**若需优化：** 配置变更时清空整个 HashMap。

---

### W5 `backoff_until` 孤立条目

`scheduler.rs:107` — 凭证删除后 backoff entry 残留。每条 ~100 bytes，影响可忽略。

**若需优化：** 删除凭证时同步清理 backoff 条目。

---

## 已排查的假设

| 假设 | 结论 | 依据 |
|------|------|------|
| drop reqwest::Client 后 Tokio 后台任务滞留 90 秒 | 可能性低 | reqwest 0.12 + hyper 1.x 架构上不存在此行为，但 rust-s3 内部 HTTP 实现未逐层验证 |
| list_snapshots 被前端轮询导致 S3 client 加速叠加 | 排除 | 代码确认：前端仅在打开还原 modal 时调用一次 |
| ZIP 写入缓冲留在堆中累积 | 排除 | 代码确认：当前实现写入 tempfile（文件 I/O），不在堆中 |

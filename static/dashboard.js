let schedulerPollTimer = null;
let schedulerManualActive = false;
let backupStatusCache = null;
// Keep this aligned with the backend clamp in src/api.rs.
const LOG_LINE_LIMIT = 50;
// Deterministic abnormal credential codes mirrored from backend refresh classification.
const ABNORMAL_LOG_CODES = [
  "refresh_token_expired",
  "refresh_token_reused",
  "refresh_token_invalidated",
  "missing_refresh_token",
  "invalid_json",
  "invalid_user_agent",
];

async function api(url, options = {}) {
  const response = await fetch(url, options);
  if (response.status === 401) {
    location.reload();
    throw new Error("未登录");
  }
  if (!response.ok) {
    const data = await response.json().catch(() => ({ message: "请求失败" }));
    throw new Error(data.message || "请求失败");
  }
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return response.json();
  }
  return response;
}

async function refreshAll() {
  await Promise.all([
    loadScheduler(),
    loadBackupStatus(),
    loadSettings(),
    loadCredentials("normal"),
    loadCredentials("abnormal"),
    reloadLog("runtime"),
    reloadLog("audit"),
  ]);
}

async function loadScheduler() {
  const data = await api("api/scheduler/status");
  const container = document.getElementById("scheduler-status");
  const manualState = data.manual_running ? "执行中" : data.manual_pending ? "排队中" : "空闲";
  const manualStateClass = data.manual_running || data.manual_pending ? "status-on" : "status-off";
  const manualProgress = `${data.manual_processed_count ?? 0}/${data.manual_total_count ?? 0}`;
  const manualSummary = `成功 ${data.manual_success_count ?? 0} / 失败 ${data.manual_failed_count ?? 0}`;
  const manualLastItemError = data.manual_last_item_error
    ? `${data.manual_last_item_error_key || "未知账号"}: ${data.manual_last_item_error}`
    : "无";
  container.innerHTML = `
    <span class="status-label">自动刷新</span>
    <span class="${data.enabled ? "status-on" : "status-off"}">${data.enabled ? "运行中" : "已停止"}</span>
    <span class="status-label">参与调度账号数</span>
    <span>${escapeHtml(data.scheduled_credential_count ?? "—")}</span>
    <span class="status-label">当前刷新账号</span>
    <span>${escapeHtml(data.current_key || "无")}</span>
    <span class="status-label">下一个账号刷新时间</span>
    <span>${escapeHtml(data.next_wake_at ? shortTime(data.next_wake_at) : "待定")}</span>
    <span class="status-label">最近错误</span>
    <span${data.last_error ? ' class="danger-text"' : ""}>${escapeHtml(data.last_error || "无")}</span>
    <span class="status-label">手动全量刷新</span>
    <span class="${manualStateClass}">${manualState}</span>
    <span class="status-label">手动当前账号</span>
    <span>${escapeHtml(data.manual_current_key || "无")}</span>
    <span class="status-label">手动进度</span>
    <span>${escapeHtml(`${manualProgress}（${manualSummary}）`)}</span>
    <span class="status-label">最近开始时间</span>
    <span>${escapeHtml(data.manual_last_started_at ? shortTime(data.manual_last_started_at) : "未运行")}</span>
    <span class="status-label">最近结束时间</span>
    <span>${escapeHtml(data.manual_last_finished_at ? shortTime(data.manual_last_finished_at) : "未完成")}</span>
    <span class="status-label">手动最近账号异常</span>
    <span${data.manual_last_item_error ? ' class="danger-text"' : ""}>${escapeHtml(manualLastItemError)}</span>
    <span class="status-label">手动流程异常</span>
    <span${data.manual_last_run_error ? ' class="danger-text"' : ""}>${escapeHtml(data.manual_last_run_error || "无")}</span>
  `;
  const manualBtn = document.getElementById("manual-refresh-all-btn");
  const manualBusy = Boolean(data.manual_pending || data.manual_running);
  manualBtn.disabled = manualBusy;
  manualBtn.textContent = manualBusy ? "手动全量刷新执行中" : "手动全量刷新";
  if (schedulerPollTimer) {
    clearTimeout(schedulerPollTimer);
    schedulerPollTimer = null;
  }
  if (data.current_key || manualBusy) {
    schedulerPollTimer = setTimeout(() => {
      loadScheduler().catch((error) => console.error(error));
    }, 2000);
  }
  if (schedulerManualActive && !manualBusy) {
    schedulerManualActive = false;
    setTimeout(() => {
      refreshAll().catch((error) => alert(error.message));
    }, 0);
    return;
  }
  schedulerManualActive = manualBusy;
}

async function loadBackupStatus() {
  const data = await api("api/backup/status");
  backupStatusCache = data;
  const lines = [];
  lines.push(`备份功能: ${data.enabled ? "已开启" : "已关闭"}`);
  lines.push(`远端配置: ${data.configured ? "已就绪" : "未完成"}`);
  lines.push(`当前状态: ${data.restore_running ? "恢复中" : data.running ? "备份中" : "空闲"}`);
  lines.push(`最近成功: ${data.last_success_at ? shortTime(data.last_success_at) : "无"}`);
  lines.push(`下次日备份: ${data.next_daily_at ? shortTime(data.next_daily_at) : "未启用"}`);
  lines.push(`待上传改动: ${data.dirty_pending ? "有" : "无"}`);
  lines.push(`最近错误: ${data.last_error || "无"}`);
  document.getElementById("backup-meta").textContent = lines.join(" | ");
  const canOperate = Boolean(data.enabled && data.configured && !data.running && !data.restore_running);
  document.getElementById("backup-run-btn").disabled = !canOperate;
  document.getElementById("backup-restore-open-btn").disabled = !canOperate;
}

function shortTime(rfc3339) {
  const d = new Date(rfc3339);
  if (isNaN(d.getTime())) return rfc3339;
  return d.toLocaleString("zh-CN", { hour12: false });
}

async function schedulerAction(action) {
  await api(`/api/scheduler/${action}`, { method: "POST" });
  await loadScheduler();
}

async function loadSettings() {
  const data = await api("api/settings");
  document.getElementById("originator").value = data.settings.request_identity.originator;
  document.getElementById("user-agent-mode").value = data.settings.request_identity.user_agent_mode;
  document.getElementById("user-agent").value = data.settings.request_identity.user_agent;
  document.getElementById("user-agent-versions").value = data.settings.request_identity.user_agent_rules.versions;
  document.getElementById("user-agent-profiles").value = data.settings.request_identity.user_agent_rules.profiles;
  document.getElementById("user-agent-terminals").value = data.settings.request_identity.user_agent_rules.terminals;
  document.getElementById("log-level").value = data.settings.log_level;
  document.getElementById("max-file-size").value = data.settings.logging.max_file_size;
  document.getElementById("proxy-mode").value = data.settings.proxy.mode;
  document.getElementById("proxy-list").value = data.settings.proxy.list;
  document.getElementById("abnormal-threshold").value = data.settings.credential_management.abnormal_threshold;
  document.getElementById("refresh-interval").value = data.settings.refresh.interval;
  document.getElementById("lead-time").value = data.settings.refresh.lead_time;
  document.getElementById("auto-delay-min").value = data.settings.refresh.inter_refresh_delay_min;
  document.getElementById("auto-delay-max").value = data.settings.refresh.inter_refresh_delay_max;
  document.getElementById("manual-delay-min").value = data.settings.refresh.manual_inter_refresh_delay_min;
  document.getElementById("manual-delay-max").value = data.settings.refresh.manual_inter_refresh_delay_max;
  document.getElementById("failure-backoff").value = data.settings.refresh.failure_backoff;
  document.getElementById("network-timeout").value = data.settings.network.timeout;
  document.getElementById("backup-enabled").value = String(data.settings.backup.enabled);
  document.getElementById("backup-remote-type").value = data.settings.backup.remote.type;
  document.getElementById("backup-endpoint").value = data.settings.backup.remote.endpoint;
  document.getElementById("backup-region").value = data.settings.backup.remote.region;
  document.getElementById("backup-bucket").value = data.settings.backup.remote.bucket;
  document.getElementById("backup-prefix").value = data.settings.backup.remote.object_prefix;
  document.getElementById("backup-access-key-id").value = data.settings.backup.remote.access_key_id;
  document.getElementById("backup-secret-access-key").value = data.settings.backup.remote.secret_access_key;
  document.getElementById("backup-path-style").value = String(data.settings.backup.remote.path_style);
  document.getElementById("backup-daily-enabled").value = String(data.settings.backup.schedule.daily_utc_enabled);
  document.getElementById("backup-after-refresh-enabled").value = String(data.settings.backup.schedule.after_refresh_enabled);
  document.getElementById("backup-after-refresh-debounce").value = data.settings.backup.schedule.after_refresh_debounce;
  document.getElementById("backup-min-auto-interval").value = data.settings.backup.schedule.min_interval_between_auto_backups;
  syncUserAgentMode();
  renderHeaderPreview(data.header_preview);
  document.getElementById("settings-meta").textContent = `配置文件: ${data.config_path} | 环境变量锁定项: ${data.locked_fields.join(", ") || "无"}`;
  for (const field of ["originator", "user-agent-mode", "user-agent", "user-agent-versions", "user-agent-profiles", "user-agent-terminals", "log-level", "max-file-size", "proxy-mode", "proxy-list", "abnormal-threshold", "refresh-interval", "lead-time", "auto-delay-min", "auto-delay-max", "manual-delay-min", "manual-delay-max", "failure-backoff", "network-timeout", "backup-enabled", "backup-remote-type", "backup-endpoint", "backup-region", "backup-bucket", "backup-prefix", "backup-access-key-id", "backup-secret-access-key", "backup-path-style", "backup-daily-enabled", "backup-after-refresh-enabled", "backup-after-refresh-debounce", "backup-min-auto-interval"]) {
    document.getElementById(field).disabled = false;
  }
  const lockMap = {
    "request_identity.originator": ["originator"],
    "request_identity.user_agent_mode": ["user-agent-mode"],
    "request_identity.user_agent": ["user-agent"],
    "request_identity.user_agent_rules": ["user-agent-versions", "user-agent-profiles", "user-agent-terminals"],
    "request_identity.user_agent_rules.versions": ["user-agent-versions"],
    "request_identity.user_agent_rules.profiles": ["user-agent-profiles"],
    "request_identity.user_agent_rules.terminals": ["user-agent-terminals"],
    log_level: ["log-level"],
    "logging.max_file_size": ["max-file-size"],
    "proxy.mode": ["proxy-mode"],
    "proxy.list": ["proxy-list"],
    "credential_management.abnormal_threshold": ["abnormal-threshold"],
    "refresh.interval": ["refresh-interval"],
    "refresh.lead_time": ["lead-time"],
    "refresh.inter_refresh_delay_min": ["auto-delay-min"],
    "refresh.inter_refresh_delay_max": ["auto-delay-max"],
    "refresh.manual_inter_refresh_delay_min": ["manual-delay-min"],
    "refresh.manual_inter_refresh_delay_max": ["manual-delay-max"],
    "refresh.failure_backoff": ["failure-backoff"],
    "network.timeout": ["network-timeout"],
    "backup.enabled": ["backup-enabled"],
    "backup.remote.type": ["backup-remote-type"],
    "backup.remote.endpoint": ["backup-endpoint"],
    "backup.remote.region": ["backup-region"],
    "backup.remote.bucket": ["backup-bucket"],
    "backup.remote.object_prefix": ["backup-prefix"],
    "backup.remote.access_key_id": ["backup-access-key-id"],
    "backup.remote.secret_access_key": ["backup-secret-access-key"],
    "backup.remote.path_style": ["backup-path-style"],
    "backup.schedule.daily_utc_enabled": ["backup-daily-enabled"],
    "backup.schedule.after_refresh_enabled": ["backup-after-refresh-enabled"],
    "backup.schedule.after_refresh_debounce": ["backup-after-refresh-debounce"],
    "backup.schedule.min_interval_between_auto_backups": ["backup-min-auto-interval"],
  };
  for (const key of data.locked_fields) {
    for (const fieldId of lockMap[key] || []) {
      document.getElementById(fieldId).disabled = true;
    }
  }
}

function renderHeaderPreview(value) {
  document.getElementById("header-preview").textContent = JSON.stringify(value, null, 2);
}

function syncUserAgentMode() {
  const listMode = document.getElementById("user-agent-mode").value === "list";
  document.getElementById("user-agent-list-group").hidden = !listMode;
  document.getElementById("user-agent-versions-group").hidden = listMode;
  document.getElementById("user-agent-profiles-group").hidden = listMode;
  document.getElementById("user-agent-terminals-group").hidden = listMode;
  document.getElementById("user-agent-mode-hint").textContent = listMode
    ? "list 模式：直接从手写 UA 列表里抽一条。"
    : "generated 模式：按版本、系统档案和终端白名单组合出合规 UA。";
}

async function refreshHeaderPreview() {
  const data = await api("api/settings/header-preview");
  renderHeaderPreview(data.header_preview);
}

async function triggerManualRefreshAll() {
  if (!confirm("这会按手动调度配置，把正常区凭证依次全量刷新一遍。确认继续吗？")) return;
  const data = await api("api/scheduler/manual-refresh-all", { method: "POST" });
  schedulerManualActive = true;
  await loadScheduler();
  alert(data.message || "手动全量刷新已开始");
}

async function saveSettings() {
  const payload = {
    log_level: document.getElementById("log-level").value,
    logging: { max_file_size: document.getElementById("max-file-size").value },
    request_identity: {
      originator: document.getElementById("originator").value,
      user_agent_mode: document.getElementById("user-agent-mode").value,
      user_agent: document.getElementById("user-agent").value,
      user_agent_rules: {
        versions: document.getElementById("user-agent-versions").value,
        profiles: document.getElementById("user-agent-profiles").value,
        terminals: document.getElementById("user-agent-terminals").value,
      },
    },
    proxy: {
      mode: document.getElementById("proxy-mode").value,
      list: document.getElementById("proxy-list").value,
    },
    credential_management: {
      abnormal_threshold: Number(document.getElementById("abnormal-threshold").value),
    },
    refresh: {
      interval: document.getElementById("refresh-interval").value,
      lead_time: document.getElementById("lead-time").value,
      inter_refresh_delay_min: document.getElementById("auto-delay-min").value,
      inter_refresh_delay_max: document.getElementById("auto-delay-max").value,
      manual_inter_refresh_delay_min: document.getElementById("manual-delay-min").value,
      manual_inter_refresh_delay_max: document.getElementById("manual-delay-max").value,
      failure_backoff: document.getElementById("failure-backoff").value,
    },
    network: {
      timeout: document.getElementById("network-timeout").value,
    },
    backup: {
      enabled: document.getElementById("backup-enabled").value === "true",
      remote: {
        type: document.getElementById("backup-remote-type").value,
        endpoint: document.getElementById("backup-endpoint").value,
        region: document.getElementById("backup-region").value,
        bucket: document.getElementById("backup-bucket").value,
        object_prefix: document.getElementById("backup-prefix").value,
        access_key_id: document.getElementById("backup-access-key-id").value,
        secret_access_key: document.getElementById("backup-secret-access-key").value,
        path_style: document.getElementById("backup-path-style").value === "true",
      },
      schedule: {
        daily_utc_enabled: document.getElementById("backup-daily-enabled").value === "true",
        after_refresh_enabled: document.getElementById("backup-after-refresh-enabled").value === "true",
        after_refresh_debounce: document.getElementById("backup-after-refresh-debounce").value,
        min_interval_between_auto_backups: document.getElementById("backup-min-auto-interval").value,
      },
    },
  };
  await api("api/settings", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  await loadSettings();
  await loadBackupStatus();
  await loadScheduler();
  alert("设置已保存");
}

async function loadCredentials(zone) {
  const data = await api(`api/credentials?zone=${zone}`);
  const container = document.getElementById(`${zone}-cards`);
  container.innerHTML = "";
  document.getElementById(`${zone}-select-all`).checked = false;
  if (data.items.length === 0) {
    container.innerHTML = `<div class="empty-hint">暂无凭证</div>`;
    return;
  }
  for (const row of data.items) {
    const encodedName = encodeURIComponent(row.name);
    const statusBadge = row.zone === "abnormal"
      ? '<span class="pill pill-warn">异常区</span>'
      : '<span class="pill">正常</span>';
    const failure = row.last_failure_code
      ? `<div class="cred-error">${escapeHtml(row.last_failure_code)} (${row.consecutive_failure_count})${row.last_failure_reason ? " — " + escapeHtml(row.last_failure_reason) : ""}</div>`
      : "";
    const parseErr = row.parse_error
      ? `<div class="cred-error">${escapeHtml(row.parse_error)}</div>`
      : "";
    const actions = zone === "normal"
      ? `<button type="button" onclick="manualRefresh('${encodedName}', this)">刷新</button>
         <button type="button" class="secondary" onclick="openCredentialEditor('${zone}','${encodedName}')">编辑</button>
         <button type="button" class="secondary" onclick="downloadCredential('${zone}','${encodedName}')">下载</button>
         <button type="button" class="danger" onclick="deleteCredential('${zone}','${encodedName}')">删除</button>`
      : `<button type="button" onclick="restoreCredential('${encodedName}')">恢复</button>
         <button type="button" class="secondary" onclick="openCredentialEditor('${zone}','${encodedName}')">编辑</button>
         <button type="button" class="secondary" onclick="downloadCredential('${zone}','${encodedName}')">下载</button>
         <button type="button" class="danger" onclick="deleteCredential('${zone}','${encodedName}')">删除</button>`;
    const card = document.createElement("div");
    card.className = `cred-card cred-card--${zone}`;
    card.innerHTML = `
      <div class="cred-card-top">
        <input type="checkbox" class="row-check card-check" data-zone="${zone}" data-name="${encodedName}" onchange="syncSelectAll('${zone}')">
        <span class="cred-name">${escapeHtml(row.name)}</span>
        ${statusBadge}
      </div>
      <div class="cred-card-info">
        <div class="cred-row"><span class="muted">邮箱</span><span>${escapeHtml(row.email || "—")}</span></div>
        <div class="cred-row"><span class="muted">最近刷新</span><span>${escapeHtml(row.last_refresh ? shortTime(row.last_refresh) : "—")}</span></div>
        <div class="cred-row"><span class="muted">过期时间</span><span>${escapeHtml(row.expired ? shortTime(row.expired) : "—")}</span></div>
      </div>
      ${failure}${parseErr}
      <div class="cred-card-actions">${actions}</div>
    `;
    container.appendChild(card);
  }
}

function selectedNames(zone) {
  return Array.from(document.querySelectorAll(`.row-check[data-zone="${zone}"]:checked`))
    .map((element) => decodeURIComponent(element.dataset.name));
}

function toggleAll(zone, checked) {
  for (const element of document.querySelectorAll(`.row-check[data-zone="${zone}"]`)) {
    element.checked = checked;
  }
}

function syncSelectAll(zone) {
  const all = Array.from(document.querySelectorAll(`.row-check[data-zone="${zone}"]`));
  const selectAll = document.getElementById(`${zone}-select-all`);
  if (all.length === 0) {
    selectAll.checked = false;
    return;
  }
  selectAll.checked = all.every((element) => element.checked);
}

function showToast(message, type = "success", duration = 3000) {
  const container = document.getElementById("toast-container");
  const toast = document.createElement("div");
  toast.className = `toast toast--${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), duration);
}

async function manualRefresh(name, btn) {
  btn.disabled = true;
  btn.classList.add("loading");

  // 分离主请求与页面重载，避免 refreshAll 失败污染刷新结果判断
  let refreshError = null;
  try {
    await api("api/credentials/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: decodeURIComponent(name) }),
    });
  } catch (error) {
    refreshError = error;
    showToast(error.message, "error");
  }

  // 无论成功失败都重拉，同步后端最新状态（失败计数、异常区迁移等）
  let reloadError = null;
  try {
    await refreshAll();
  } catch (error) {
    reloadError = error;
  }

  // 若卡片未被重绘，恢复按钮状态
  if (reloadError && btn.isConnected) {
    btn.disabled = false;
    btn.classList.remove("loading");
  }

  if (reloadError) {
    const message = refreshError
      ? `页面同步失败：${reloadError.message}`
      : `刷新已完成，但页面同步失败：${reloadError.message}`;
    showToast(message, "error", 4500);
    return;
  }

  if (!refreshError) showToast("刷新成功");
}

async function restoreCredential(name) {
  await api("api/credentials/restore", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ names: [decodeURIComponent(name)] }),
  });
  await refreshAll();
}

async function deleteCredential(zone, name) {
  if (!confirm("确认删除这个凭证吗？")) return;
  await api("api/credentials/delete", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ zone, names: [decodeURIComponent(name)] }),
  });
  await refreshAll();
}

async function deleteSelected(zone) {
  const names = selectedNames(zone);
  if (names.length === 0) {
    alert("请先选择至少一个凭证");
    return;
  }
  if (!confirm(`确认删除选中的 ${names.length} 个凭证吗？`)) return;
  await api("api/credentials/delete", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ zone, names }),
  });
  await refreshAll();
}

const credentialEditorState = {
  zone: null,
  name: null,
};

async function openCredentialEditor(zone, name) {
  try {
    const decodedName = decodeURIComponent(name);
    const data = await api(`api/credentials/content?zone=${zone}&name=${encodeURIComponent(decodedName)}`);
    credentialEditorState.zone = zone;
    credentialEditorState.name = decodedName;
    document.getElementById("credential-editor-meta").textContent = `${zone === "normal" ? "正常区" : "异常区"} / ${decodedName}`;
    document.getElementById("credential-editor-content").value = data.content;
    const modal = document.getElementById("credential-editor-modal");
    modal.classList.remove("hidden");
    modal.setAttribute("aria-hidden", "false");
    document.body.classList.add("modal-open");
    document.getElementById("credential-editor-content").focus();
  } catch (error) {
    alert(error.message);
  }
}

function closeCredentialEditor() {
  credentialEditorState.zone = null;
  credentialEditorState.name = null;
  document.getElementById("credential-editor-content").value = "";
  const modal = document.getElementById("credential-editor-modal");
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
  document.body.classList.remove("modal-open");
}

async function saveCredentialEditor() {
  if (!credentialEditorState.zone || !credentialEditorState.name) return;
  try {
    await api("api/credentials/content", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        zone: credentialEditorState.zone,
        name: credentialEditorState.name,
        content: document.getElementById("credential-editor-content").value,
      }),
    });
    closeCredentialEditor();
    await refreshAll();
    alert("凭证已保存");
  } catch (error) {
    alert(error.message);
  }
}

function downloadCredential(zone, name) {
  window.location.href = `api/credentials/download?zone=${zone}&name=${name}`;
}

function downloadCredentialArchive(zone) {
  window.location.href = `api/credentials/archive.zip?zone=${zone}`;
}

const backupRestoreState = {
  snapshots: [],
  selectedKey: null,
};

async function runBackupNow() {
  const data = await api("api/backup/run", { method: "POST" });
  await loadBackupStatus();
  showToast(`备份完成：${data.snapshot?.key || "远端快照已更新"}`);
}

async function openBackupRestoreModal() {
  try {
    const data = await api("api/backup/snapshots");
    backupRestoreState.snapshots = data.items || [];
    backupRestoreState.selectedKey = backupRestoreState.snapshots[0]?.key || null;
    const list = document.getElementById("backup-restore-list");
    if (backupRestoreState.snapshots.length === 0) {
      list.innerHTML = `<div class="empty-hint">远端没有可用备份</div>`;
    } else {
      list.innerHTML = backupRestoreState.snapshots.map((item, index) => `
        <div class="backup-snapshot-item">
          <label>
            <input type="radio" name="backup-snapshot" value="${escapeHtml(item.key)}" ${index === 0 ? "checked" : ""} onchange="selectBackupSnapshot(this.value)">
            <span class="backup-snapshot-meta">
              <span>${escapeHtml(item.key)}</span>
              <span class="muted">时间：${escapeHtml(item.created_at ? shortTime(item.created_at) : item.last_modified ? shortTime(item.last_modified) : "未知")}</span>
              <span class="muted">触发：${escapeHtml(item.trigger || "unknown")} | 大小：${escapeHtml(formatBytes(item.size || 0))}</span>
            </span>
          </label>
        </div>
      `).join("");
    }
    document.getElementById("backup-restore-confirmation").value = "";
    syncBackupRestoreConfirm();
    const modal = document.getElementById("backup-restore-modal");
    modal.classList.remove("hidden");
    modal.setAttribute("aria-hidden", "false");
    document.body.classList.add("modal-open");
  } catch (error) {
    alert(error.message);
  }
}

function closeBackupRestoreModal() {
  backupRestoreState.snapshots = [];
  backupRestoreState.selectedKey = null;
  document.getElementById("backup-restore-confirmation").value = "";
  const modal = document.getElementById("backup-restore-modal");
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
  document.body.classList.remove("modal-open");
}

function selectBackupSnapshot(value) {
  backupRestoreState.selectedKey = value;
  syncBackupRestoreConfirm();
}

function syncBackupRestoreConfirm() {
  const enabled = backupRestoreState.selectedKey
    && document.getElementById("backup-restore-confirmation").value.trim() === "确定还原";
  document.getElementById("backup-restore-submit").disabled = !enabled;
}

async function submitBackupRestore() {
  if (!backupRestoreState.selectedKey) {
    alert("请选择一个备份");
    return;
  }
  const confirmation = document.getElementById("backup-restore-confirmation").value.trim();
  if (confirmation !== "确定还原") {
    alert("请输入“确定还原”后再继续");
    return;
  }
  await api("api/backup/restore", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      snapshot_key: backupRestoreState.selectedKey,
      confirmation,
    }),
  });
  closeBackupRestoreModal();
  await refreshAll();
  showToast("备份还原完成");
}

async function importFiles() {
  const input = document.getElementById("upload-files");
  if (!input.files.length) return alert("请选择文件");
  const files = Array.from(input.files);
  input.value = "";
  const zips = files.filter((f) => f.name.toLowerCase().endsWith(".zip"));
  const jsons = files.filter((f) => f.name.toLowerCase().endsWith(".json"));
  if (zips.length > 0 && jsons.length > 0) {
    return alert("请勿混合上传 JSON 和 ZIP 文件");
  }
  if (zips.length > 1) {
    return alert("一次只能上传一个 ZIP 文件");
  }
  if (zips.length === 1) {
    const form = new FormData();
    form.append("file", zips[0], zips[0].name);
    await api("api/credentials/import-zip", { method: "POST", body: form });
  } else if (jsons.length > 0) {
    const form = new FormData();
    for (const f of jsons) form.append("files", f, f.name);
    await api("api/credentials/import-json", { method: "POST", body: form });
  } else {
    return alert("请选择 .json 或 .zip 文件");
  }
  await refreshAll();
}

function formatUserAgentPatchMessage(actionLabel, data) {
  return `${actionLabel}完成：已更新 ${data.updated} 个，未改动 ${data.unchanged} 个，跳过损坏凭证 ${data.skipped_invalid} 个`;
}

async function fillMissingUserAgents() {
  if (!confirm("只给缺少 UA 的凭证补充，已有 UA 的不改。确认继续吗？")) return;
  const data = await api("api/credentials/user-agent/fill-missing", { method: "POST" });
  await refreshAll();
  alert(formatUserAgentPatchMessage("补充 UA", data));
}

async function reassignCliVersions() {
  if (!confirm("这会只重写 UA 里的 codex_cli_rs/version 段，系统和终端信息保持不变。确认继续吗？")) return;
  const data = await api("api/credentials/user-agent/reassign-cli-version", { method: "POST" });
  await refreshAll();
  alert(formatUserAgentPatchMessage("重配 UA-cx 版本", data));
}

async function reassignAllUserAgents() {
  if (!confirm("这会强制重写全部凭证的 UA，包括原来已有 UA 的。确认继续吗？")) return;
  const data = await api("api/credentials/user-agent/reassign", { method: "POST" });
  await refreshAll();
  alert(formatUserAgentPatchMessage("重配 UA-全量", data));
}

async function reloadLog(kind) {
  const data = await api(`api/logs?kind=${kind}&limit=${LOG_LINE_LIMIT}`);
  renderLog(kind, data.content || "");
}

function downloadLog(kind) {
  window.location.href = `api/logs/download?kind=${kind}`;
}

async function clearLog(kind) {
  await api("api/logs/clear", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ kind }),
  });
  await reloadLog(kind);
}

async function logout() {
  await api("api/session/logout", { method: "POST" });
  location.reload();
}

function formatBytes(value) {
  const bytes = Number(value) || 0;
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function classifyLogLine(line) {
  const normalized = line.toLowerCase();
  if (normalized.includes("refresh succeeded") || normalized.includes("refresh_success")) {
    return "success";
  }
  if (
    normalized.includes("[error]") ||
    normalized.includes("count_towards_abnormal=true") ||
    normalized.includes("moved_to_abnormal=true") ||
    normalized.includes("final_zone=abnormal") ||
    ABNORMAL_LOG_CODES.some((code) => normalized.includes(code))
  ) {
    return "error";
  }
  if (
    normalized.includes("[warn]") ||
    normalized.includes("refresh failed") ||
    normalized.includes("refresh_failed")
  ) {
    return "warn";
  }
  return "";
}

function renderLog(kind, content) {
  const container = document.getElementById(`${kind}-log`);
  if (!content) {
    container.textContent = "";
    return;
  }
  container.innerHTML = content
    .split(/\r?\n/)
    .map((line) => {
      const tone = classifyLogLine(line);
      const className = tone ? `log-line log-line--${tone}` : "log-line";
      return `<span class="${className}">${line ? escapeHtml(line) : "&nbsp;"}</span>`;
    })
    .join("\n");
  container.scrollTop = container.scrollHeight;
}

function switchTab(tabId) {
  for (const panel of document.querySelectorAll(".tab-panel")) {
    panel.classList.toggle("hidden", panel.id !== "tab-" + tabId);
  }
  for (const btn of document.querySelectorAll(".tab-btn")) {
    btn.classList.toggle("active", btn.dataset.tab === tabId);
  }
}

window.refreshAll = refreshAll;
window.refreshHeaderPreview = refreshHeaderPreview;
window.schedulerAction = schedulerAction;
window.triggerManualRefreshAll = triggerManualRefreshAll;
window.saveSettings = saveSettings;
window.syncUserAgentMode = syncUserAgentMode;
window.manualRefresh = manualRefresh;
window.restoreCredential = restoreCredential;
window.deleteCredential = deleteCredential;
window.deleteSelected = deleteSelected;
window.downloadCredential = downloadCredential;
window.downloadCredentialArchive = downloadCredentialArchive;
window.openCredentialEditor = openCredentialEditor;
window.closeCredentialEditor = closeCredentialEditor;
window.saveCredentialEditor = saveCredentialEditor;
window.importFiles = importFiles;
window.fillMissingUserAgents = fillMissingUserAgents;
window.reassignCliVersions = reassignCliVersions;
window.reassignAllUserAgents = reassignAllUserAgents;
window.runBackupNow = runBackupNow;
window.openBackupRestoreModal = openBackupRestoreModal;
window.closeBackupRestoreModal = closeBackupRestoreModal;
window.selectBackupSnapshot = selectBackupSnapshot;
window.syncBackupRestoreConfirm = syncBackupRestoreConfirm;
window.submitBackupRestore = submitBackupRestore;
window.reloadLog = reloadLog;
window.downloadLog = downloadLog;
window.clearLog = clearLog;
window.logout = logout;
window.toggleAll = toggleAll;
window.syncSelectAll = syncSelectAll;
window.switchTab = switchTab;

document.addEventListener("DOMContentLoaded", () => {
  refreshAll().catch((error) => alert(error.message));
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !document.getElementById("credential-editor-modal").classList.contains("hidden")) {
    closeCredentialEditor();
    return;
  }
  if (event.key === "Escape" && !document.getElementById("backup-restore-modal").classList.contains("hidden")) {
    closeBackupRestoreModal();
  }
});

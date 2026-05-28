let schedulerPollTimer = null;
let schedulerManualActive = false;
let backupStatusCache = null;
let credPageSize = 50;
let backupRemoteDrafts = [];
let backupRemotesLocked = false;
const credState = {
  normal: { page: 1, data: [], selected: new Set() },
  abnormal: { page: 1, data: [], selected: new Set() },
};
const credentialSearchState = {
  query: "",
  minLength: 2,
};
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
    const error = new Error(data.message || "请求失败");
    error.code = data.code || "";
    throw error;
  }
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return response.json();
  }
  return response;
}

async function refreshAll() {
  await loadSettings();
  await loadBackupStatus();
  await Promise.all([
    loadScheduler(),
    loadCpaConfig(),
    loadCpaStatus(),
    loadCredentials("normal"),
    loadCredentials("abnormal"),
    reloadLog("runtime"),
    reloadLog("audit"),
    reloadCpaLog(),
  ]);
}

function createEmptyBackupRemote() {
  return {
    name: "",
    type: "s3_compatible",
    endpoint: "",
    region: "",
    bucket: "",
    object_prefix: "token-refresh",
    access_key_id: "",
    secret_access_key: "",
    path_style: true,
  };
}

function normalizeBackupRemote(remote = {}) {
  return {
    name: remote.name || "",
    type: remote.type || "s3_compatible",
    endpoint: remote.endpoint || "",
    region: remote.region || "",
    bucket: remote.bucket || "",
    object_prefix: remote.object_prefix || "token-refresh",
    access_key_id: remote.access_key_id || "",
    secret_access_key: remote.secret_access_key || "",
    path_style: remote.path_style !== false,
  };
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
  const latestBackupRemote = backupStatusCache?.latest_remote_name || "无";
  const latestBackupSnapshot = backupStatusCache?.last_snapshot_key
    ? backupStatusCache.last_snapshot_key.split("/").pop()
    : "无";
  container.innerHTML = `
    <span class="status-label">自动刷新</span>
    <span class="${data.enabled ? "status-on" : "status-off"}">${data.enabled ? "运行中" : "已停止"}</span>
    <span class="status-label">参与调度账号数</span>
    <span>${escapeHtml(data.scheduled_credential_count ?? "—")}</span>
    <span class="status-label">当前刷新账号</span>
    <span>${escapeHtml(data.current_key || "无")}</span>
    <span class="status-label">下一预计刷新账号</span>
    <span>${escapeHtml(data.next_key || "无")}</span>
    <span class="status-label">下一次调度检查</span>
    <span>${escapeHtml(formatSchedulerNextCheck(data))}</span>
    <span class="status-label">下一个未到期账号时间</span>
    <span>${escapeHtml(formatSchedulerNextDue(data))}</span>
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
    <span class="status-label">最新备份端</span>
    <span>${escapeHtml(latestBackupRemote)}</span>
    <span class="status-label">最新备份快照</span>
    <span>${escapeHtml(latestBackupSnapshot)}</span>
  `;
  const manualBtn = document.getElementById("manual-refresh-all-btn");
  const manualBusy = Boolean(data.manual_pending || data.manual_running);
  manualBtn.disabled = manualBusy;
  manualBtn.textContent = manualBusy ? "手动全量刷新执行中" : "手动全量刷新";
  if (schedulerPollTimer) {
    clearTimeout(schedulerPollTimer);
    schedulerPollTimer = null;
  }
  if (data.enabled || data.current_key || manualBusy) {
    const pollDelay = data.current_key || manualBusy ? 2000 : 5000;
    schedulerPollTimer = setTimeout(() => {
      loadScheduler().catch((error) => console.error(error));
    }, pollDelay);
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

  function v(text, cls) {
    return cls ? `<span class="${cls}">${text}</span>` : text;
  }

  const runState = data.restore_running ? v("恢复中", "status-on")
                 : data.running         ? v("备份中", "status-on")
                 : "空闲";

  const items = [
    ["💾", "备份",  data.enabled    ? v("开启", "status-on")   : v("关闭",   "status-off")],
    ["☁️",  "远端",  data.configured ? v(`就绪 (${data.configured_remote_count || 0})`, "status-on")   : v("未完成", "danger-text")],
    ["⚡",  "状态",  runState],
    ["🕐", "成功",  data.last_success_at ? shortTime(data.last_success_at) : v("无", "status-off")],
    ["🧭", "最新端", data.latest_remote_name ? escapeHtml(data.latest_remote_name) : v("无", "status-off")],
    ["📅", "日备",  formatDailyBackupStatus(data)],
    ["🔄", "刷新后", formatAfterRefreshBackupStatus(data)],
    ["📤", "待传",  data.dirty_pending ? v("有", "status-warn") : v("无", "status-off")],
    ["🔔", "错误",  data.last_error ? v(escapeHtml(data.last_error), "danger-text") : v("无", "status-off")],
  ];

  const SEP = '<span class="backup-sep">·</span>';
  const html = items
    .map(([icon, label, val]) =>
      `<span class="backup-item">${icon} <span class="muted">${label}:</span> ${val}</span>`
    )
    .join(SEP);

  document.getElementById("backup-meta").innerHTML = html;
  const canOperate = Boolean(data.enabled && data.configured && !data.running && !data.restore_running);
  document.getElementById("backup-run-btn").disabled = !canOperate;
  document.getElementById("backup-restore-open-btn").disabled = !canOperate;
}

function formatDailyBackupStatus(data) {
  if (!data.enabled) return "未启用";
  if (!data.configured) return "配置未完成";
  if (!data.next_daily_at) return "未启用";
  const displayTime = shortTime(data.next_daily_at);
  const dueAt = new Date(data.next_daily_at);
  if (isNaN(dueAt.getTime())) return displayTime;
  if (dueAt.getTime() <= Date.now()) {
    return `${data.running ? "今日执行中" : "已到执行时间，等待执行"}（今日计划点 ${displayTime}）`;
  }
  return displayTime;
}

function formatAfterRefreshBackupStatus(data) {
  if (!data.enabled) return "未启用";
  if (!data.configured) return "配置未完成";
  if (!data.after_refresh_enabled) return "未启用";
  if (!data.dirty_pending) return "已启用，当前无待处理改动";
  if (!data.next_after_refresh_at) return "已启用，等待计算";
  const displayTime = shortTime(data.next_after_refresh_at);
  const dueAt = new Date(data.next_after_refresh_at);
  if (isNaN(dueAt.getTime())) return displayTime;
  if (dueAt.getTime() <= Date.now()) {
    return `${data.running ? "执行中" : "已到执行时间，等待执行"}（计划点 ${displayTime}）`;
  }
  return `预计 ${displayTime}`;
}

function formatSchedulerNextCheck(data) {
  if (data.current_key) return "执行中";
  if (!data.enabled) return "已停止";
  if (!data.next_wake_at) return "待定";
  const displayTime = shortTime(data.next_wake_at);
  const dueAt = new Date(data.next_wake_at);
  const reason = formatSchedulerWaitReason(data.wait_reason);
  if (isNaN(dueAt.getTime())) return `${displayTime}${reason}`;
  if (dueAt.getTime() <= Date.now()) {
    return `${displayTime}${reason}，等待状态刷新`;
  }
  return `${displayTime}${reason}`;
}

function formatSchedulerNextDue(data) {
  if (!data.enabled) return "待定";
  if (!data.next_due_at) return "待定";
  const displayTime = shortTime(data.next_due_at);
  const dueAt = new Date(data.next_due_at);
  if (isNaN(dueAt.getTime())) return displayTime;
  if (dueAt.getTime() <= Date.now()) {
    return `已到期（计划点 ${displayTime}）`;
  }
  return displayTime;
}

function formatSchedulerWaitReason(reason) {
  switch (reason) {
    case "inter_refresh_delay":
      return "（账号间延迟）";
    case "idle_sleep":
      return "（等待下一次检查）";
    default:
      return "";
  }
}

function shortTime(rfc3339) {
  const d = new Date(rfc3339);
  if (isNaN(d.getTime())) return rfc3339;
  return d.toLocaleString("zh-CN", { hour12: false });
}

function escapeAttr(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function renderBackupRemoteEditors() {
  const container = document.getElementById("backup-remotes-container");
  if (!container) return;
  if (!backupRemoteDrafts.length) {
    container.innerHTML = `<div class="empty-hint">当前没有备份端，点击“新增备份端”后再保存。</div>`;
    return;
  }
  container.innerHTML = backupRemoteDrafts.map((remote, index) => `
    <div class="backup-remote-card">
      <div class="backup-remote-card-header">
        <div class="backup-remote-card-title">${escapeHtml(remote.name || `备份端 ${index + 1}`)}</div>
        <div class="toolbar backup-remote-card-actions">
          <button type="button" class="secondary" onclick="moveBackupRemote(${index}, -1)" ${backupRemotesLocked || index === 0 ? "disabled" : ""}>上移</button>
          <button type="button" class="secondary" onclick="moveBackupRemote(${index}, 1)" ${backupRemotesLocked || index === backupRemoteDrafts.length - 1 ? "disabled" : ""}>下移</button>
          <button type="button" class="danger" onclick="removeBackupRemote(${index})" ${backupRemotesLocked ? "disabled" : ""}>删除</button>
        </div>
      </div>
      <div class="grid">
        <div>
          <label>名称</label>
          <input type="text" data-remote-index="${index}" data-field="name" value="${escapeAttr(remote.name)}" ${backupRemotesLocked ? "disabled" : ""}>
        </div>
        <div>
          <label>远端类型</label>
          <select data-remote-index="${index}" data-field="type" ${backupRemotesLocked ? "disabled" : ""}>
            <option value="s3_compatible" ${remote.type === "s3_compatible" ? "selected" : ""}>s3_compatible</option>
          </select>
        </div>
        <div>
          <label>S3 Endpoint</label>
          <input type="text" data-remote-index="${index}" data-field="endpoint" placeholder="https://example.com" value="${escapeAttr(remote.endpoint)}" ${backupRemotesLocked ? "disabled" : ""}>
        </div>
        <div>
          <label>Bucket</label>
          <input type="text" data-remote-index="${index}" data-field="bucket" value="${escapeAttr(remote.bucket)}" ${backupRemotesLocked ? "disabled" : ""}>
        </div>
        <div>
          <label>Access Key ID</label>
          <input type="text" data-remote-index="${index}" data-field="access_key_id" value="${escapeAttr(remote.access_key_id)}" ${backupRemotesLocked ? "disabled" : ""}>
        </div>
        <div>
          <label>Secret Access Key</label>
          <input type="password" data-remote-index="${index}" data-field="secret_access_key" autocomplete="new-password" value="${escapeAttr(remote.secret_access_key)}" ${backupRemotesLocked ? "disabled" : ""}>
        </div>
        <details class="field-expand grid-full">
          <summary>高级选项</summary>
          <div class="grid advanced-grid">
            <div>
              <label>Region</label>
              <input type="text" data-remote-index="${index}" data-field="region" placeholder="留空自动识别，失败时回退到 us-east-1" value="${escapeAttr(remote.region)}" ${backupRemotesLocked ? "disabled" : ""}>
            </div>
            <div>
              <label>备份目录前缀</label>
              <input type="text" data-remote-index="${index}" data-field="object_prefix" placeholder="留空则直接写到 snapshots/" value="${escapeAttr(remote.object_prefix)}" ${backupRemotesLocked ? "disabled" : ""}>
            </div>
            <div>
              <label>Path-style</label>
              <select data-remote-index="${index}" data-field="path_style" ${backupRemotesLocked ? "disabled" : ""}>
                <option value="true" ${remote.path_style ? "selected" : ""}>true</option>
                <option value="false" ${remote.path_style ? "" : "selected"}>false</option>
              </select>
            </div>
          </div>
          <div class="muted advanced-hint">Claw Cloud 建议保留 <code>Path-style=true</code>。Region 留空时会优先从 Endpoint 自动识别。</div>
        </details>
      </div>
    </div>
  `).join("");
}

function collectBackupRemoteInputs() {
  return Array.from(document.querySelectorAll("#backup-remotes-container .backup-remote-card")).map((_, index) => {
    const getValue = (field) => document.querySelector(`[data-remote-index="${index}"][data-field="${field}"]`)?.value ?? "";
    return {
      name: getValue("name").trim(),
      type: getValue("type"),
      endpoint: getValue("endpoint").trim(),
      region: getValue("region").trim(),
      bucket: getValue("bucket").trim(),
      object_prefix: getValue("object_prefix").trim(),
      access_key_id: getValue("access_key_id").trim(),
      secret_access_key: getValue("secret_access_key"),
      path_style: getValue("path_style") === "true",
    };
  });
}

function addBackupRemote() {
  backupRemoteDrafts = [...collectBackupRemoteInputs(), createEmptyBackupRemote()];
  renderBackupRemoteEditors();
}

function removeBackupRemote(index) {
  backupRemoteDrafts = collectBackupRemoteInputs().filter((_, current) => current !== index);
  renderBackupRemoteEditors();
}

function moveBackupRemote(index, delta) {
  const nextIndex = index + delta;
  if (nextIndex < 0 || nextIndex >= backupRemoteDrafts.length) return;
  const next = collectBackupRemoteInputs();
  const [item] = next.splice(index, 1);
  next.splice(nextIndex, 0, item);
  backupRemoteDrafts = next;
  renderBackupRemoteEditors();
}

async function schedulerAction(action) {
  await api(`api/scheduler/${action}`, { method: "POST" });
  await loadScheduler();
}

function normalizeCredentialPageSize(value) {
  const parsed = Number.parseInt(String(value), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 50;
}

function applyCredentialPageSize(value, rerenderCredentials = false) {
  const normalized = normalizeCredentialPageSize(value);
  credPageSize = normalized;
  document.getElementById("credential-page-size").value = normalized;
  if (rerenderCredentials) {
    renderCredentials("normal");
    renderCredentials("abnormal");
  }
}

async function loadSettings(rerenderCredentials = false) {
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
  document.getElementById("proxy-backup-list").value = data.settings.proxy.backup_list;
  document.getElementById("abnormal-threshold").value = data.settings.credential_management.abnormal_threshold;
  applyCredentialPageSize(data.settings.credential_management.credential_page_size, rerenderCredentials);
  document.getElementById("refresh-interval").value = data.settings.refresh.interval;
  document.getElementById("lead-time").value = data.settings.refresh.lead_time;
  document.getElementById("auto-delay-min").value = data.settings.refresh.inter_refresh_delay_min;
  document.getElementById("auto-delay-max").value = data.settings.refresh.inter_refresh_delay_max;
  document.getElementById("manual-delay-min").value = data.settings.refresh.manual_inter_refresh_delay_min;
  document.getElementById("manual-delay-max").value = data.settings.refresh.manual_inter_refresh_delay_max;
  document.getElementById("failure-backoff").value = data.settings.refresh.failure_backoff;
  document.getElementById("network-timeout").value = data.settings.network.timeout;
  document.getElementById("backup-enabled").value = String(data.settings.backup.enabled);
  backupRemoteDrafts = (data.settings.backup.remotes || []).map(normalizeBackupRemote);
  document.getElementById("backup-daily-enabled").value = String(data.settings.backup.schedule.daily_utc_enabled);
  document.getElementById("backup-after-refresh-enabled").value = String(data.settings.backup.schedule.after_refresh_enabled);
  document.getElementById("backup-after-refresh-debounce").value = data.settings.backup.schedule.after_refresh_debounce;
  document.getElementById("backup-min-auto-interval").value = data.settings.backup.schedule.min_interval_between_auto_backups;
  syncUserAgentMode();
  renderHeaderPreview(data.header_preview);
  document.getElementById("settings-meta").textContent = `配置文件: ${data.config_path} | 环境变量锁定项: ${data.locked_fields.join(", ") || "无"}`;
  for (const field of ["originator", "user-agent-mode", "user-agent", "user-agent-versions", "user-agent-profiles", "user-agent-terminals", "log-level", "max-file-size", "proxy-mode", "proxy-list", "proxy-backup-list", "abnormal-threshold", "credential-page-size", "refresh-interval", "lead-time", "auto-delay-min", "auto-delay-max", "manual-delay-min", "manual-delay-max", "failure-backoff", "network-timeout", "backup-enabled", "backup-daily-enabled", "backup-after-refresh-enabled", "backup-after-refresh-debounce", "backup-min-auto-interval"]) {
    document.getElementById(field).disabled = false;
  }
  backupRemotesLocked = false;
  document.getElementById("backup-remote-add-btn").disabled = false;
  renderBackupRemoteEditors();
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
    "proxy.backup_list": ["proxy-backup-list"],
    "credential_management.abnormal_threshold": ["abnormal-threshold"],
    "credential_management.credential_page_size": ["credential-page-size"],
    "refresh.interval": ["refresh-interval"],
    "refresh.lead_time": ["lead-time"],
    "refresh.inter_refresh_delay_min": ["auto-delay-min"],
    "refresh.inter_refresh_delay_max": ["auto-delay-max"],
    "refresh.manual_inter_refresh_delay_min": ["manual-delay-min"],
    "refresh.manual_inter_refresh_delay_max": ["manual-delay-max"],
    "refresh.failure_backoff": ["failure-backoff"],
    "network.timeout": ["network-timeout"],
    "backup.enabled": ["backup-enabled"],
    "backup.remotes": ["backup-remote-add-btn"],
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
  backupRemotesLocked = data.locked_fields.includes("backup.remotes");
  renderBackupRemoteEditors();
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
    : "generated 模式：按版本、系统档案和终端白名单组合，并追加客户端版本后缀。";
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
  try {
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
        backup_list: document.getElementById("proxy-backup-list").value,
      },
      credential_management: {
        abnormal_threshold: Number(document.getElementById("abnormal-threshold").value),
        credential_page_size: normalizeCredentialPageSize(document.getElementById("credential-page-size").value),
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
        remotes: collectBackupRemoteInputs(),
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
    await loadSettings(true);
    await loadBackupStatus();
    await loadScheduler();
    alert("设置已保存");
  } catch (error) {
    alert(error.message);
  }
}

async function loadCredentials(zone) {
  const data = await api(`api/credentials?zone=${zone}`);
  const selected = credState[zone].selected;
  const validNames = new Set(data.items.map((item) => item.name));
  credState[zone].data = data.items;
  credState[zone].selected = new Set(
    Array.from(selected).filter((name) => validNames.has(name))
  );
  renderCredentials(zone);
  renderCredentialSearchState();
}

function normalizeCredentialSearchQuery(value) {
  return String(value ?? "").trim().toLowerCase();
}

function isCredentialSearchActive() {
  return credentialSearchState.query.length >= credentialSearchState.minLength;
}

function buildCredentialSearchText(row) {
  return [
    row.name,
    row.email,
    row.account_id,
  ]
    .filter((value) => value)
    .join("\n")
    .toLowerCase();
}

function matchesCredentialSearch(row, query) {
  return buildCredentialSearchText(row).includes(query);
}

function getVisibleCredentialRows(zone) {
  const rows = credState[zone].data;
  if (!isCredentialSearchActive()) return rows;
  return rows.filter((row) => matchesCredentialSearch(row, credentialSearchState.query));
}

function updateCredentialCount(zone, visibleCount, totalCount) {
  const countEl = document.getElementById(`${zone}-count`);
  if (!countEl) return;
  countEl.textContent = isCredentialSearchActive()
    ? `(${visibleCount}/${totalCount})`
    : `(${totalCount})`;
}

function renderCredentialSearchState() {
  const input = document.getElementById("credential-search-input");
  const clearBtn = document.getElementById("credential-search-clear");
  const status = document.getElementById("credential-search-status");
  if (!input || !clearBtn || !status) return;
  clearBtn.hidden = input.value.length === 0;
  status.className = "credential-search-status muted";

  const query = credentialSearchState.query;
  if (!query) {
    status.textContent = "";
    return;
  }
  if (!isCredentialSearchActive()) {
    status.textContent = `至少输入 ${credentialSearchState.minLength} 个字符后开始过滤`;
    return;
  }

  const normalMatches = getVisibleCredentialRows("normal").length;
  const abnormalMatches = getVisibleCredentialRows("abnormal").length;
  const totalMatches = normalMatches + abnormalMatches;
  if (totalMatches === 0) {
    status.textContent = "没有匹配的凭证";
    status.className = "credential-search-status warn-text";
    return;
  }
  status.textContent = `已筛选：正常区 ${normalMatches} 条，异常区 ${abnormalMatches} 条`;
}

function updateCredentialSearch(rawValue) {
  const nextQuery = normalizeCredentialSearchQuery(rawValue);
  if (nextQuery === credentialSearchState.query) {
    renderCredentialSearchState();
    return;
  }
  credentialSearchState.query = nextQuery;
  credState.normal.page = 1;
  credState.abnormal.page = 1;
  renderCredentialSearchState();
  renderCredentials("normal");
  renderCredentials("abnormal");
}

function handleCredentialSearchInput() {
  updateCredentialSearch(document.getElementById("credential-search-input")?.value || "");
}

function clearCredentialSearch() {
  const input = document.getElementById("credential-search-input");
  if (!input) return;
  input.value = "";
  updateCredentialSearch("");
  input.focus();
}

function renderCredentials(zone) {
  const { page } = credState[zone];
  const data = getVisibleCredentialRows(zone);
  const ps = credPageSize;
  const total = data.length;
  updateCredentialCount(zone, total, credState[zone].data.length);
  const totalPages = Math.max(1, Math.ceil(total / ps));
  const clampedPage = Math.min(Math.max(1, page), totalPages);
  if (clampedPage !== credState[zone].page) credState[zone].page = clampedPage;
  const start = (clampedPage - 1) * ps;
  const pageItems = data.slice(start, start + ps);

  const container = document.getElementById(`${zone}-cards`);
  container.innerHTML = "";

  if (total === 0) {
    const emptyText = isCredentialSearchActive()
      ? "没有匹配的凭证"
      : "暂无凭证";
    container.innerHTML = `<div class="empty-hint">${emptyText}</div>`;
  } else {
    for (const row of pageItems) {
      container.appendChild(buildCredCard(zone, row));
    }
  }
  renderPager(zone, total, clampedPage, ps);
  updateSelectAllControl(zone);
}

function buildCredCard(zone, row) {
  const encodedName = encodeURIComponent(row.name);
  const statusBadge = row.zone === "abnormal"
    ? '<span class="pill pill-warn">异常区</span>'
    : '<span class="pill">正常</span>';
  const exhaustedBadge = zone === "normal" && row.cpa_exhausted
    ? `<span class="pill badge-exhausted">${escapeHtml(formatExhaustedBadge(row.exhausted_resets_at))}</span>`
    : "";
  const failureCount = Number(row.consecutive_failure_count || 0);
  const failure = row.last_failure_code
    ? `<div class="cred-error">${escapeHtml(row.last_failure_code)}${failureCount > 0 ? ` (${failureCount})` : ""}${row.last_failure_reason ? " — " + escapeHtml(row.last_failure_reason) : ""}</div>`
    : "";
  const parseErr = row.parse_error
    ? `<div class="cred-error">${escapeHtml(row.parse_error)}</div>`
    : "";
  const displayName = row.email || row.name;
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
      <input type="checkbox" class="row-check card-check" data-zone="${zone}" data-name="${encodedName}" onchange="toggleRowSelection('${zone}', '${encodedName}', this.checked)" ${credState[zone].selected.has(row.name) ? "checked" : ""}>
      <span class="cred-name">${escapeHtml(displayName)}</span>
      ${statusBadge}
      ${exhaustedBadge}
    </div>
    ${failure}${parseErr}
    <div class="cred-card-actions">${actions}</div>
  `;
  return card;
}

function formatExhaustedBadge(resetsAt) {
  if (!resetsAt) return "耗尽（~7d 后自动恢复）";
  const d = new Date(resetsAt);
  if (isNaN(d.getTime())) return `耗尽（重置于 ${resetsAt}）`;
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const min = String(d.getMinutes()).padStart(2, "0");
  return `耗尽（重置于 ${mm}/${dd} ${hh}:${min}）`;
}

function renderPager(zone, total, page, pageSize) {
  const el = document.getElementById(`${zone}-pager`);
  if (!el) return;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  if (totalPages <= 1) {
    el.innerHTML = "";
    return;
  }
  el.innerHTML = `
    <button type="button" class="secondary" onclick="goCredPage('${zone}', ${page - 1})" ${page <= 1 ? "disabled" : ""}>上一页</button>
    <span class="pager-info">第 ${page} / ${totalPages} 页（共 ${total} 条）</span>
    <button type="button" class="secondary" onclick="goCredPage('${zone}', ${page + 1})" ${page >= totalPages ? "disabled" : ""}>下一页</button>
  `;
}

function goCredPage(zone, page) {
  credState[zone].page = page;
  renderCredentials(zone);
  document.getElementById(`${zone}-cards`).scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function selectedNames(zone) {
  const visibleNames = new Set(getVisibleCredentialRows(zone).map((row) => row.name));
  return Array.from(credState[zone].selected).filter((name) => visibleNames.has(name));
}

function toggleAll(zone, checked) {
  const nextSelected = new Set(credState[zone].selected);
  for (const row of getVisibleCredentialRows(zone)) {
    if (checked) {
      nextSelected.add(row.name);
    } else {
      nextSelected.delete(row.name);
    }
  }
  credState[zone].selected = nextSelected;
  renderCredentials(zone);
}

function toggleRowSelection(zone, name, checked) {
  const decodedName = decodeURIComponent(name);
  if (checked) {
    credState[zone].selected.add(decodedName);
  } else {
    credState[zone].selected.delete(decodedName);
  }
  updateSelectAllControl(zone);
}

function updateSelectAllControl(zone) {
  const selectAll = document.getElementById(`${zone}-select-all`);
  if (!selectAll) return;
  const visibleRows = getVisibleCredentialRows(zone);
  const total = visibleRows.length;
  const visibleNames = new Set(visibleRows.map((row) => row.name));
  const selectedCount = Array.from(credState[zone].selected).filter((name) => visibleNames.has(name)).length;
  if (total === 0) {
    selectAll.indeterminate = false;
    selectAll.checked = false;
    return;
  }
  selectAll.indeterminate = selectedCount > 0 && selectedCount < total;
  selectAll.checked = selectedCount === total;
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

async function restoreSelected() {
  const names = selectedNames("abnormal");
  if (names.length === 0) {
    alert("请先选择至少一个凭证");
    return;
  }
  if (!confirm(`确认恢复选中的 ${names.length} 个凭证到正常区吗？`)) return;
  await api("api/credentials/restore", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ names }),
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

    const row = credState[zone]?.data.find((r) => r.name === decodedName);
    const infoPanel = document.getElementById("credential-editor-info");
    if (infoPanel && row) {
      infoPanel.innerHTML = `
        <div class="info-panel-title">凭证信息</div>
        <div class="info-panel-row"><span class="muted">文件名</span><span class="info-val">${escapeHtml(decodedName)}</span></div>
        <div class="info-panel-row"><span class="muted">邮箱</span><span class="info-val">${escapeHtml(row.email || "—")}</span></div>
        <div class="info-panel-row"><span class="muted">最近刷新</span><span class="info-val">${escapeHtml(row.last_refresh ? shortTime(row.last_refresh) : "—")}</span></div>
        <div class="info-panel-row"><span class="muted">过期时间</span><span class="info-val">${escapeHtml(row.expired ? shortTime(row.expired) : "—")}</span></div>
      `;
    } else if (infoPanel) {
      infoPanel.innerHTML = "";
    }

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
  const infoPanel = document.getElementById("credential-editor-info");
  if (infoPanel) infoPanel.innerHTML = "";
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

async function downloadSelected(zone) {
  const names = selectedNames(zone);
  if (names.length === 0) {
    alert("请先选择至少一个凭证");
    return;
  }
  const response = await api("api/credentials/archive-selected.zip", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ zone, names }),
  });
  await downloadBlobResponse(response, `credentials-${zone}-selected.zip`);
}

async function downloadBlobResponse(response, fallbackName) {
  const blob = await response.blob();
  const disposition = response.headers.get("content-disposition") || "";
  const match = disposition.match(/filename="([^"]+)"/i);
  const fileName = match?.[1] || fallbackName;
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

const backupRestoreState = {
  snapshots: [],
  selectedIndex: null,
  needsPassword: false,
};

const backupRunState = {
  remotes: [],
  selectedIndex: null,
};

async function openBackupRunModal() {
  try {
    await loadBackupStatus();
    backupRunState.remotes = Array.isArray(backupStatusCache?.configured_remote_names)
      ? backupStatusCache.configured_remote_names
      : [];
    backupRunState.selectedIndex = null;
    const list = document.getElementById("backup-run-list");
    if (!backupRunState.remotes.length) {
      list.innerHTML = `<div class="empty-hint">当前没有可用备份端</div>`;
    } else {
      list.innerHTML = backupRunState.remotes.map((remoteName, index) => `
        <div class="backup-snapshot-item">
          <label>
            <input type="radio" name="backup-run-remote" value="${index}" onchange="selectBackupRunRemote(${index})">
            <span class="backup-snapshot-meta">
              <span>${escapeHtml(remoteName)}</span>
              <span class="muted">${index === 0 ? "当前第一顺位备份端" : `当前第 ${index + 1} 顺位备份端`}</span>
            </span>
          </label>
        </div>
      `).join("");
    }
    syncBackupRunConfirm();
    const modal = document.getElementById("backup-run-modal");
    modal.classList.remove("hidden");
    modal.setAttribute("aria-hidden", "false");
    document.body.classList.add("modal-open");
  } catch (error) {
    alert(error.message);
  }
}

function closeBackupRunModal() {
  backupRunState.remotes = [];
  backupRunState.selectedIndex = null;
  const modal = document.getElementById("backup-run-modal");
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
  document.body.classList.remove("modal-open");
}

function selectBackupRunRemote(index) {
  backupRunState.selectedIndex = Number(index);
  syncBackupRunConfirm();
}

function syncBackupRunConfirm() {
  document.getElementById("backup-run-submit").disabled = !Number.isInteger(backupRunState.selectedIndex);
}

async function submitBackupRun() {
  const remoteName = backupRunState.remotes[backupRunState.selectedIndex];
  if (!remoteName) {
    alert("请选择一个备份端");
    return;
  }
  const data = await api("api/backup/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ remote_name: remoteName }),
  });
  closeBackupRunModal();
  await loadBackupStatus();
  await loadScheduler();
  const remoteLabel = data.snapshot?.remote_name ? `${data.snapshot.remote_name} / ` : "";
  showToast(`备份完成：${remoteLabel}${data.snapshot?.key || "远端快照已更新"}`);
}

async function openBackupRestoreModal() {
  try {
    const data = await api("api/backup/snapshots");
    backupRestoreState.snapshots = data.items || [];
    backupRestoreState.selectedIndex = backupRestoreState.snapshots.length ? 0 : null;
    const list = document.getElementById("backup-restore-list");
    const warnings = document.getElementById("backup-restore-warnings");
    const warningItems = data.warnings || [];
    if (warningItems.length) {
      warnings.classList.remove("hidden");
      warnings.innerHTML = warningItems.map((item) => `<div>${escapeHtml(item)}</div>`).join("");
    } else {
      warnings.classList.add("hidden");
      warnings.innerHTML = "";
    }
    if (backupRestoreState.snapshots.length === 0) {
      list.innerHTML = `<div class="empty-hint">远端没有可用备份</div>`;
    } else {
      list.innerHTML = backupRestoreState.snapshots.map((item, index) => `
        <div class="backup-snapshot-item">
          <label>
            <input type="radio" name="backup-snapshot" value="${index}" ${index === 0 ? "checked" : ""} onchange="selectBackupSnapshot(${index})">
            <span class="backup-snapshot-meta">
              <span>${escapeHtml(item.key)}</span>
              <span class="muted">时间：${escapeHtml(item.created_at ? shortTime(item.created_at) : item.last_modified ? shortTime(item.last_modified) : "未知")}</span>
              <span class="muted">来源：${escapeHtml(item.remote_name || "未标记")}${item.is_current_latest ? " | 当前最新" : ""}</span>
              <span class="muted">触发：${escapeHtml(item.trigger || "unknown")} | 大小：${escapeHtml(formatBytes(item.size || 0))}</span>
            </span>
          </label>
        </div>
      `).join("");
    }
    setBackupRestorePasswordRequired(false);
    document.getElementById("backup-restore-confirmation").value = "";
    document.getElementById("backup-restore-password").value = "";
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
  backupRestoreState.selectedIndex = null;
  backupRestoreState.needsPassword = false;
  document.getElementById("backup-restore-confirmation").value = "";
  document.getElementById("backup-restore-password").value = "";
  setBackupRestorePasswordRequired(false);
  const warnings = document.getElementById("backup-restore-warnings");
  warnings.classList.add("hidden");
  warnings.innerHTML = "";
  const modal = document.getElementById("backup-restore-modal");
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
  document.body.classList.remove("modal-open");
}

function selectBackupSnapshot(index) {
  backupRestoreState.selectedIndex = Number(index);
  document.getElementById("backup-restore-password").value = "";
  setBackupRestorePasswordRequired(false);
  syncBackupRestoreConfirm();
}

function setBackupRestorePasswordRequired(required) {
  backupRestoreState.needsPassword = required;
  const group = document.getElementById("backup-restore-password-group");
  const hint = document.getElementById("backup-restore-password-hint");
  group.classList.toggle("hidden", !required);
  hint.textContent = required
    ? "当前 WEB_PASSWORD 无法解密该备份，请输入历史备份密码后重试"
    : "留空时使用当前 WEB_PASSWORD";
  hint.classList.toggle("danger-text", required);
  hint.classList.toggle("muted", !required);
}

function syncBackupRestoreConfirm() {
  const password = document.getElementById("backup-restore-password").value.trim();
  const enabled = Number.isInteger(backupRestoreState.selectedIndex)
    && document.getElementById("backup-restore-confirmation").value.trim() === "确定还原"
    && (!backupRestoreState.needsPassword || password.length > 0);
  document.getElementById("backup-restore-submit").disabled = !enabled;
}

async function submitBackupRestore() {
  const selected = backupRestoreState.snapshots[backupRestoreState.selectedIndex];
  if (!selected) {
    alert("请选择一个备份");
    return;
  }
  const confirmation = document.getElementById("backup-restore-confirmation").value.trim();
  if (confirmation !== "确定还原") {
    alert("请输入“确定还原”后再继续");
    return;
  }
  const password = document.getElementById("backup-restore-password").value.trim();
  try {
    await api("api/backup/restore", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        remote_name: selected.remote_name,
        snapshot_key: selected.key,
        confirmation,
        password: password || undefined,
      }),
    });
    closeBackupRestoreModal();
    await refreshAll();
    showToast("备份还原完成");
  } catch (error) {
    if (error.code === "backup_password_invalid") {
      setBackupRestorePasswordRequired(true);
      syncBackupRestoreConfirm();
      document.getElementById("backup-restore-password").focus();
      return;
    }
    alert(error.message);
  }
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
  if (!confirm("这会把旧 codex_cli_rs UA 重配为当前 originator/version；codex-tui 会同步客户端版本后缀，旧 macOS 片段会按官方格式规范化。确认继续吗？")) return;
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

function openCpaSupplementModal() {
  const modal = document.getElementById("cpa-supplement-modal");
  const input = document.getElementById("cpa-supplement-count");
  const submitBtn = document.getElementById("cpa-supplement-submit");
  input.value = "";
  submitBtn.disabled = false;
  submitBtn.classList.remove("loading");
  submitBtn.textContent = "开始补充";
  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
  document.body.classList.add("modal-open");
  setTimeout(() => input.focus(), 0);
}

function closeCpaSupplementModal() {
  const modal = document.getElementById("cpa-supplement-modal");
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
  document.body.classList.remove("modal-open");
}

async function submitCpaSupplement() {
  const input = document.getElementById("cpa-supplement-count");
  const count = Number(input.value);
  if (!Number.isInteger(count) || count <= 0) {
    alert("请输入大于 0 的整数数量");
    input.focus();
    input.select();
    return;
  }
  const submitBtn = document.getElementById("cpa-supplement-submit");
  const toolbarBtn = document.getElementById("cpa-supplement-btn");
  submitBtn.disabled = true;
  submitBtn.classList.add("loading");
  submitBtn.textContent = "补充中";
  toolbarBtn.disabled = true;
  toolbarBtn.classList.add("loading");
  toolbarBtn.textContent = "补充执行中";
  try {
    const data = await api("api/cpa/supplement", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ count }),
    });
    await refreshAll();
    closeCpaSupplementModal();
    const summary = `补充完成：请求 ${data.requested}，符合条件 ${data.eligible}，实际补充 ${data.supplemented}`;
    if (data.ok && data.warnings?.length) {
      showToast(`${summary}；提示：${data.warnings[0]}`, "warning", 6500);
    } else if (data.ok) {
      showToast(summary);
    } else {
      showToast(`${summary}；错误：${data.error || data.errors?.[0] || "CPA 补充失败"}`, "error", 6500);
    }
  } catch (error) {
    showToast(error.message, "error", 4500);
  } finally {
    if (submitBtn.isConnected) {
      submitBtn.disabled = false;
      submitBtn.classList.remove("loading");
      submitBtn.textContent = "开始补充";
    }
    if (toolbarBtn.isConnected) {
      toolbarBtn.disabled = false;
      toolbarBtn.classList.remove("loading");
      toolbarBtn.textContent = "补充凭证";
    }
  }
}

async function loadCpaConfig() {
  const data = await api("api/cpa/config");
  document.getElementById("cpa-enabled").checked = Boolean(data.enabled);
  document.getElementById("cpa-base-url").value = data.base_url || "";
  document.getElementById("cpa-management-key").value = "";
  document.getElementById("cpa-management-key-meta").textContent = data.management_key_set
    ? "当前：已设置"
    : "当前：未设置";
  document.getElementById("cpa-inspect-interval").value = data.inspect_interval_minutes ?? 60;
  document.getElementById("cpa-auto-supplement-enabled").checked = Boolean(data.auto_supplement_enabled);
  document.getElementById("cpa-supplement-target").value = data.supplement_target ?? 50;
  document.getElementById("cpa-safety-abort-enabled").checked = Boolean(data.safety_abort_enabled);
  document.getElementById("cpa-safety-abort-ratio").value = data.safety_abort_ratio_percent ?? 50;
}

async function saveCpaConfig() {
  try {
    await api("api/cpa/config", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        enabled: document.getElementById("cpa-enabled").checked,
        base_url: document.getElementById("cpa-base-url").value,
        management_key: document.getElementById("cpa-management-key").value,
        inspect_interval_minutes: Number(document.getElementById("cpa-inspect-interval").value),
        auto_supplement_enabled: document.getElementById("cpa-auto-supplement-enabled").checked,
        supplement_target: Number(document.getElementById("cpa-supplement-target").value),
        safety_abort_enabled: document.getElementById("cpa-safety-abort-enabled").checked,
        safety_abort_ratio_percent: Number(document.getElementById("cpa-safety-abort-ratio").value),
      }),
    });
    await Promise.all([loadCpaConfig(), loadCpaStatus()]);
    showToast("CPA 配置已保存");
  } catch (error) {
    showToast(error.message, "error", 4500);
  }
}

async function loadCpaStatus() {
  const data = await api("api/cpa/status");
  const last = data.last_result || null;
  const container = document.getElementById("cpa-status");
  const running = Boolean(data.running);
  const lastHasWarnings = Boolean(last && last.ok && last.warnings?.length);
  const lastStateText = !last
    ? "未运行"
    : lastHasWarnings
      ? "成功（有告警）"
    : last.ok
      ? "成功"
      : "失败";
  const lastStateClass = !last
    ? "status-off"
    : lastHasWarnings
      ? "warn-text"
    : last.ok
      ? "status-on"
      : "danger-text";
  const summary = !last
    ? "无"
    : `total=${last.total_codex} | 异常候选=${last.candidates_401} | 移入异常区=${last.moved_to_abnormal} | 耗尽候选=${last.candidates_exhausted} | 移入正常区=${last.moved_to_normal_exhausted} | 补号=${last.supplement_done}`;
  const lastRange = !last
    ? "未运行"
    : `${escapeHtml(shortTime(last.started_at))} -> ${escapeHtml(shortTime(last.finished_at))}`;
  const detailMessage = data.last_error || (last ? (last.error || last.errors?.[0] || last.warnings?.[0]) : "");
  const detailLabel = data.last_error || (last && !last.ok)
    ? "最近错误"
    : lastHasWarnings
      ? "最近告警"
      : "最近错误";
  const detailClass = data.last_error || (last && !last.ok)
    ? "danger-text"
    : lastHasWarnings
      ? "warn-text"
      : "";
  container.innerHTML = `
    <div class="cpa-status-tiles">
      <div class="cpa-tile">
        <div class="cpa-tile-label">自动巡查</div>
        <div class="cpa-tile-value ${data.enabled ? "status-on" : "status-off"}">${data.enabled ? "已开启" : "已关闭"}</div>
      </div>
      <div class="cpa-tile">
        <div class="cpa-tile-label">当前状态</div>
        <div class="cpa-tile-value ${running ? "status-on" : "status-off"}">${running ? "执行中" : "空闲"}</div>
      </div>
      <div class="cpa-tile">
        <div class="cpa-tile-label">下次巡查</div>
        <div class="cpa-tile-value">${escapeHtml(data.next_wake_at ? shortTime(data.next_wake_at) : "待定")}</div>
      </div>
      <div class="cpa-tile">
        <div class="cpa-tile-label">上次结果</div>
        <div class="cpa-tile-value ${lastStateClass}">${escapeHtml(lastStateText)}</div>
      </div>
      <div class="cpa-tile cpa-tile--wide">
        <div class="cpa-tile-label">上次时间</div>
        <div class="cpa-tile-value">${lastRange}</div>
      </div>
      <div class="cpa-tile cpa-tile--wide">
        <div class="cpa-tile-label">${detailLabel}</div>
        <div class="cpa-tile-value${detailClass ? ` ${detailClass}` : ""}">${escapeHtml(detailMessage || "无")}</div>
      </div>
      <div class="cpa-tile cpa-tile--full">
        <div class="cpa-tile-label">统计</div>
        <div class="cpa-tile-value cpa-tile-stats">${escapeHtml(summary)}</div>
      </div>
    </div>
  `;
  const inspectBtn = document.getElementById("cpa-inspect-btn");
  const reclaimBtn = document.getElementById("cpa-reclaim-btn");
  const supplementBtn = document.getElementById("cpa-supplement-btn");
  inspectBtn.disabled = running;
  inspectBtn.textContent = running ? "巡查执行中" : "立即巡查";
  reclaimBtn.disabled = running;
  reclaimBtn.textContent = running ? "取回执行中" : "取回凭证";
  supplementBtn.disabled = running;
  supplementBtn.textContent = running ? "补充执行中" : "补充凭证";
}

async function runCpaReclaimAll() {
  if (!confirm("这会从 CLIProxyAPI 服务器取回全部 codex 凭证，并按状态放入正常区或异常区。成功取回后，远端对应文件会被删除。确认继续吗？")) return;
  const btn = document.getElementById("cpa-reclaim-btn");
  btn.disabled = true;
  btn.classList.add("loading");
  try {
    const data = await api("api/cpa/reclaim-all", { method: "POST" });
    await refreshAll();
    const summary = `取回完成：正常 ${data.imported_to_normal}，异常 ${data.imported_to_abnormal}，耗尽 ${data.imported_exhausted}，清理残留 ${data.cleaned_disabled_residual}，跳过 ${data.skipped}`;
    if (data.ok && data.warnings?.length) {
      const warningSuffix = data.warnings.length > 1 ? ` 等 ${data.warnings.length} 条` : "";
      showToast(`${summary}；告警：${data.warnings[0]}${warningSuffix}`, "warning", 6000);
    } else if (data.ok) {
      showToast(summary);
    } else {
      showToast(data.error || data.errors?.[0] || "CPA 取回失败", "error", 4500);
    }
  } catch (error) {
    showToast(error.message, "error", 4500);
  } finally {
    if (btn.isConnected) {
      btn.disabled = false;
      btn.classList.remove("loading");
      btn.textContent = "取回凭证";
    }
  }
}

async function runCpaInspectOnce() {
  const btn = document.getElementById("cpa-inspect-btn");
  btn.disabled = true;
  btn.classList.add("loading");
  try {
    const data = await api("api/cpa/inspect-once", { method: "POST" });
    await refreshAll();
    if (data.ok && data.warnings?.length) {
      showToast(`CPA巡查完成：移入异常 ${data.moved_to_abnormal}，移入耗尽 ${data.moved_to_normal_exhausted}，补号 ${data.supplement_done}；告警：${data.warnings[0]}`, "warning", 5500);
    } else if (data.ok) {
      showToast(`CPA巡查完成：移入异常 ${data.moved_to_abnormal}，移入耗尽 ${data.moved_to_normal_exhausted}，补号 ${data.supplement_done}`);
    } else {
      showToast(data.error || data.errors?.[0] || "CPA 巡查失败", "error", 4500);
    }
  } catch (error) {
    showToast(error.message, "error", 4500);
  } finally {
    if (btn.isConnected) {
      btn.disabled = false;
      btn.classList.remove("loading");
      btn.textContent = "立即巡查";
    }
  }
}

async function reloadLog(kind) {
  const data = await api(`api/logs?kind=${kind}&limit=${LOG_LINE_LIMIT}`);
  renderLog(kind, data.content || "");
}

async function reloadCpaLog() {
  const data = await api(`api/cpa/logs?limit=${LOG_LINE_LIMIT}`);
  renderLog("cpa", data.content || "");
}

function downloadLog(kind) {
  window.location.href = `api/logs/download?kind=${kind}`;
}

function downloadCpaLog() {
  window.location.href = "api/cpa/logs/download";
}

async function clearLog(kind) {
  await api("api/logs/clear", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ kind }),
  });
  await reloadLog(kind);
}

async function clearCpaLog() {
  await api("api/cpa/logs/clear", { method: "POST" });
  await reloadCpaLog();
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
  if (
    normalized.includes("refresh succeeded") ||
    normalized.includes("refresh_success") ||
    normalized.includes("backup finished") ||
    normalized.includes("backup uploaded successfully") ||
    normalized.includes("backup restore completed")
  ) {
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
window.addBackupRemote = addBackupRemote;
window.removeBackupRemote = removeBackupRemote;
window.moveBackupRemote = moveBackupRemote;
window.manualRefresh = manualRefresh;
window.restoreCredential = restoreCredential;
window.restoreSelected = restoreSelected;
window.deleteCredential = deleteCredential;
window.deleteSelected = deleteSelected;
window.downloadCredential = downloadCredential;
window.downloadCredentialArchive = downloadCredentialArchive;
window.downloadSelected = downloadSelected;
window.openCredentialEditor = openCredentialEditor;
window.closeCredentialEditor = closeCredentialEditor;
window.saveCredentialEditor = saveCredentialEditor;
window.importFiles = importFiles;
window.fillMissingUserAgents = fillMissingUserAgents;
window.reassignCliVersions = reassignCliVersions;
window.reassignAllUserAgents = reassignAllUserAgents;
window.saveCpaConfig = saveCpaConfig;
window.runCpaReclaimAll = runCpaReclaimAll;
window.runCpaInspectOnce = runCpaInspectOnce;
window.openCpaSupplementModal = openCpaSupplementModal;
window.closeCpaSupplementModal = closeCpaSupplementModal;
window.submitCpaSupplement = submitCpaSupplement;
window.reloadCpaLog = reloadCpaLog;
window.downloadCpaLog = downloadCpaLog;
window.clearCpaLog = clearCpaLog;
window.openBackupRunModal = openBackupRunModal;
window.closeBackupRunModal = closeBackupRunModal;
window.selectBackupRunRemote = selectBackupRunRemote;
window.submitBackupRun = submitBackupRun;
window.openBackupRestoreModal = openBackupRestoreModal;
window.closeBackupRestoreModal = closeBackupRestoreModal;
window.selectBackupSnapshot = selectBackupSnapshot;
window.syncBackupRestoreConfirm = syncBackupRestoreConfirm;
window.submitBackupRestore = submitBackupRestore;
window.reloadLog = reloadLog;
window.downloadLog = downloadLog;
window.clearLog = clearLog;
window.logout = logout;
window.handleCredentialSearchInput = handleCredentialSearchInput;
window.clearCredentialSearch = clearCredentialSearch;
window.toggleAll = toggleAll;
window.toggleRowSelection = toggleRowSelection;
window.goCredPage = goCredPage;
window.switchTab = switchTab;

document.addEventListener("DOMContentLoaded", () => {
  refreshAll().catch((error) => alert(error.message));
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !document.getElementById("credential-editor-modal").classList.contains("hidden")) {
    closeCredentialEditor();
    return;
  }
  if (event.key === "Escape" && !document.getElementById("backup-run-modal").classList.contains("hidden")) {
    closeBackupRunModal();
    return;
  }
  if (event.key === "Escape" && !document.getElementById("backup-restore-modal").classList.contains("hidden")) {
    closeBackupRestoreModal();
    return;
  }
  if (event.key === "Escape" && !document.getElementById("cpa-supplement-modal").classList.contains("hidden")) {
    closeCpaSupplementModal();
  }
});

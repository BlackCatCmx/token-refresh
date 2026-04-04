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
  container.innerHTML = `
    <span class="status-label">自动刷新</span>
    <span class="${data.enabled ? "status-on" : "status-off"}">${data.enabled ? "运行中" : "已停止"}</span>
    <span class="status-label">当前账号</span>
    <span>${escapeHtml(data.current_key || "无")}</span>
    <span class="status-label">下次唤醒</span>
    <span>${escapeHtml(data.next_wake_at ? shortTime(data.next_wake_at) : "待定")}</span>
    <span class="status-label">最近错误</span>
    <span${data.last_error ? ' class="danger-text"' : ""}>${escapeHtml(data.last_error || "无")}</span>
  `;
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
  document.getElementById("delay-min").value = data.settings.refresh.inter_refresh_delay_min;
  document.getElementById("delay-max").value = data.settings.refresh.inter_refresh_delay_max;
  document.getElementById("failure-backoff").value = data.settings.refresh.failure_backoff;
  document.getElementById("network-timeout").value = data.settings.network.timeout;
  syncUserAgentMode();
  renderHeaderPreview(data.header_preview);
  document.getElementById("settings-meta").textContent = `配置文件: ${data.config_path} | 环境变量锁定项: ${data.locked_fields.join(", ") || "无"}`;
  for (const field of ["originator", "user-agent-mode", "user-agent", "user-agent-versions", "user-agent-profiles", "user-agent-terminals", "log-level", "max-file-size", "proxy-mode", "proxy-list", "abnormal-threshold", "refresh-interval", "lead-time", "delay-min", "delay-max", "failure-backoff", "network-timeout"]) {
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
    "refresh.inter_refresh_delay_min": ["delay-min"],
    "refresh.inter_refresh_delay_max": ["delay-max"],
    "refresh.failure_backoff": ["failure-backoff"],
    "network.timeout": ["network-timeout"],
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
      inter_refresh_delay_min: document.getElementById("delay-min").value,
      inter_refresh_delay_max: document.getElementById("delay-max").value,
      failure_backoff: document.getElementById("failure-backoff").value,
    },
    network: {
      timeout: document.getElementById("network-timeout").value,
    },
  };
  await api("api/settings", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  await loadSettings();
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
      ? `<button type="button" onclick="manualRefresh('${encodedName}')">刷新</button>
         <button type="button" class="secondary" onclick="downloadCredential('${zone}','${encodedName}')">下载</button>
         <button type="button" class="danger" onclick="deleteCredential('${zone}','${encodedName}')">删除</button>`
      : `<button type="button" onclick="restoreCredential('${encodedName}')">恢复</button>
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

async function manualRefresh(name) {
  await api("api/credentials/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: decodeURIComponent(name) }),
  });
  await refreshAll();
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

function downloadCredential(zone, name) {
  window.location.href = `api/credentials/download?zone=${zone}&name=${name}`;
}

function downloadCredentialArchive(zone) {
  window.location.href = `api/credentials/archive.zip?zone=${zone}`;
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

async function reassignAllUserAgents() {
  if (!confirm("这会强制重写全部凭证的 UA，包括原来已有 UA 的。确认继续吗？")) return;
  const data = await api("api/credentials/user-agent/reassign", { method: "POST" });
  await refreshAll();
  alert(formatUserAgentPatchMessage("强制重配 UA", data));
}

async function reloadLog(kind) {
  const data = await api(`api/logs?kind=${kind}&limit=120`);
  document.getElementById(`${kind}-log`).textContent = data.content || "";
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

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
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
window.saveSettings = saveSettings;
window.syncUserAgentMode = syncUserAgentMode;
window.manualRefresh = manualRefresh;
window.restoreCredential = restoreCredential;
window.deleteCredential = deleteCredential;
window.deleteSelected = deleteSelected;
window.downloadCredential = downloadCredential;
window.downloadCredentialArchive = downloadCredentialArchive;
window.importFiles = importFiles;
window.fillMissingUserAgents = fillMissingUserAgents;
window.reassignAllUserAgents = reassignAllUserAgents;
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

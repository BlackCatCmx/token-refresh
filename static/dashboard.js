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
  const data = await api("/api/scheduler/status");
  const container = document.getElementById("scheduler-status");
  const rows = [
    ["自动刷新", data.enabled ? "开启" : "停止"],
    ["当前账号", data.current_key || "无"],
    ["下次唤醒", data.next_wake_at ? shortTime(data.next_wake_at) : "待定"],
    ["最近错误", data.last_error || "无"],
  ];
  container.innerHTML = rows.map(([label, value]) =>
    `<span class="status-label">${escapeHtml(label)}</span><span>${escapeHtml(value)}</span>`
  ).join("");
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
  const data = await api("/api/settings");
  document.getElementById("originator").value = data.settings.request_identity.originator;
  document.getElementById("user-agent").value = data.settings.request_identity.user_agent;
  document.getElementById("log-level").value = data.settings.log_level;
  document.getElementById("max-file-size").value = data.settings.logging.max_file_size;
  document.getElementById("proxy-mode").value = data.settings.proxy.mode;
  document.getElementById("proxy-list").value = data.settings.proxy.list;
  document.getElementById("abnormal-threshold").value = data.settings.credential_management.abnormal_threshold;
  document.getElementById("lead-time").value = data.settings.refresh.lead_time;
  document.getElementById("delay-min").value = data.settings.refresh.inter_refresh_delay_min;
  document.getElementById("delay-max").value = data.settings.refresh.inter_refresh_delay_max;
  document.getElementById("failure-backoff").value = data.settings.refresh.failure_backoff;
  document.getElementById("network-timeout").value = data.settings.network.timeout;
  document.getElementById("header-preview").textContent = JSON.stringify(data.header_preview, null, 2);
  document.getElementById("settings-meta").textContent = `配置文件: ${data.config_path} | 环境变量锁定项: ${data.locked_fields.join(", ") || "无"}`;
  for (const field of ["originator", "user-agent", "log-level", "max-file-size", "proxy-mode", "proxy-list", "abnormal-threshold", "lead-time", "delay-min", "delay-max", "failure-backoff", "network-timeout"]) {
    document.getElementById(field).disabled = false;
  }
  const lockMap = {
    "request_identity.originator": "originator",
    "request_identity.user_agent": "user-agent",
    log_level: "log-level",
    "logging.max_file_size": "max-file-size",
    "proxy.mode": "proxy-mode",
    "proxy.list": "proxy-list",
    "credential_management.abnormal_threshold": "abnormal-threshold",
    "refresh.lead_time": "lead-time",
    "refresh.inter_refresh_delay_min": "delay-min",
    "refresh.inter_refresh_delay_max": "delay-max",
    "refresh.failure_backoff": "failure-backoff",
    "network.timeout": "network-timeout",
  };
  for (const key of data.locked_fields) {
    if (lockMap[key]) document.getElementById(lockMap[key]).disabled = true;
  }
}

async function saveSettings() {
  const payload = {
    log_level: document.getElementById("log-level").value,
    logging: { max_file_size: document.getElementById("max-file-size").value },
    request_identity: {
      originator: document.getElementById("originator").value,
      user_agent: document.getElementById("user-agent").value,
    },
    proxy: {
      mode: document.getElementById("proxy-mode").value,
      list: document.getElementById("proxy-list").value,
    },
    credential_management: {
      abnormal_threshold: Number(document.getElementById("abnormal-threshold").value),
    },
    refresh: {
      lead_time: document.getElementById("lead-time").value,
      inter_refresh_delay_min: document.getElementById("delay-min").value,
      inter_refresh_delay_max: document.getElementById("delay-max").value,
      failure_backoff: document.getElementById("failure-backoff").value,
    },
    network: {
      timeout: document.getElementById("network-timeout").value,
    },
  };
  await api("/api/settings", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  await loadSettings();
  await loadScheduler();
  alert("设置已保存");
}

async function loadCredentials(zone) {
  const data = await api(`/api/credentials?zone=${zone}`);
  const tbody = document.getElementById(`${zone}-table`);
  tbody.innerHTML = "";
  document.getElementById(`${zone}-select-all`).checked = false;
  if (data.items.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-hint">暂无凭证</td></tr>`;
    return;
  }
  for (const row of data.items) {
    const tr = document.createElement("tr");
    const status = row.zone === "abnormal" ? '<span class="pill">异常区</span>' : '<span class="pill">正常</span>';
    const failure = row.last_failure_code ? `${row.last_failure_code} (${row.consecutive_failure_count})` : "-";
    const encodedName = encodeURIComponent(row.name);
    const actions = zone === "normal"
      ? `<div class="actions"><button onclick="manualRefresh('${encodedName}')">刷新</button><button class="danger" onclick="deleteCredential('${zone}','${encodedName}')">删除</button><button class="secondary" onclick="downloadCredential('${zone}','${encodedName}')">下载</button></div>`
      : `<div class="actions"><button onclick="restoreCredential('${encodedName}')">恢复</button><button class="danger" onclick="deleteCredential('${zone}','${encodedName}')">删除</button><button class="secondary" onclick="downloadCredential('${zone}','${encodedName}')">下载</button></div>`;
    tr.innerHTML = `
      <td class="checkbox-cell"><input class="row-check" type="checkbox" data-zone="${zone}" data-name="${encodedName}" onchange="syncSelectAll('${zone}')"></td>
      <td>${escapeHtml(row.name)}</td>
      <td>${escapeHtml(row.email || "-")}</td>
      <td>${status}</td>
      <td class="nowrap">${escapeHtml(row.last_refresh ? shortTime(row.last_refresh) : "-")}</td>
      <td class="nowrap">${escapeHtml(row.expired ? shortTime(row.expired) : "-")}</td>
      <td>${escapeHtml(failure)}<div class="danger-text">${escapeHtml(row.parse_error || row.last_failure_reason || "")}</div></td>
      <td>${actions}</td>`;
    tbody.appendChild(tr);
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
  await api("/api/credentials/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: decodeURIComponent(name) }),
  });
  await refreshAll();
}

async function restoreCredential(name) {
  await api("/api/credentials/restore", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ names: [decodeURIComponent(name)] }),
  });
  await refreshAll();
}

async function deleteCredential(zone, name) {
  if (!confirm("确认删除这个凭证吗？")) return;
  await api("/api/credentials/delete", {
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
  await api("/api/credentials/delete", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ zone, names }),
  });
  await refreshAll();
}

function downloadCredential(zone, name) {
  window.location.href = `/api/credentials/download?zone=${zone}&name=${name}`;
}

function downloadCredentialArchive(zone) {
  window.location.href = `/api/credentials/archive.zip?zone=${zone}`;
}

async function importJsonFiles() {
  const input = document.getElementById("json-files");
  if (!input.files.length) return alert("请选择 JSON 文件");
  const form = new FormData();
  for (const file of input.files) form.append("files", file, file.name);
  await api("/api/credentials/import-json", { method: "POST", body: form });
  input.value = "";
  await refreshAll();
}

async function importZipFile() {
  const input = document.getElementById("zip-file");
  if (!input.files.length) return alert("请选择 ZIP 文件");
  const form = new FormData();
  form.append("file", input.files[0], input.files[0].name);
  await api("/api/credentials/import-zip", { method: "POST", body: form });
  input.value = "";
  await refreshAll();
}

async function reloadLog(kind) {
  const data = await api(`/api/logs?kind=${kind}&limit=120`);
  document.getElementById(`${kind}-log`).textContent = data.content || "";
}

function downloadLog(kind) {
  window.location.href = `/api/logs/download?kind=${kind}`;
}

async function clearLog(kind) {
  await api("/api/logs/clear", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ kind }),
  });
  await reloadLog(kind);
}

async function logout() {
  await api("/api/session/logout", { method: "POST" });
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

window.refreshAll = refreshAll;
window.schedulerAction = schedulerAction;
window.saveSettings = saveSettings;
window.manualRefresh = manualRefresh;
window.restoreCredential = restoreCredential;
window.deleteCredential = deleteCredential;
window.deleteSelected = deleteSelected;
window.downloadCredential = downloadCredential;
window.downloadCredentialArchive = downloadCredentialArchive;
window.importJsonFiles = importJsonFiles;
window.importZipFile = importZipFile;
window.reloadLog = reloadLog;
window.downloadLog = downloadLog;
window.clearLog = clearLog;
window.logout = logout;
window.toggleAll = toggleAll;
window.syncSelectAll = syncSelectAll;

document.addEventListener("DOMContentLoaded", () => {
  refreshAll().catch((error) => alert(error.message));
});

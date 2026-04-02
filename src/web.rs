use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::http::HeaderMap;
use cookie::{Cookie, SameSite};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::net::TcpListener;

use crate::api;
use crate::config::{ConfigManager, ConfigPaths, parse_byte_size_str};
use crate::credential_store::CredentialStore;
use crate::lockfile::ServiceLock;
use crate::logging::LogManager;
use crate::recovery;
use crate::scheduler::SchedulerHandle;
use crate::status::CredentialStatusStore;
use crate::transaction::RefreshTransaction;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct AppState {
    pub config_manager: ConfigManager,
    pub store: Arc<CredentialStore>,
    pub status_store: Arc<CredentialStatusStore>,
    pub logger: Arc<LogManager>,
    pub scheduler: SchedulerHandle,
    pub transaction: Arc<RefreshTransaction>,
    pub session_manager: SessionManager,
    pub _service_lock: Arc<ServiceLock>,
}

#[derive(Clone)]
pub struct SessionManager {
    cookie_name: &'static str,
    expected_value: String,
}

impl SessionManager {
    pub fn new(password: &str, session_secret: &str) -> Result<Self> {
        let mut mac =
            HmacSha256::new_from_slice(session_secret.as_bytes()).context("invalid HMAC key")?;
        mac.update(password.as_bytes());
        let expected_value = hex_encode(&mac.finalize().into_bytes());
        Ok(Self {
            cookie_name: "codex_refresh_session",
            expected_value,
        })
    }

    pub fn is_authenticated(&self, headers: &HeaderMap) -> bool {
        let cookies = headers
            .get(axum::http::header::COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        Cookie::split_parse(cookies).flatten().any(|cookie| {
            cookie.name() == self.cookie_name && cookie.value() == self.expected_value
        })
    }

    pub fn login_cookie(&self) -> Result<String> {
        Ok(
            Cookie::build((self.cookie_name, self.expected_value.clone()))
                .path("/")
                .http_only(true)
                .same_site(SameSite::Lax)
                .build()
                .to_string(),
        )
    }

    pub fn logout_cookie(&self) -> Result<String> {
        Ok(Cookie::build((self.cookie_name, ""))
            .path("/")
            .http_only(true)
            .same_site(SameSite::Lax)
            .max_age(cookie::time::Duration::seconds(0))
            .build()
            .to_string())
    }
}

pub async fn serve(config_paths: ConfigPaths) -> Result<()> {
    let config_manager = ConfigManager::load(config_paths).await?;
    let config = config_manager.effective_config().await;
    std::fs::create_dir_all(&config.state_dir)
        .with_context(|| format!("failed to create {}", config.state_dir.display()))?;
    let logger = Arc::new(LogManager::new(
        &config.state_dir,
        parse_byte_size_str(&config.logging.max_file_size)?,
    )?);
    let _ = logger.runtime("info", "service starting");
    let store = Arc::new(CredentialStore::new(&config)?);
    recovery::recover_all(
        &[
            store.normal_dir().to_path_buf(),
            store.abnormal_dir().to_path_buf(),
        ],
        &logger,
    )?;
    let status_store = Arc::new(CredentialStatusStore::load(
        config.state_dir.join("credential_status.json"),
    )?);
    let service_lock = Arc::new(ServiceLock::acquire(
        &config.state_dir.join("service.lock"),
    )?);
    let transaction = Arc::new(RefreshTransaction::new(
        store.clone(),
        status_store.clone(),
        logger.clone(),
    ));
    let scheduler = SchedulerHandle::new(
        config_manager.clone(),
        store.clone(),
        transaction.clone(),
        logger.clone(),
    );
    let session_manager = SessionManager::new(
        &config_manager.web_password().await,
        &config_manager.web_session_secret().await,
    )?;
    let state = Arc::new(AppState {
        config_manager: config_manager.clone(),
        store,
        status_store,
        logger,
        scheduler,
        transaction,
        session_manager,
        _service_lock: service_lock,
    });

    if !config.web.enabled {
        tokio::signal::ctrl_c().await?;
        return Ok(());
    }

    let listener = TcpListener::bind(config.web.listen.trim())
        .await
        .with_context(|| format!("failed to bind {}", config.web.listen))?;
    let app = api::router(state);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server failed")?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

pub fn login_page(error_message: Option<&str>) -> String {
    let error_html = error_message
        .map(|message| format!(r#"<p class="error">{}</p>"#, escape_html(message)))
        .unwrap_or_default();
    format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Codex Refresh 登录</title>
  <style>
    body {{ margin: 0; font-family: "Segoe UI", "PingFang SC", sans-serif; background: linear-gradient(135deg, #f7efe4, #e7f1ff); color: #1b2430; }}
    .wrap {{ max-width: 420px; margin: 12vh auto; padding: 32px; background: rgba(255,255,255,0.88); border: 1px solid #d8e0ea; border-radius: 24px; box-shadow: 0 18px 50px rgba(20, 35, 55, 0.14); }}
    h1 {{ margin-top: 0; font-size: 28px; }}
    p {{ line-height: 1.6; }}
    input {{ width: 100%; box-sizing: border-box; padding: 14px 16px; border-radius: 14px; border: 1px solid #b8c7d8; font-size: 16px; }}
    button {{ width: 100%; margin-top: 16px; padding: 14px 16px; border: 0; border-radius: 14px; background: #1f5eff; color: white; font-size: 16px; cursor: pointer; }}
    .error {{ color: #b42318; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Codex Refresh</h1>
    <p>输入管理员密码后进入控制台。</p>
    {error_html}
    <form id="login-form">
      <input id="password" name="password" type="password" placeholder="WEB_PASSWORD" autocomplete="current-password" required>
      <button type="submit">登录</button>
    </form>
  </div>
  <script>
    document.getElementById('login-form').addEventListener('submit', async (event) => {{
      event.preventDefault();
      const password = document.getElementById('password').value;
      const response = await fetch('/api/session/login', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ password }})
      }});
      if (response.ok) {{
        location.reload();
        return;
      }}
      const data = await response.json().catch(() => ({{ message: '登录失败' }}));
      alert(data.message || '登录失败');
    }});
  </script>
</body>
</html>"#
    )
}

pub fn dashboard_page() -> String {
    let mut html = String::new();
    let _ = write!(
        &mut html,
        r#"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Codex Refresh 控制台</title>
  <style>
    :root {{ --bg: #f6f5f1; --panel: rgba(255,255,255,0.92); --line: #d7d3ca; --ink: #1f2933; --accent: #0f766e; --warn: #c2410c; --danger: #b42318; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: "Segoe UI", "PingFang SC", sans-serif; color: var(--ink); background: radial-gradient(circle at top left, #fff3d6, transparent 28%), radial-gradient(circle at top right, #dceeff, transparent 30%), var(--bg); }}
    header {{ padding: 28px 22px 10px; display: flex; justify-content: space-between; align-items: center; gap: 16px; }}
    h1 {{ margin: 0; font-size: 28px; }}
    main {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; padding: 0 22px 30px; }}
    section {{ background: var(--panel); border: 1px solid var(--line); border-radius: 22px; padding: 18px; box-shadow: 0 12px 28px rgba(30, 41, 59, 0.08); }}
    h2 {{ margin: 0 0 12px; font-size: 20px; }}
    .toolbar {{ display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }}
    button, select {{ border: 0; border-radius: 12px; padding: 10px 14px; background: #163dff; color: white; cursor: pointer; }}
    button.secondary {{ background: #334155; }}
    button.warn {{ background: var(--warn); }}
    button.danger {{ background: var(--danger); }}
    input, textarea, select {{ width: 100%; border: 1px solid #c8d0da; border-radius: 12px; padding: 10px 12px; background: white; color: inherit; }}
    textarea {{ min-height: 96px; resize: vertical; }}
    .grid {{ display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }}
    .list {{ max-height: 360px; overflow: auto; border: 1px solid var(--line); border-radius: 12px; background: white; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ padding: 10px; border-bottom: 1px solid #eef2f6; text-align: left; vertical-align: top; }}
    th {{ position: sticky; top: 0; background: #f8fafc; }}
    pre {{ background: #09101a; color: #d9f2ff; border-radius: 14px; padding: 14px; overflow: auto; min-height: 180px; }}
    .muted {{ color: #62748a; }}
    .pill {{ display: inline-block; padding: 2px 8px; border-radius: 999px; background: #e5f6f3; color: #0f766e; }}
    .danger-text {{ color: var(--danger); }}
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Codex Refresh 控制台</h1>
      <div class="muted">上传凭证、查看状态、调参数、手动刷新、处理异常区都在这里。</div>
    </div>
    <div class="toolbar">
      <button class="secondary" onclick="refreshAll()">刷新页面数据</button>
      <button class="danger" onclick="logout()">退出</button>
    </div>
  </header>
  <main>
    <section>
      <h2>调度状态</h2>
      <div id="scheduler-status" class="muted">加载中...</div>
      <div class="toolbar">
        <button onclick="schedulerAction('start')">开始自动刷新</button>
        <button class="warn" onclick="schedulerAction('stop')">停止自动刷新</button>
      </div>
    </section>
    <section>
      <h2>导入与导出</h2>
      <div class="grid">
        <div>
          <label>导入多个 JSON</label>
          <input id="json-files" type="file" multiple accept=".json">
          <button onclick="importJsonFiles()">上传 JSON</button>
        </div>
        <div>
          <label>导入 ZIP</label>
          <input id="zip-file" type="file" accept=".zip">
          <button onclick="importZipFile()">上传 ZIP</button>
        </div>
      </div>
      <div class="toolbar">
        <button onclick="downloadCredentialArchive('normal')">下载正常区 ZIP</button>
        <button onclick="downloadCredentialArchive('abnormal')">下载异常区 ZIP</button>
        <button class="secondary" onclick="downloadCredentialArchive('all')">下载全部 ZIP</button>
      </div>
    </section>
    <section>
      <h2>请求头预览</h2>
      <pre id="header-preview"></pre>
    </section>
    <section>
      <h2>设置</h2>
      <div class="grid">
        <div><label>originator</label><input id="originator"></div>
        <div><label>User-Agent</label><input id="user-agent"></div>
        <div><label>日志级别</label><input id="log-level"></div>
        <div><label>日志单文件上限</label><input id="max-file-size"></div>
        <div><label>代理模式</label><select id="proxy-mode"><option value="fixed">fixed</option><option value="round_robin">round_robin</option></select></div>
        <div><label>异常阈值</label><input id="abnormal-threshold" type="number" min="1"></div>
        <div><label>提前刷新窗口</label><input id="lead-time"></div>
        <div><label>刷新间最小延迟</label><input id="delay-min"></div>
        <div><label>刷新间最大延迟</label><input id="delay-max"></div>
        <div><label>失败退避</label><input id="failure-backoff"></div>
        <div><label>网络超时</label><input id="network-timeout"></div>
      </div>
      <label>SOCKS5 代理列表</label>
      <textarea id="proxy-list" placeholder="一行一个 socks5://ip:port"></textarea>
      <div class="toolbar">
        <button onclick="saveSettings()">保存设置</button>
      </div>
      <div id="settings-meta" class="muted"></div>
    </section>
    <section style="grid-column: 1 / -1;">
      <h2>正常区凭证</h2>
      <div class="list"><table><thead><tr><th>名称</th><th>邮箱</th><th>状态</th><th>最近刷新</th><th>过期时间</th><th>异常</th><th>操作</th></tr></thead><tbody id="normal-table"></tbody></table></div>
    </section>
    <section style="grid-column: 1 / -1;">
      <h2>异常区凭证</h2>
      <div class="list"><table><thead><tr><th>名称</th><th>邮箱</th><th>状态</th><th>最近刷新</th><th>过期时间</th><th>异常</th><th>操作</th></tr></thead><tbody id="abnormal-table"></tbody></table></div>
    </section>
    <section>
      <h2>运行日志</h2>
      <div class="toolbar">
        <button onclick="reloadLog('runtime')">刷新</button>
        <button onclick="downloadLog('runtime')">下载</button>
        <button class="warn" onclick="clearLog('runtime')">清空</button>
      </div>
      <pre id="runtime-log"></pre>
    </section>
    <section>
      <h2>审计日志</h2>
      <div class="toolbar">
        <button onclick="reloadLog('audit')">刷新</button>
        <button onclick="downloadLog('audit')">下载</button>
        <button class="warn" onclick="clearLog('audit')">清空</button>
        <button class="secondary" onclick="downloadLog('all')">打包下载全部日志</button>
      </div>
      <pre id="audit-log"></pre>
    </section>
  </main>
  <script>
    async function api(url, options = {{}}) {{
      const response = await fetch(url, options);
      if (response.status === 401) {{
        location.reload();
        throw new Error('未登录');
      }}
      if (!response.ok) {{
        const data = await response.json().catch(() => ({{ message: '请求失败' }}));
        throw new Error(data.message || '请求失败');
      }}
      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {{
        return response.json();
      }}
      return response;
    }}

    async function refreshAll() {{
      await Promise.all([loadScheduler(), loadSettings(), loadCredentials('normal'), loadCredentials('abnormal'), reloadLog('runtime'), reloadLog('audit')]);
    }}

    async function loadScheduler() {{
      const data = await api('/api/scheduler/status');
      const text = [
        `自动刷新: ${{data.enabled ? '开启' : '停止'}}`,
        data.current_key ? `当前账号: ${{data.current_key}}` : '当前账号: 无',
        data.next_wake_at ? `下次唤醒: ${{data.next_wake_at}}` : '下次唤醒: 待定',
        data.last_error ? `最近错误: ${{data.last_error}}` : '最近错误: 无'
      ].join(' | ');
      document.getElementById('scheduler-status').textContent = text;
    }}

    async function schedulerAction(action) {{
      await api(`/api/scheduler/${{action}}`, {{ method: 'POST' }});
      await loadScheduler();
    }}

    async function loadSettings() {{
      const data = await api('/api/settings');
      document.getElementById('originator').value = data.settings.request_identity.originator;
      document.getElementById('user-agent').value = data.settings.request_identity.user_agent;
      document.getElementById('log-level').value = data.settings.log_level;
      document.getElementById('max-file-size').value = data.settings.logging.max_file_size;
      document.getElementById('proxy-mode').value = data.settings.proxy.mode;
      document.getElementById('proxy-list').value = data.settings.proxy.list;
      document.getElementById('abnormal-threshold').value = data.settings.credential_management.abnormal_threshold;
      document.getElementById('lead-time').value = data.settings.refresh.lead_time;
      document.getElementById('delay-min').value = data.settings.refresh.inter_refresh_delay_min;
      document.getElementById('delay-max').value = data.settings.refresh.inter_refresh_delay_max;
      document.getElementById('failure-backoff').value = data.settings.refresh.failure_backoff;
      document.getElementById('network-timeout').value = data.settings.network.timeout;
      document.getElementById('header-preview').textContent = JSON.stringify(data.header_preview, null, 2);
      document.getElementById('settings-meta').textContent = `配置文件: ${{data.config_path}} | 环境变量锁定项: ${{data.locked_fields.join(', ') || '无'}}`;
      for (const field of ['originator','user-agent','log-level','max-file-size','proxy-mode','proxy-list','abnormal-threshold','lead-time','delay-min','delay-max','failure-backoff','network-timeout']) {{
        document.getElementById(field).disabled = false;
      }}
      const lockMap = {{
        'request_identity.originator': 'originator',
        'request_identity.user_agent': 'user-agent',
        'log_level': 'log-level',
        'logging.max_file_size': 'max-file-size',
        'proxy.mode': 'proxy-mode',
        'proxy.list': 'proxy-list',
        'credential_management.abnormal_threshold': 'abnormal-threshold',
        'refresh.lead_time': 'lead-time',
        'refresh.inter_refresh_delay_min': 'delay-min',
        'refresh.inter_refresh_delay_max': 'delay-max',
        'refresh.failure_backoff': 'failure-backoff',
        'network.timeout': 'network-timeout'
      }};
      for (const key of data.locked_fields) {{
        if (lockMap[key]) document.getElementById(lockMap[key]).disabled = true;
      }}
    }}

    async function saveSettings() {{
      const payload = {{
        log_level: document.getElementById('log-level').value,
        logging: {{ max_file_size: document.getElementById('max-file-size').value }},
        request_identity: {{
          originator: document.getElementById('originator').value,
          user_agent: document.getElementById('user-agent').value
        }},
        proxy: {{
          mode: document.getElementById('proxy-mode').value,
          list: document.getElementById('proxy-list').value
        }},
        credential_management: {{
          abnormal_threshold: Number(document.getElementById('abnormal-threshold').value)
        }},
        refresh: {{
          lead_time: document.getElementById('lead-time').value,
          inter_refresh_delay_min: document.getElementById('delay-min').value,
          inter_refresh_delay_max: document.getElementById('delay-max').value,
          failure_backoff: document.getElementById('failure-backoff').value
        }},
        network: {{
          timeout: document.getElementById('network-timeout').value
        }}
      }};
      await api('/api/settings', {{
        method: 'PUT',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(payload)
      }});
      await loadSettings();
      await loadScheduler();
      alert('设置已保存');
    }}

    async function loadCredentials(zone) {{
      const data = await api(`/api/credentials?zone=${{zone}}`);
      const tbody = document.getElementById(`${{zone}}-table`);
      tbody.innerHTML = '';
      for (const row of data.items) {{
        const tr = document.createElement('tr');
        const status = row.zone === 'abnormal' ? '<span class="pill">异常区</span>' : '<span class="pill">正常</span>';
        const failure = row.last_failure_code ? `${{row.last_failure_code}} (${{row.consecutive_failure_count}})` : '-';
        const actions = zone === 'normal'
          ? `<button onclick="manualRefresh('${{encodeURIComponent(row.name)}}')">刷新</button> <button class="danger" onclick="deleteCredential('${{zone}}','${{encodeURIComponent(row.name)}}')">删除</button> <button class="secondary" onclick="downloadCredential('${{zone}}','${{encodeURIComponent(row.name)}}')">下载</button>`
          : `<button onclick="restoreCredential('${{encodeURIComponent(row.name)}}')">恢复</button> <button class="danger" onclick="deleteCredential('${{zone}}','${{encodeURIComponent(row.name)}}')">删除</button> <button class="secondary" onclick="downloadCredential('${{zone}}','${{encodeURIComponent(row.name)}}')">下载</button>`;
        tr.innerHTML = `
          <td>${{escapeHtml(row.name)}}<div class="muted">${{escapeHtml(row.path)}}</div></td>
          <td>${{escapeHtml(row.email || '-')}}</td>
          <td>${{status}}</td>
          <td>${{escapeHtml(row.last_refresh || '-')}}</td>
          <td>${{escapeHtml(row.expired || '-')}}</td>
          <td>${{escapeHtml(failure)}}<div class="danger-text">${{escapeHtml(row.parse_error || row.last_failure_reason || '')}}</div></td>
          <td>${{actions}}</td>`;
        tbody.appendChild(tr);
      }}
    }}

    async function manualRefresh(name) {{
      await api('/api/credentials/refresh', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ name: decodeURIComponent(name) }})
      }});
      await refreshAll();
    }}

    async function restoreCredential(name) {{
      await api('/api/credentials/restore', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ names: [decodeURIComponent(name)] }})
      }});
      await refreshAll();
    }}

    async function deleteCredential(zone, name) {{
      if (!confirm('确认删除这个凭证吗？')) return;
      await api('/api/credentials/delete', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ zone, names: [decodeURIComponent(name)] }})
      }});
      await refreshAll();
    }}

    function downloadCredential(zone, name) {{
      window.location.href = `/api/credentials/download?zone=${{zone}}&name=${{name}}`;
    }}

    function downloadCredentialArchive(zone) {{
      window.location.href = `/api/credentials/archive.zip?zone=${{zone}}`;
    }}

    async function importJsonFiles() {{
      const input = document.getElementById('json-files');
      if (!input.files.length) return alert('请选择 JSON 文件');
      const form = new FormData();
      for (const file of input.files) form.append('files', file, file.name);
      await api('/api/credentials/import-json', {{ method: 'POST', body: form }});
      input.value = '';
      await refreshAll();
    }}

    async function importZipFile() {{
      const input = document.getElementById('zip-file');
      if (!input.files.length) return alert('请选择 ZIP 文件');
      const form = new FormData();
      form.append('file', input.files[0], input.files[0].name);
      await api('/api/credentials/import-zip', {{ method: 'POST', body: form }});
      input.value = '';
      await refreshAll();
    }}

    async function reloadLog(kind) {{
      const data = await api(`/api/logs?kind=${{kind}}&limit=120`);
      document.getElementById(`${{kind}}-log`).textContent = data.content || '';
    }}

    function downloadLog(kind) {{
      window.location.href = `/api/logs/download?kind=${{kind}}`;
    }}

    async function clearLog(kind) {{
      await api('/api/logs/clear', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ kind }})
      }});
      await reloadLog(kind);
    }}

    async function logout() {{
      await api('/api/session/logout', {{ method: 'POST' }});
      location.reload();
    }}

    function escapeHtml(value) {{
      return String(value)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
    }}

    refreshAll().catch((error) => alert(error.message));
  </script>
</body>
</html>"#
    );
    html
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut result, "{byte:02x}");
    }
    result
}

pub fn download_name_for(path: &PathBuf, fallback: &str) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(fallback)
        .to_string()
}

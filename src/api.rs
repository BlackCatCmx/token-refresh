use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Json;
use axum::Router;
use axum::extract::{Multipart, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};

use crate::archive;
use crate::config::{EditableSettings, parse_byte_size_str};
use crate::credential_store::{CredentialStore, CredentialZone};
use crate::import::{ImportedFile, import_json_files, import_zip};
use crate::logging::LogKind;
use crate::web::{AppState, app_css, dashboard_js, dashboard_page, login_js, login_page};

pub fn router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/api/session/logout", post(logout))
        .route("/api/credentials", get(list_credentials))
        .route(
            "/api/credentials/import-json",
            post(import_json_credentials),
        )
        .route("/api/credentials/import-zip", post(import_zip_credentials))
        .route("/api/credentials/refresh", post(refresh_credential))
        .route("/api/credentials/restore", post(restore_credentials))
        .route("/api/credentials/delete", post(delete_credentials))
        .route("/api/credentials/download", get(download_credential))
        .route(
            "/api/credentials/archive.zip",
            get(download_credential_archive),
        )
        .route("/api/scheduler/start", post(start_scheduler))
        .route("/api/scheduler/stop", post(stop_scheduler))
        .route("/api/scheduler/status", get(scheduler_status))
        .route("/api/logs", get(get_logs))
        .route("/api/logs/download", get(download_logs))
        .route("/api/logs/clear", post(clear_logs))
        .route("/api/settings", get(get_settings).put(update_settings))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    Router::new()
        .route("/", get(index))
        .route("/assets/app.css", get(asset_app_css))
        .route("/assets/login.js", get(asset_login_js))
        .route("/assets/dashboard.js", get(asset_dashboard_js))
        .route("/api/session/login", post(login))
        .route("/api/health", get(health))
        .merge(protected)
        .with_state(state)
}

async fn index(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Html<&'static str> {
    if state.session_manager.is_authenticated(&headers) {
        Html(dashboard_page())
    } else {
        Html(login_page())
    }
}

async fn asset_app_css() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        app_css(),
    )
        .into_response()
}

async fn asset_login_js() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        login_js(),
    )
        .into_response()
}

async fn asset_dashboard_js() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        dashboard_js(),
    )
        .into_response()
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    if state.session_manager.is_authenticated(request.headers()) {
        next.run(request).await
    } else {
        json_error(StatusCode::UNAUTHORIZED, "未登录")
    }
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    password: String,
}

async fn login(State(state): State<Arc<AppState>>, Json(payload): Json<LoginRequest>) -> Response {
    let expected_password = state.config_manager.web_password().await;
    if payload.password != expected_password {
        return json_error(StatusCode::UNAUTHORIZED, "密码错误");
    }
    match state.session_manager.login_cookie() {
        Ok(cookie_value) => (
            StatusCode::OK,
            [(header::SET_COOKIE, cookie_value)],
            Json(SimpleMessage {
                message: "登录成功".to_string(),
            }),
        )
            .into_response(),
        Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}

async fn logout(State(state): State<Arc<AppState>>) -> Response {
    match state.session_manager.logout_cookie() {
        Ok(cookie_value) => (
            StatusCode::OK,
            [(header::SET_COOKIE, cookie_value)],
            Json(SimpleMessage {
                message: "已退出".to_string(),
            }),
        )
            .into_response(),
        Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}

async fn health(State(state): State<Arc<AppState>>) -> Response {
    let normal = state
        .store
        .scan_zone(CredentialZone::Normal)
        .map(|items| items.len())
        .unwrap_or_default();
    let abnormal = state
        .store
        .scan_zone(CredentialZone::Abnormal)
        .map(|items| items.len())
        .unwrap_or_default();
    let scheduler = state.scheduler.status().await;
    Json(serde_json::json!({
        "ok": true,
        "normal_credentials": normal,
        "abnormal_credentials": abnormal,
        "scheduler_enabled": scheduler.enabled
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
struct ZoneQuery {
    zone: String,
}

#[derive(Debug, Serialize)]
struct CredentialsResponse {
    items: Vec<CredentialView>,
}

#[derive(Debug, Serialize)]
struct CredentialView {
    name: String,
    zone: String,
    email: Option<String>,
    account_id: Option<String>,
    last_refresh: Option<String>,
    expired: Option<String>,
    parse_error: Option<String>,
    consecutive_failure_count: u32,
    last_failure_code: Option<String>,
    last_failure_reason: Option<String>,
}

async fn list_credentials(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ZoneQuery>,
) -> Response {
    match CredentialZone::parse(&query.zone).and_then(|zone| build_credential_views(&state, zone)) {
        Ok(items) => Json(CredentialsResponse { items }).into_response(),
        Err(err) => json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    }
}

fn build_credential_views(state: &AppState, zone: CredentialZone) -> Result<Vec<CredentialView>> {
    let entries = state.store.scan_zone(zone)?;
    let statuses = state.status_store.all()?;
    let mut items = Vec::new();
    for entry in entries {
        let status = statuses.get(&crate::status::normalize_status_key(&entry.key));
        let credential = entry.credential.as_ref();
        items.push(CredentialView {
            name: entry.key.clone(),
            zone: zone.as_str().to_string(),
            email: credential.and_then(|value| value.email.clone()),
            account_id: credential.and_then(|value| value.account_id.clone()),
            last_refresh: credential.and_then(|value| value.last_refresh.clone()),
            expired: credential.and_then(|value| value.expired.clone()),
            parse_error: entry.parse_error.clone(),
            consecutive_failure_count: status
                .map(|value| value.consecutive_failure_count)
                .unwrap_or(0),
            last_failure_code: status.and_then(|value| value.last_failure_code.clone()),
            last_failure_reason: status.and_then(|value| value.last_failure_reason.clone()),
        });
    }
    Ok(items)
}

async fn import_json_credentials(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Response {
    match collect_json_files(&mut multipart)
        .await
        .and_then(|files| import_json_files(&state.store, files))
    {
        Ok(imported) => {
            state.scheduler.wake();
            Json(serde_json::json!({ "imported": imported })).into_response()
        }
        Err(err) => json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    }
}

async fn collect_json_files(multipart: &mut Multipart) -> Result<Vec<ImportedFile>> {
    let mut files = Vec::new();
    while let Some(field) = multipart
        .next_field()
        .await
        .context("failed to read upload field")?
    {
        let file_name = field
            .file_name()
            .map(str::to_string)
            .unwrap_or_else(|| "credential.json".to_string());
        let bytes = field
            .bytes()
            .await
            .context("failed to read uploaded file")?;
        files.push(ImportedFile {
            name: file_name,
            bytes: bytes.to_vec(),
            zone: CredentialZone::Normal,
        });
    }
    if files.is_empty() {
        anyhow::bail!("未上传任何 JSON 文件");
    }
    Ok(files)
}

async fn import_zip_credentials(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Response {
    let field = match multipart.next_field().await {
        Ok(Some(field)) => field,
        Ok(None) => return json_error(StatusCode::BAD_REQUEST, "未上传 ZIP 文件"),
        Err(err) => return json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    match field.bytes().await.context("failed to read uploaded ZIP") {
        Ok(bytes) => match import_zip(&state.store, &bytes) {
            Ok(imported) => {
                state.scheduler.wake();
                Json(serde_json::json!({ "imported": imported })).into_response()
            }
            Err(err) => json_error(StatusCode::BAD_REQUEST, &err.to_string()),
        },
        Err(err) => json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct NameRequest {
    name: String,
}

async fn refresh_credential(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<NameRequest>,
) -> Response {
    let config = state.config_manager.effective_config().await;
    match state
        .transaction
        .refresh_one(
            &config,
            CredentialZone::Normal,
            payload.name.trim(),
            crate::transaction::RefreshTrigger::Manual,
        )
        .await
    {
        Ok(outcome) if outcome.success => {
            state.scheduler.wake();
            Json(SimpleMessage {
                message: outcome.message,
            })
            .into_response()
        }
        Ok(outcome) => json_error(
            StatusCode::BAD_REQUEST,
            &format!(
                "{}{}",
                outcome.message,
                outcome
                    .failure_code
                    .as_deref()
                    .map(|code| format!(" ({code})"))
                    .unwrap_or_default()
            ),
        ),
        Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct NamesRequest {
    names: Vec<String>,
}

async fn restore_credentials(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<NamesRequest>,
) -> Response {
    match move_credentials(
        &state.store,
        &state.status_store,
        CredentialZone::Abnormal,
        CredentialZone::Normal,
        &payload.names,
    ) {
        Ok(count) => {
            state.scheduler.wake();
            Json(serde_json::json!({ "restored": count })).into_response()
        }
        Err(err) => json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    }
}

async fn delete_credentials(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DeleteRequest>,
) -> Response {
    let zone = match CredentialZone::parse(payload.zone.trim()) {
        Ok(zone) => zone,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    for name in &payload.names {
        if let Err(err) = state.store.delete(zone, name.trim()) {
            return json_error(StatusCode::BAD_REQUEST, &err.to_string());
        }
        if let Err(err) = state.status_store.remove(name.trim()) {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
        }
    }
    state.scheduler.wake();
    Json(serde_json::json!({ "deleted": payload.names.len() })).into_response()
}

#[derive(Debug, Deserialize)]
struct DeleteRequest {
    zone: String,
    names: Vec<String>,
}

fn move_credentials(
    store: &CredentialStore,
    status_store: &crate::status::CredentialStatusStore,
    from: CredentialZone,
    to: CredentialZone,
    names: &[String],
) -> Result<usize> {
    for name in names {
        store.move_between_zones(from, to, name.trim())?;
        status_store.restore_to_normal(name.trim())?;
    }
    Ok(names.len())
}

#[derive(Debug, Deserialize)]
struct DownloadCredentialQuery {
    zone: String,
    name: String,
}

async fn download_credential(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DownloadCredentialQuery>,
) -> Response {
    let zone = match CredentialZone::parse(query.zone.trim()) {
        Ok(zone) => zone,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    match state.store.read_bytes(zone, query.name.trim()) {
        Ok(bytes) => download_response(
            "application/json",
            file_name_from_key(query.name.trim()),
            bytes,
        ),
        Err(err) => json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct ArchiveQuery {
    zone: String,
}

async fn download_credential_archive(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ArchiveQuery>,
) -> Response {
    match archive::build_credential_archive(&state.store, query.zone.trim()) {
        Ok(bytes) => download_response(
            "application/zip",
            format!("credentials-{}.zip", query.zone.trim()),
            bytes,
        ),
        Err(err) => json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    }
}

async fn start_scheduler(State(state): State<Arc<AppState>>) -> Response {
    state.scheduler.start().await;
    Json(SimpleMessage {
        message: "自动刷新已开启".to_string(),
    })
    .into_response()
}

async fn stop_scheduler(State(state): State<Arc<AppState>>) -> Response {
    state.scheduler.stop().await;
    Json(SimpleMessage {
        message: "自动刷新已停止".to_string(),
    })
    .into_response()
}

async fn scheduler_status(State(state): State<Arc<AppState>>) -> Response {
    Json(state.scheduler.status().await).into_response()
}

#[derive(Debug, Deserialize)]
struct LogsQuery {
    kind: String,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct LogsResponse {
    kind: String,
    content: String,
}

async fn get_logs(State(state): State<Arc<AppState>>, Query(query): Query<LogsQuery>) -> Response {
    let kind = match LogKind::parse(query.kind.trim()) {
        Ok(kind) => kind,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    match state.logger.read_tail(kind, query.limit.unwrap_or(100)) {
        Ok(content) => Json(LogsResponse {
            kind: query.kind,
            content,
        })
        .into_response(),
        Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct DownloadLogsQuery {
    kind: String,
}

async fn download_logs(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DownloadLogsQuery>,
) -> Response {
    let kind = match LogKind::parse(query.kind.trim()) {
        Ok(kind) => kind,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    match kind {
        LogKind::Runtime => match state.logger.read_bytes(LogKind::Runtime) {
            Ok(bytes) => download_response("text/plain; charset=utf-8", "runtime.log", bytes),
            Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        },
        LogKind::Audit => match state.logger.read_bytes(LogKind::Audit) {
            Ok(bytes) => download_response("text/plain; charset=utf-8", "audit.log", bytes),
            Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        },
        LogKind::All => match build_log_archive(&state) {
            Ok(bytes) => download_response("application/zip", "logs.zip", bytes),
            Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        },
    }
}

fn build_log_archive(state: &AppState) -> Result<Vec<u8>> {
    let cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, kind) in [
        ("runtime.log", LogKind::Runtime),
        ("audit.log", LogKind::Audit),
    ] {
        writer.start_file(name, options)?;
        writer.write_all(&state.logger.read_bytes(kind)?)?;
    }
    let cursor = writer.finish()?;
    Ok(cursor.into_inner())
}

#[derive(Debug, Deserialize)]
struct ClearLogsRequest {
    kind: String,
}

async fn clear_logs(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ClearLogsRequest>,
) -> Response {
    let kind = match LogKind::parse(payload.kind.trim()) {
        Ok(kind) => kind,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    match state.logger.clear(kind) {
        Ok(()) => Json(SimpleMessage {
            message: "日志已清空".to_string(),
        })
        .into_response(),
        Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}

#[derive(Debug, Serialize)]
struct SettingsResponse {
    settings: EditableSettings,
    header_preview: BTreeMap<String, String>,
    locked_fields: Vec<String>,
    config_path: String,
}

async fn get_settings(State(state): State<Arc<AppState>>) -> Response {
    let mut locked_fields: Vec<String> = state
        .config_manager
        .locked_fields()
        .await
        .into_iter()
        .collect();
    locked_fields.sort();
    Json(SettingsResponse {
        settings: state.config_manager.editable_settings().await,
        header_preview: state.config_manager.header_preview().await,
        locked_fields,
        config_path: state
            .config_manager
            .config_path()
            .await
            .display()
            .to_string(),
    })
    .into_response()
}

async fn update_settings(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<EditableSettings>,
) -> Response {
    match state.config_manager.update_settings(payload).await {
        Ok(config) => match parse_byte_size_str(&config.logging.max_file_size).and_then(|size| {
            state.logger.update_max_file_size(size)?;
            state.logger.update_runtime_level(&config.log_level)
        }) {
            Ok(()) => {
                state.scheduler.wake();
                Json(SimpleMessage {
                    message: "设置已保存".to_string(),
                })
                .into_response()
            }
            Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        },
        Err(err) => json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    }
}

#[derive(Debug, Serialize)]
struct SimpleMessage {
    message: String,
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(SimpleMessage {
            message: message.to_string(),
        }),
    )
        .into_response()
}

fn file_name_from_key(key: &str) -> String {
    std::path::Path::new(key)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("credential.json")
        .to_string()
}

fn download_response(content_type: &str, file_name: impl Into<String>, bytes: Vec<u8>) -> Response {
    let file_name = file_name.into();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{file_name}\""))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    (StatusCode::OK, headers, bytes).into_response()
}

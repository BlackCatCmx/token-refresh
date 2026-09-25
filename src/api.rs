use std::collections::{BTreeMap, BTreeSet};
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
use crate::backup::RestoreResult;
use crate::backup_archive;
use crate::config::{EditableSettings, parse_byte_size_str};
use crate::cpa_client::CpaClient;
use crate::cpa_config::CpaConfig;
use crate::credential::CodexCredentialFile;
use crate::credential_store::{CredentialStore, CredentialZone};
use crate::import::{
    ImportedFile, UserAgentPatchMode, UserAgentPatchSummary, import_json_files, import_zip,
    patch_user_agents,
};
use crate::logging::LogKind;
use crate::migration_archive::{self, MigrationArchiveInput, MigrationRestoreSummary};
use crate::web::{AppState, app_css, dashboard_js, dashboard_page, login_js, login_page};
use crate::write_coordinator::WriteCoordinator;

const LOG_LINE_LIMIT: usize = 50;

pub fn router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/api/session/logout", post(logout))
        .route("/api/credentials", get(list_credentials))
        .route(
            "/api/credentials/import-json",
            post(import_json_credentials),
        )
        .route("/api/credentials/import-zip", post(import_zip_credentials))
        .route(
            "/api/credentials/user-agent/fill-missing",
            post(fill_missing_credential_user_agents),
        )
        .route(
            "/api/credentials/user-agent/reassign-cli-version",
            post(reassign_credential_cli_versions),
        )
        .route(
            "/api/credentials/user-agent/reassign",
            post(reassign_credential_user_agents),
        )
        .route("/api/credentials/refresh", post(refresh_credential))
        .route("/api/credentials/restore", post(restore_credentials))
        .route(
            "/api/credentials/cpa-exhausted/clear",
            post(clear_cpa_exhausted_credentials),
        )
        .route("/api/credentials/delete", post(delete_credentials))
        .route(
            "/api/credentials/content",
            get(get_credential_content).put(update_credential_content),
        )
        .route("/api/credentials/download", get(download_credential))
        .route(
            "/api/credentials/archive.zip",
            get(download_credential_archive),
        )
        .route(
            "/api/credentials/archive-selected.zip",
            post(download_selected_credential_archive),
        )
        .route("/api/migration/export.zip", post(export_migration_zip))
        .route("/api/migration/import", post(import_migration_zip))
        .route("/api/backup/status", get(get_backup_status))
        .route("/api/backup/snapshots", get(list_backup_snapshots))
        .route("/api/backup/run", post(run_backup_now))
        .route("/api/backup/restore", post(restore_from_backup))
        .route("/api/scheduler/start", post(start_scheduler))
        .route("/api/scheduler/stop", post(stop_scheduler))
        .route(
            "/api/scheduler/manual-refresh-all",
            post(trigger_manual_refresh_all),
        )
        .route("/api/scheduler/status", get(scheduler_status))
        .route("/api/logs", get(get_logs))
        .route("/api/logs/download", get(download_logs))
        .route("/api/logs/clear", post(clear_logs))
        .route(
            "/api/cpa/config",
            get(get_cpa_config).put(update_cpa_config),
        )
        .route("/api/cpa/test", post(test_cpa_connection))
        .route("/api/cpa/status", get(get_cpa_status))
        .route("/api/cpa/reclaim-all", post(run_cpa_reclaim_all))
        .route("/api/cpa/inspect-once", post(run_cpa_inspect_once))
        .route("/api/cpa/supplement", post(run_cpa_supplement))
        .route("/api/cpa/logs", get(get_cpa_logs))
        .route("/api/cpa/logs/download", get(download_cpa_logs))
        .route("/api/cpa/logs/clear", post(clear_cpa_logs))
        .route(
            "/api/settings/header-preview",
            get(get_random_header_preview),
        )
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
    cpa_exhausted: bool,
    exhausted_resets_at: Option<String>,
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
            cpa_exhausted: status
                .and_then(|value| value.cpa_exhausted)
                .unwrap_or(false),
            exhausted_resets_at: status.and_then(|value| value.exhausted_resets_at.clone()),
        });
    }
    Ok(items)
}

async fn acquire_write_guard(
    coordinator: &WriteCoordinator,
) -> Result<(
    tokio::sync::OwnedMutexGuard<()>,
    tokio::sync::OwnedMutexGuard<()>,
)> {
    coordinator.ensure_writes_allowed()?;
    let activity_guard = coordinator.lock_activity().await;
    let commit_guard = coordinator.lock_commit().await;
    coordinator.ensure_writes_allowed()?;
    Ok((activity_guard, commit_guard))
}

async fn import_json_credentials(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Response {
    let user_agent_list = state
        .config_manager
        .effective_config()
        .await
        .request_identity;
    let files = match collect_json_files(&mut multipart).await {
        Ok(files) => files,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    let _write_guards = match acquire_write_guard(&state.write_coordinator).await {
        Ok(guard) => guard,
        Err(err) => return json_error(StatusCode::CONFLICT, &err.to_string()),
    };
    match import_json_files(&state.store, files, &user_agent_list) {
        Ok(imported) => {
            let _ = state.logger.runtime(
                "info",
                format!("imported {} JSON credential file(s)", imported.len()),
            );
            state.backup.mark_dirty("import_json_credentials");
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
    let user_agent_list = state
        .config_manager
        .effective_config()
        .await
        .request_identity;
    let field = match multipart.next_field().await {
        Ok(Some(field)) => field,
        Ok(None) => return json_error(StatusCode::BAD_REQUEST, "未上传 ZIP 文件"),
        Err(err) => return json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    let bytes = match field.bytes().await.context("failed to read uploaded ZIP") {
        Ok(bytes) => bytes,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    let _write_guards = match acquire_write_guard(&state.write_coordinator).await {
        Ok(guard) => guard,
        Err(err) => return json_error(StatusCode::CONFLICT, &err.to_string()),
    };
    match import_zip(&state.store, &bytes, &user_agent_list) {
        Ok(imported) => {
            let _ = state.logger.runtime(
                "info",
                format!("imported {} credential file(s) from ZIP", imported.len()),
            );
            state.backup.mark_dirty("import_zip_credentials");
            state.scheduler.wake();
            Json(serde_json::json!({ "imported": imported })).into_response()
        }
        Err(err) => json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    }
}

#[derive(Debug, Serialize)]
struct UserAgentPatchResponse {
    updated: usize,
    unchanged: usize,
    skipped_invalid: usize,
}

async fn fill_missing_credential_user_agents(State(state): State<Arc<AppState>>) -> Response {
    patch_credential_user_agents(state, UserAgentPatchMode::FillMissing).await
}

async fn reassign_credential_cli_versions(State(state): State<Arc<AppState>>) -> Response {
    patch_credential_user_agents(state, UserAgentPatchMode::ReassignCliVersion).await
}

async fn reassign_credential_user_agents(State(state): State<Arc<AppState>>) -> Response {
    patch_credential_user_agents(state, UserAgentPatchMode::ForceReassign).await
}

async fn patch_credential_user_agents(state: Arc<AppState>, mode: UserAgentPatchMode) -> Response {
    let user_agent_list = state
        .config_manager
        .effective_config()
        .await
        .request_identity;
    let _write_guards = match acquire_write_guard(&state.write_coordinator).await {
        Ok(guard) => guard,
        Err(err) => return json_error(StatusCode::CONFLICT, &err.to_string()),
    };
    match patch_user_agents(&state.store, &user_agent_list, mode) {
        Ok(UserAgentPatchSummary {
            updated,
            unchanged,
            skipped_invalid,
        }) => {
            let action = match mode {
                UserAgentPatchMode::FillMissing => "filled missing credential user agents",
                UserAgentPatchMode::ReassignCliVersion => {
                    "reassigned credential user agent cli versions"
                }
                UserAgentPatchMode::ForceReassign => "reassigned credential user agents",
            };
            let _ = state.logger.runtime(
                "info",
                format!(
                    "{} (updated={}, unchanged={}, skipped_invalid={})",
                    action, updated, unchanged, skipped_invalid
                ),
            );
            if updated > 0 {
                state.backup.mark_dirty("patch_credential_user_agents");
            }
            state.scheduler.wake();
            Json(UserAgentPatchResponse {
                updated,
                unchanged,
                skipped_invalid,
            })
            .into_response()
        }
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
    if let Err(err) = state.write_coordinator.ensure_writes_allowed() {
        return json_error(StatusCode::CONFLICT, &err.to_string());
    }
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
            state.backup.mark_dirty("manual_refresh");
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
    let _write_guards = match acquire_write_guard(&state.write_coordinator).await {
        Ok(guard) => guard,
        Err(err) => return json_error(StatusCode::CONFLICT, &err.to_string()),
    };
    match move_credentials(
        &state.store,
        &state.status_store,
        CredentialZone::Abnormal,
        CredentialZone::Normal,
        &payload.names,
    ) {
        Ok(count) => {
            let _ = state.logger.runtime(
                "info",
                format!(
                    "restored {} credential file(s) from abnormal to normal",
                    count
                ),
            );
            state.backup.mark_dirty("restore_credentials");
            state.scheduler.wake();
            Json(serde_json::json!({ "restored": count })).into_response()
        }
        Err(err) => json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    }
}

#[derive(Debug, Serialize)]
struct ClearCpaExhaustedResponse {
    selected: usize,
    cleared: usize,
    skipped: usize,
}

async fn clear_cpa_exhausted_credentials(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<NamesRequest>,
) -> Response {
    let _write_guards = match acquire_write_guard(&state.write_coordinator).await {
        Ok(guard) => guard,
        Err(err) => return json_error(StatusCode::CONFLICT, &err.to_string()),
    };
    match clear_cpa_exhausted_statuses(&state.store, &state.status_store, &payload.names) {
        Ok(summary) => {
            if summary.cleared > 0 {
                let _ = state.logger.runtime(
                    "info",
                    format!(
                        "cleared CPA exhausted flag for {} normal credential(s), skipped {}",
                        summary.cleared, summary.skipped
                    ),
                );
                state.backup.mark_dirty("clear_cpa_exhausted");
                state.scheduler.wake();
            }
            Json(summary).into_response()
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
    let _write_guards = match acquire_write_guard(&state.write_coordinator).await {
        Ok(guard) => guard,
        Err(err) => return json_error(StatusCode::CONFLICT, &err.to_string()),
    };
    for name in &payload.names {
        if let Err(err) = state.store.delete(zone, name.trim()) {
            return json_error(StatusCode::BAD_REQUEST, &err.to_string());
        }
        if let Err(err) = state.status_store.remove(name.trim()) {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
        }
    }
    let _ = state.logger.runtime(
        "info",
        format!(
            "deleted {} credential file(s) from {} zone",
            payload.names.len(),
            zone.as_str()
        ),
    );
    if !payload.names.is_empty() {
        state.backup.mark_dirty("delete_credentials");
    }
    state.scheduler.wake();
    Json(serde_json::json!({ "deleted": payload.names.len() })).into_response()
}

#[derive(Debug, Deserialize)]
struct DeleteRequest {
    zone: String,
    names: Vec<String>,
}

fn clear_cpa_exhausted_statuses(
    store: &CredentialStore,
    status_store: &crate::status::CredentialStatusStore,
    names: &[String],
) -> Result<ClearCpaExhaustedResponse> {
    let mut seen = BTreeSet::new();
    let mut selected = 0usize;
    let mut cleared = 0usize;
    let mut skipped = 0usize;

    for raw_name in names {
        let name = raw_name.trim();
        if name.is_empty() || !seen.insert(name.to_string()) {
            continue;
        }
        selected += 1;
        if !store.key_to_path(CredentialZone::Normal, name)?.exists() {
            skipped += 1;
            continue;
        }
        let exhausted = status_store
            .get(name)?
            .and_then(|record| record.cpa_exhausted)
            .unwrap_or(false);
        if exhausted {
            status_store.clear_cpa_exhausted(name)?;
            cleared += 1;
        } else {
            skipped += 1;
        }
    }

    Ok(ClearCpaExhaustedResponse {
        selected,
        cleared,
        skipped,
    })
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

#[derive(Debug, Serialize)]
struct CredentialContentResponse {
    zone: String,
    name: String,
    content: String,
}

async fn get_credential_content(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DownloadCredentialQuery>,
) -> Response {
    let zone = match CredentialZone::parse(query.zone.trim()) {
        Ok(zone) => zone,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    match state.store.read_bytes(zone, query.name.trim()) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(content) => Json(CredentialContentResponse {
                zone: zone.as_str().to_string(),
                name: query.name.trim().to_string(),
                content,
            })
            .into_response(),
            Err(err) => json_error(
                StatusCode::BAD_REQUEST,
                &format!("凭证文件不是有效 UTF-8: {err}"),
            ),
        },
        Err(err) => json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct UpdateCredentialContentRequest {
    zone: String,
    name: String,
    content: String,
}

async fn update_credential_content(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UpdateCredentialContentRequest>,
) -> Response {
    let zone = match CredentialZone::parse(payload.zone.trim()) {
        Ok(zone) => zone,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    if let Err(err) = validate_credential_content(&payload.content) {
        return json_error(StatusCode::BAD_REQUEST, &err.to_string());
    }
    let _write_guards = match acquire_write_guard(&state.write_coordinator).await {
        Ok(guard) => guard,
        Err(err) => return json_error(StatusCode::CONFLICT, &err.to_string()),
    };
    match state
        .store
        .write_bytes(zone, payload.name.trim(), payload.content.as_bytes())
    {
        Ok(_) => {
            let _ = state.logger.runtime(
                "info",
                format!(
                    "credential content updated for {} in {} zone",
                    payload.name.trim(),
                    zone.as_str()
                ),
            );
            state.backup.mark_dirty("update_credential_content");
            state.scheduler.wake();
            Json(SimpleMessage {
                message: "凭证已保存".to_string(),
            })
            .into_response()
        }
        Err(err) => json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    }
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

#[derive(Debug, Deserialize)]
struct SelectedArchiveRequest {
    zone: String,
    names: Vec<String>,
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

async fn download_selected_credential_archive(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SelectedArchiveRequest>,
) -> Response {
    match archive::build_selected_credential_archive(
        &state.store,
        payload.zone.trim(),
        &payload.names,
    ) {
        Ok(bytes) => download_response(
            "application/zip",
            format!("credentials-{}-selected.zip", payload.zone.trim()),
            bytes,
        ),
        Err(err) => json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct ExportMigrationRequest {
    confirmation: String,
}

#[derive(Debug)]
struct ImportMigrationPayload {
    bytes: Vec<u8>,
    confirmation: String,
    password: Option<String>,
}

async fn export_migration_zip(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ExportMigrationRequest>,
) -> Response {
    if payload.confirmation.trim() != "确定导出迁移包" {
        return json_error(StatusCode::BAD_REQUEST, "请输入“确定导出迁移包”后再继续");
    }
    match export_migration_archive(&state).await {
        Ok((bytes, file_name)) => download_response("application/zip", file_name, bytes),
        Err(err) => json_error(migration_error_status(&err), &err.to_string()),
    }
}

async fn import_migration_zip(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Response {
    let payload = match collect_migration_import_payload(&mut multipart).await {
        Ok(payload) => payload,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    if payload.confirmation.trim() != "确定导入迁移包" {
        return json_error(StatusCode::BAD_REQUEST, "请输入“确定导入迁移包”后再继续");
    }
    let password = payload
        .password
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or(state.config_manager.web_password().await);
    match restore_migration_archive_from_bytes(&state, &payload.bytes, &password).await {
        Ok(summary) => Json(summary).into_response(),
        Err(err) if migration_archive::is_invalid_migration_password(&err) => json_error_with_code(
            StatusCode::BAD_REQUEST,
            "迁移包密码错误",
            "migration_password_invalid",
        ),
        Err(err) => json_error(migration_error_status(&err), &err.to_string()),
    }
}

async fn export_migration_archive(state: &AppState) -> Result<(Vec<u8>, String)> {
    let scheduler_status = state.scheduler.status().await;
    if scheduler_status.manual_running || scheduler_status.manual_pending {
        anyhow::bail!("手动全量刷新正在执行中，请等待其完成后重试");
    }
    state.scheduler.stop().await?;
    let _activity_guard = state.write_coordinator.lock_activity().await;
    let _commit_guard = state.write_coordinator.lock_commit().await;
    let normal_files = collect_zone_file_bytes(&state.store, CredentialZone::Normal)?;
    let abnormal_files = collect_zone_file_bytes(&state.store, CredentialZone::Abnormal)?;
    let status_records = state.status_store.all()?;
    let effective_config = state.config_manager.effective_config().await;
    let editable_settings = EditableSettings::from(&effective_config);
    let cpa_config = state.cpa_config.get();
    let created_at = chrono::Utc::now();
    let bytes = migration_archive::build_migration_archive(
        MigrationArchiveInput {
            normal_files,
            abnormal_files,
            status_records,
            editable_settings,
            cpa_config,
        },
        created_at,
        &state.config_manager.web_password().await,
    )?;
    let file_name = format!(
        "token-refresh-migration-{}.zip",
        created_at.format("%Y%m%dT%H%M%SZ")
    );
    let _ = state.logger.runtime(
        "info",
        format!("migration archive exported bytes={}", bytes.len()),
    );
    Ok((bytes, file_name))
}

async fn restore_migration_archive_from_bytes(
    state: &AppState,
    bytes: &[u8],
    password: &str,
) -> Result<MigrationRestoreSummary> {
    let parsed = migration_archive::parse_migration_archive(bytes, password)?;
    state
        .config_manager
        .validate_settings_update(&parsed.editable_settings)
        .await?;
    let cpa_config = migration_archive::sanitize_cpa_config(parsed.cpa_config.clone()).normalized();
    cpa_config.validate()?;

    let scheduler_status = state.scheduler.status().await;
    if scheduler_status.manual_running || scheduler_status.manual_pending {
        anyhow::bail!("手动全量刷新正在执行中，请等待其完成后重试");
    }
    let previous_scheduler_enabled = state.scheduler.persisted_enabled()?;
    let _activity_guard = state.write_coordinator.lock_activity().await;
    let freeze_guard = state.write_coordinator.begin_restore()?;
    state.scheduler.pause().await;
    let result = async {
        let _commit_guard = state.write_coordinator.lock_commit().await;
        let summary = migration_archive::restore_migration_archive(
            &state.store,
            &state.status_store,
            &parsed,
        )?;
        let updated_config = state
            .config_manager
            .update_settings(parsed.editable_settings)
            .await?;
        state.cpa_config.set(cpa_config)?;
        parse_byte_size_str(&updated_config.logging.max_file_size).and_then(|size| {
            state.logger.update_max_file_size(size)?;
            state.logger.update_runtime_level(&updated_config.log_level)
        })?;
        Ok::<MigrationRestoreSummary, anyhow::Error>(summary)
    }
    .await;
    drop(freeze_guard);

    let import_committed = result.is_ok();
    let result = if import_committed {
        state.scheduler.clear_backoff().await;
        match state.scheduler.stop().await {
            Ok(()) => {
                state.scheduler.wake();
                state.cpa_scheduler.wake();
                result
            }
            Err(err) => Err(err),
        }
    } else {
        if previous_scheduler_enabled {
            state.scheduler.resume().await;
        }
        result
    };

    match &result {
        Ok(summary) => {
            let _ = state.logger.runtime(
                "info",
                format!(
                    "migration import completed normal_count={} abnormal_count={} status_count={}",
                    summary.normal_count, summary.abnormal_count, summary.status_count
                ),
            );
        }
        Err(err) => {
            let _ = state
                .logger
                .runtime("error", format!("migration import failed: {err:#}"));
        }
    }
    result
}

fn collect_zone_file_bytes(
    store: &CredentialStore,
    zone: CredentialZone,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut files = BTreeMap::new();
    for entry in store.scan_zone(zone)? {
        files.insert(entry.key.clone(), store.read_bytes(zone, &entry.key)?);
    }
    Ok(files)
}

async fn collect_migration_import_payload(
    multipart: &mut Multipart,
) -> Result<ImportMigrationPayload> {
    let mut bytes = None;
    let mut confirmation = None;
    let mut password = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .context("failed to read upload field")?
    {
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "file" => {
                bytes = Some(
                    field
                        .bytes()
                        .await
                        .context("failed to read uploaded migration ZIP")?
                        .to_vec(),
                );
            }
            "confirmation" => {
                confirmation = Some(
                    field
                        .text()
                        .await
                        .context("failed to read migration confirmation")?,
                );
            }
            "password" => {
                password = Some(
                    field
                        .text()
                        .await
                        .context("failed to read migration password")?,
                );
            }
            _ => {}
        }
    }
    Ok(ImportMigrationPayload {
        bytes: bytes.context("未上传迁移 ZIP 文件")?,
        confirmation: confirmation.unwrap_or_default(),
        password,
    })
}

async fn start_scheduler(State(state): State<Arc<AppState>>) -> Response {
    match state.scheduler.start().await {
        Ok(()) => {
            let _ = state
                .logger
                .runtime("info", "scheduler enabled from web console");
            Json(SimpleMessage {
                message: "自动刷新已开启".to_string(),
            })
            .into_response()
        }
        Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}

async fn stop_scheduler(State(state): State<Arc<AppState>>) -> Response {
    match state.scheduler.stop().await {
        Ok(()) => {
            let _ = state
                .logger
                .runtime("info", "scheduler disabled from web console");
            Json(SimpleMessage {
                message: "自动刷新已停止".to_string(),
            })
            .into_response()
        }
        Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}

async fn trigger_manual_refresh_all(State(state): State<Arc<AppState>>) -> Response {
    if let Err(err) = state.write_coordinator.ensure_writes_allowed() {
        return json_error(StatusCode::CONFLICT, &err.to_string());
    }
    match state.scheduler.trigger_manual_refresh_all().await {
        Ok(()) => {
            let _ = state
                .logger
                .runtime("info", "manual full refresh requested from web console");
            Json(SimpleMessage {
                message: "手动全量刷新已开始".to_string(),
            })
            .into_response()
        }
        Err(err) => json_error(StatusCode::CONFLICT, &err.to_string()),
    }
}

async fn scheduler_status(State(state): State<Arc<AppState>>) -> Response {
    let status = state.scheduler.status().await;
    let scheduled_credential_count = match state.store.scan_zone(CredentialZone::Normal) {
        Ok(entries) => entries.len(),
        Err(err) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    };
    Json(SchedulerStatusResponse {
        status,
        scheduled_credential_count,
    })
    .into_response()
}

async fn get_backup_status(State(state): State<Arc<AppState>>) -> Response {
    Json(state.backup.status().await).into_response()
}

async fn list_backup_snapshots(State(state): State<Arc<AppState>>) -> Response {
    match state.backup.list_snapshots().await {
        Ok(result) => Json(serde_json::json!({
            "items": result.items,
            "warnings": result.warnings
        }))
        .into_response(),
        Err(err) => json_error(backup_error_status(&err), &err.to_string()),
    }
}

#[derive(Debug, Deserialize, Default)]
struct RunBackupNowRequest {
    #[serde(default)]
    remote_name: Option<String>,
}

async fn run_backup_now(
    State(state): State<Arc<AppState>>,
    payload: Option<Json<RunBackupNowRequest>>,
) -> Response {
    let remote_name = payload.and_then(|Json(payload)| payload.remote_name);
    match state.backup.run_manual_backup(remote_name.as_deref()).await {
        Ok(snapshot) => Json(serde_json::json!({ "snapshot": snapshot })).into_response(),
        Err(err) => json_error(backup_error_status(&err), &err.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct RestoreBackupRequest {
    remote_name: String,
    snapshot_key: String,
    confirmation: String,
    #[serde(default)]
    password: Option<String>,
}

async fn restore_from_backup(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RestoreBackupRequest>,
) -> Response {
    if payload.confirmation.trim() != "确定还原" {
        return json_error(StatusCode::BAD_REQUEST, "请输入“确定还原”后再继续");
    }
    let password = payload
        .password
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or(state.config_manager.web_password().await);
    match state
        .backup
        .restore_snapshot(
            payload.remote_name.trim(),
            payload.snapshot_key.trim(),
            &password,
        )
        .await
    {
        Ok(RestoreResult {
            snapshot_key,
            normal_count,
            abnormal_count,
        }) => {
            state.scheduler.wake();
            Json(serde_json::json!({
                "snapshot_key": snapshot_key,
                "normal_count": normal_count,
                "abnormal_count": abnormal_count
            }))
            .into_response()
        }
        Err(err) if backup_archive::is_invalid_backup_password(&err) => json_error_with_code(
            StatusCode::BAD_REQUEST,
            "备份密码错误",
            "backup_password_invalid",
        ),
        Err(err) => json_error(backup_error_status(&err), &err.to_string()),
    }
}

#[derive(Debug, Serialize)]
struct SchedulerStatusResponse {
    #[serde(flatten)]
    status: crate::scheduler::SchedulerStatus,
    scheduled_credential_count: usize,
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

fn clamp_log_line_limit(limit: Option<usize>) -> usize {
    limit
        .map(|value| value.min(LOG_LINE_LIMIT))
        .unwrap_or(LOG_LINE_LIMIT)
}

async fn get_logs(State(state): State<Arc<AppState>>, Query(query): Query<LogsQuery>) -> Response {
    let kind = match LogKind::parse(query.kind.trim()) {
        Ok(kind) => kind,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    match state
        .logger
        .read_tail(kind, clamp_log_line_limit(query.limit))
    {
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
    }
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
struct CpaConfigResponse {
    enabled: bool,
    base_url: String,
    inspect_interval_minutes: u64,
    auto_supplement_enabled: bool,
    supplement_target: usize,
    auto_assign_proxy_enabled: bool,
    proxy_list: String,
    safety_abort_enabled: bool,
    safety_abort_ratio_percent: u8,
    management_key_set: bool,
}

#[derive(Debug, Deserialize)]
struct UpdateCpaConfigRequest {
    enabled: bool,
    base_url: String,
    management_key: String,
    inspect_interval_minutes: u64,
    auto_supplement_enabled: bool,
    supplement_target: usize,
    #[serde(default)]
    auto_assign_proxy_enabled: Option<bool>,
    #[serde(default)]
    proxy_list: Option<String>,
    safety_abort_enabled: bool,
    safety_abort_ratio_percent: u8,
}

#[derive(Debug, Deserialize)]
struct TestCpaConnectionRequest {
    base_url: String,
    #[serde(default)]
    management_key: Option<String>,
}

#[derive(Debug, Serialize)]
struct TestCpaConnectionResponse {
    ok: bool,
    status_code: Option<u16>,
    message: String,
}

async fn get_cpa_config(State(state): State<Arc<AppState>>) -> Response {
    let config = state.cpa_config.get();
    Json(CpaConfigResponse {
        enabled: config.enabled,
        base_url: config.base_url,
        inspect_interval_minutes: config.inspect_interval_minutes,
        auto_supplement_enabled: config.auto_supplement_enabled,
        supplement_target: config.supplement_target,
        auto_assign_proxy_enabled: config.auto_assign_proxy_enabled,
        proxy_list: config.proxy_list,
        safety_abort_enabled: config.safety_abort_enabled,
        safety_abort_ratio_percent: config.safety_abort_ratio_percent,
        management_key_set: !config.management_key.trim().is_empty(),
    })
    .into_response()
}

async fn update_cpa_config(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UpdateCpaConfigRequest>,
) -> Response {
    let existing = state.cpa_config.get();
    let config = CpaConfig {
        enabled: payload.enabled,
        base_url: payload.base_url,
        management_key: if payload.management_key.trim().is_empty() {
            existing.management_key
        } else {
            payload.management_key
        },
        inspect_interval_minutes: payload.inspect_interval_minutes,
        auto_supplement_enabled: payload.auto_supplement_enabled,
        supplement_target: payload.supplement_target,
        auto_assign_proxy_enabled: payload
            .auto_assign_proxy_enabled
            .unwrap_or(existing.auto_assign_proxy_enabled),
        proxy_list: payload.proxy_list.unwrap_or(existing.proxy_list),
        safety_abort_enabled: payload.safety_abort_enabled,
        safety_abort_ratio_percent: payload.safety_abort_ratio_percent,
    };
    match state.cpa_config.set(config) {
        Ok(()) => {
            state.cpa_scheduler.wake();
            Json(SimpleMessage {
                message: "CPA 配置已保存".to_string(),
            })
            .into_response()
        }
        Err(err) => json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    }
}

async fn test_cpa_connection(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestCpaConnectionRequest>,
) -> Response {
    let existing = state.cpa_config.get();
    let management_key = match payload.management_key {
        Some(value) if !value.trim().is_empty() => value,
        _ => existing.management_key,
    };
    let client = match CpaClient::new(&payload.base_url, &management_key) {
        Ok(client) => client,
        Err(err) => {
            return Json(TestCpaConnectionResponse {
                ok: false,
                status_code: None,
                message: err.to_string(),
            })
            .into_response();
        }
    };
    match client.test_connection().await {
        Ok(status) => Json(TestCpaConnectionResponse {
            ok: status.is_success(),
            status_code: Some(status.as_u16()),
            message: status
                .canonical_reason()
                .unwrap_or(if status.is_success() {
                    "OK"
                } else {
                    "HTTP error"
                })
                .to_string(),
        })
        .into_response(),
        Err(err) => Json(TestCpaConnectionResponse {
            ok: false,
            status_code: None,
            message: err.to_string(),
        })
        .into_response(),
    }
}

#[derive(Debug, Serialize)]
struct CpaStatusResponse {
    #[serde(flatten)]
    status: crate::cpa_scheduler::CpaSchedulerStatus,
    last_result: Option<crate::cpa_manager::InspectResult>,
}

async fn get_cpa_status(State(state): State<Arc<AppState>>) -> Response {
    Json(CpaStatusResponse {
        status: state.cpa_scheduler.status().await,
        last_result: state.cpa_manager.last_result(),
    })
    .into_response()
}

async fn run_cpa_inspect_once(State(state): State<Arc<AppState>>) -> Response {
    let config = state.cpa_config.get();
    let result = state.cpa_manager.inspect_once(&config).await;
    Json(result).into_response()
}

async fn run_cpa_reclaim_all(State(state): State<Arc<AppState>>) -> Response {
    let config = state.cpa_config.get();
    let result = state.cpa_manager.reclaim_all(&config).await;
    Json(result).into_response()
}

#[derive(Debug, Deserialize)]
struct CpaSupplementRequest {
    count: usize,
}

async fn run_cpa_supplement(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CpaSupplementRequest>,
) -> Response {
    if payload.count == 0 {
        return json_error(StatusCode::BAD_REQUEST, "补充数量必须大于 0");
    }
    let config = state.cpa_config.get();
    let result = state
        .cpa_manager
        .supplement_once(&config, payload.count)
        .await;
    Json(result).into_response()
}

#[derive(Debug, Deserialize)]
struct CpaLogsQuery {
    limit: Option<usize>,
}

async fn get_cpa_logs(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CpaLogsQuery>,
) -> Response {
    match state.cpa_log.read_tail(clamp_log_line_limit(query.limit)) {
        Ok(content) => Json(LogsResponse {
            kind: "cpa".to_string(),
            content,
        })
        .into_response(),
        Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}

async fn download_cpa_logs(State(state): State<Arc<AppState>>) -> Response {
    match state.cpa_log.read_bytes() {
        Ok(bytes) => download_response("text/plain; charset=utf-8", "cpa.log", bytes),
        Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}

async fn clear_cpa_logs(State(state): State<Arc<AppState>>) -> Response {
    match state.cpa_log.clear() {
        Ok(()) => Json(SimpleMessage {
            message: "CPA 日志已清空".to_string(),
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
    match state.config_manager.header_preview().await {
        Ok(header_preview) => Json(SettingsResponse {
            settings: state.config_manager.editable_settings().await,
            header_preview,
            locked_fields,
            config_path: state
                .config_manager
                .config_path()
                .await
                .display()
                .to_string(),
        })
        .into_response(),
        Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}

#[derive(Debug, Serialize)]
struct HeaderPreviewResponse {
    header_preview: BTreeMap<String, String>,
}

async fn get_random_header_preview(State(state): State<Arc<AppState>>) -> Response {
    match state.config_manager.random_header_preview().await {
        Ok(header_preview) => Json(HeaderPreviewResponse { header_preview }).into_response(),
        Err(err) => json_error(StatusCode::BAD_REQUEST, &err.to_string()),
    }
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
                let _ = state.logger.runtime(
                    "info",
                    format!(
                        "settings updated (log_level={}, max_file_size={}, proxy_mode={}, abnormal_threshold={}, timeout={}, backup_enabled={}, backup_remote_count={})",
                        config.log_level.trim(),
                        config.logging.max_file_size.trim(),
                        config.proxy.mode.trim(),
                        config.credential_management.abnormal_threshold,
                        config.network.timeout.trim(),
                        config.backup.enabled,
                        config.backup.remotes.len(),
                    ),
                );
                state.backup.wake();
                state.scheduler.wake();
                Json(SimpleMessage {
                    message: "设置已保存".to_string(),
                })
                .into_response()
            }
            Err(err) => {
                let _ = state
                    .logger
                    .runtime("error", format!("settings update apply failed: {err:#}"));
                json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string())
            }
        },
        Err(err) => {
            let _ = state
                .logger
                .runtime("warn", format!("settings update rejected: {err:#}"));
            json_error(StatusCode::BAD_REQUEST, &err.to_string())
        }
    }
}

#[derive(Debug, Serialize)]
struct SimpleMessage {
    message: String,
}

#[derive(Debug, Serialize)]
struct ErrorMessage {
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'static str>,
}

fn json_error(status: StatusCode, message: &str) -> Response {
    json_error_with_optional_code(status, message, None)
}

fn json_error_with_code(status: StatusCode, message: &str, code: &'static str) -> Response {
    json_error_with_optional_code(status, message, Some(code))
}

fn json_error_with_optional_code(
    status: StatusCode,
    message: &str,
    code: Option<&'static str>,
) -> Response {
    (
        status,
        Json(ErrorMessage {
            message: message.to_string(),
            code,
        }),
    )
        .into_response()
}

fn backup_error_status(error: &anyhow::Error) -> StatusCode {
    let message = error.to_string();
    if message.contains("未启用")
        || message.contains("配置不完整")
        || message.contains("正在执行")
        || message.contains("从备份还原")
        || message.contains("请等待其完成")
    {
        StatusCode::CONFLICT
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

fn migration_error_status(error: &anyhow::Error) -> StatusCode {
    let message = error.to_string();
    if message.contains("正在执行")
        || message.contains("从备份还原")
        || message.contains("请等待其完成")
        || message.contains("当前已有")
    {
        StatusCode::CONFLICT
    } else {
        StatusCode::BAD_REQUEST
    }
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

fn validate_credential_content(content: &str) -> Result<()> {
    let credential: CodexCredentialFile = serde_json::from_str(content).context("JSON 格式错误")?;
    if !credential.is_codex() {
        anyhow::bail!("只允许保存 type 为 codex 的凭证文件");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::status::CredentialStatusStore;

    #[tokio::test]
    async fn deleting_during_refresh_cannot_restore_a_deleted_credential() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.credentials_dir = temp.path().join("credentials");
        config.abnormal_credentials_dir = temp.path().join("credentials_abnormal");
        let store = Arc::new(CredentialStore::new(&config, None).unwrap());
        let coordinator = Arc::new(WriteCoordinator::new());
        let credential = CodexCredentialFile {
            provider_type: "codex".to_string(),
            refresh_token: "refresh".to_string(),
            ..CodexCredentialFile::default()
        };
        store
            .write_credential(CredentialZone::Normal, "account.json", &credential)
            .unwrap();

        let activity_guard = coordinator.lock_activity().await;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let delete_store = store.clone();
        let delete_coordinator = coordinator.clone();
        let mut deletion = tokio::spawn(async move {
            started_tx.send(()).unwrap();
            let _write_guards = acquire_write_guard(&delete_coordinator).await.unwrap();
            delete_store
                .delete(CredentialZone::Normal, "account.json")
                .unwrap();
        });
        started_rx.await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut deletion)
                .await
                .is_err()
        );

        store
            .write_credential(CredentialZone::Normal, "account.json", &credential)
            .unwrap();
        drop(activity_guard);
        deletion.await.unwrap();
        assert!(
            store
                .read_entry(CredentialZone::Normal, "account.json")
                .is_err()
        );
    }

    #[test]
    fn validate_credential_content_accepts_valid_codex_json() {
        let raw = r#"{"type":"codex","access_token":"a","refresh_token":"b"}"#;
        assert!(validate_credential_content(raw).is_ok());
    }

    #[test]
    fn validate_credential_content_rejects_invalid_json() {
        let raw = r#"{"type":"codex","access_token":"a""#;
        assert!(validate_credential_content(raw).is_err());
    }

    #[test]
    fn validate_credential_content_rejects_non_codex_json() {
        let raw = r#"{"type":"other","access_token":"a","refresh_token":"b"}"#;
        assert!(validate_credential_content(raw).is_err());
    }

    #[test]
    fn clear_cpa_exhausted_statuses_only_clears_exhausted_normal_credentials() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.credentials_dir = temp.path().join("credentials");
        config.abnormal_credentials_dir = temp.path().join("credentials_abnormal");
        let store = CredentialStore::new(&config, None).unwrap();
        let status_store = CredentialStatusStore::load(temp.path().join("status.json")).unwrap();
        let credential = CodexCredentialFile {
            provider_type: "codex".to_string(),
            refresh_token: "refresh".to_string(),
            ..CodexCredentialFile::default()
        };
        store
            .write_credential(CredentialZone::Normal, "exhausted.json", &credential)
            .unwrap();
        store
            .write_credential(CredentialZone::Normal, "normal.json", &credential)
            .unwrap();
        store
            .write_credential(CredentialZone::Abnormal, "abnormal.json", &credential)
            .unwrap();
        status_store
            .set_cpa_exhausted("exhausted.json", Some("2030-01-01T00:00:00Z".to_string()))
            .unwrap();
        status_store
            .set_cpa_exhausted("abnormal.json", Some("2030-01-01T00:00:00Z".to_string()))
            .unwrap();

        let summary = clear_cpa_exhausted_statuses(
            &store,
            &status_store,
            &[
                "exhausted.json".to_string(),
                "exhausted.json".to_string(),
                "normal.json".to_string(),
                "missing.json".to_string(),
                "abnormal.json".to_string(),
                "".to_string(),
            ],
        )
        .unwrap();

        assert_eq!(summary.selected, 4);
        assert_eq!(summary.cleared, 1);
        assert_eq!(summary.skipped, 3);
        assert_eq!(
            status_store
                .get("exhausted.json")
                .unwrap()
                .and_then(|record| record.cpa_exhausted),
            None
        );
        assert_eq!(
            status_store
                .get("abnormal.json")
                .unwrap()
                .and_then(|record| record.cpa_exhausted),
            Some(true)
        );
    }

    #[test]
    fn clamp_log_line_limit_uses_default_when_missing() {
        assert_eq!(clamp_log_line_limit(None), 50);
    }

    #[test]
    fn clamp_log_line_limit_caps_large_values() {
        assert_eq!(clamp_log_line_limit(Some(120)), 50);
    }

    #[test]
    fn clamp_log_line_limit_keeps_small_values() {
        assert_eq!(clamp_log_line_limit(Some(12)), 12);
    }
}

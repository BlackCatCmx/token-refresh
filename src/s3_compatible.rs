use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use s3::Bucket;
use s3::creds::Credentials;
use s3::error::S3Error;
use s3::region::Region;
use s3::request::ResponseData;
use tokio::io::AsyncRead;

use crate::config::BackupRemoteConfig;

#[derive(Clone)]
pub struct S3CompatibleClient {
    bucket: Box<Bucket>,
    object_prefix: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct RemoteSnapshot {
    pub key: String,
    pub size: u64,
    pub last_modified: Option<String>,
    pub created_at: Option<String>,
    pub trigger: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_name: Option<String>,
    #[serde(default)]
    pub is_current_latest: bool,
}

impl S3CompatibleClient {
    pub fn new(config: &BackupRemoteConfig) -> Result<Self> {
        let credentials = Credentials::new(
            Some(config.access_key_id.trim()),
            Some(config.secret_access_key.trim()),
            None,
            None,
            None,
        )
        .context("failed to build S3 credentials")?;
        let region = Region::Custom {
            region: resolve_region(config.region.trim(), config.endpoint.trim()),
            endpoint: config.endpoint.trim().trim_end_matches('/').to_string(),
        };
        let bucket = Bucket::new(config.bucket.trim(), region, credentials)
            .context("failed to initialize S3 bucket client")?;
        let bucket = if config.path_style {
            bucket.with_path_style()
        } else {
            bucket
        };
        Ok(Self {
            bucket,
            object_prefix: normalize_prefix(config.object_prefix.trim()),
        })
    }

    pub async fn put_object_stream<R: AsyncRead + Unpin + ?Sized>(
        &self,
        key: &str,
        reader: &mut R,
    ) -> Result<()> {
        let object_path = object_path(key);
        let response = self
            .bucket
            .put_object_stream(reader, object_path)
            .await
            .map_err(|err| describe_s3_error("上传备份", err))?;
        ensure_status(response.status_code(), &[200, 201], "上传备份")?;
        Ok(())
    }

    pub async fn get_object(&self, key: &str) -> Result<Vec<u8>> {
        let response = self
            .bucket
            .get_object(object_path(key))
            .await
            .map_err(|err| describe_s3_error("下载备份", err))
            .with_context(|| format!("failed to download backup object {key}"))?;
        ensure_response_status(&response, &[200], "下载备份")?;
        Ok(response.bytes().to_vec())
    }

    pub async fn delete_object(&self, key: &str) -> Result<()> {
        let response = self
            .bucket
            .delete_object(object_path(key))
            .await
            .map_err(|err| describe_s3_error("删除旧备份", err))
            .with_context(|| format!("failed to delete backup object {key}"))?;
        ensure_response_status(&response, &[200, 204, 404], "删除旧备份")?;
        Ok(())
    }

    pub async fn list_snapshots(&self) -> Result<Vec<RemoteSnapshot>> {
        let prefix = self.snapshot_root_prefix();
        let results = self
            .bucket
            .list(prefix.clone(), None)
            .await
            .map_err(|err| describe_s3_error("列出备份", err))
            .context("failed to list backup snapshots")?;
        let mut snapshots = Vec::new();
        for page in results {
            for object in page.contents {
                if !object.key.ends_with(".zip") {
                    continue;
                }
                let (created_at, trigger) = parse_snapshot_name(&object.key);
                snapshots.push(RemoteSnapshot {
                    key: object.key.clone(),
                    size: object.size,
                    last_modified: normalize_timestamp(&object.last_modified),
                    created_at,
                    trigger,
                    remote_name: None,
                    is_current_latest: false,
                });
            }
        }
        snapshots.sort_by(|left, right| right.key.cmp(&left.key));
        Ok(snapshots)
    }

    pub fn snapshot_root_prefix(&self) -> String {
        if self.object_prefix.is_empty() {
            "snapshots/".to_string()
        } else {
            format!("{}/snapshots/", self.object_prefix)
        }
    }
}

pub fn resolve_region(region: &str, endpoint: &str) -> String {
    let region = region.trim();
    if !region.is_empty() {
        return region.to_string();
    }
    infer_region_from_endpoint(endpoint).unwrap_or_else(|| "us-east-1".to_string())
}

pub fn parse_snapshot_name_for_display(key: &str) -> (Option<String>, String) {
    parse_snapshot_name(key)
}

fn normalize_prefix(prefix: &str) -> String {
    prefix.trim_matches('/').to_string()
}

fn infer_region_from_endpoint(endpoint: &str) -> Option<String> {
    let host = reqwest::Url::parse(endpoint)
        .ok()?
        .host_str()?
        .to_ascii_lowercase();
    for label in host.split('.') {
        if looks_like_region(label) {
            return Some(label.to_string());
        }
    }
    None
}

fn looks_like_region(label: &str) -> bool {
    let mut parts = label.split('-');
    let Some(first) = parts.next() else {
        return false;
    };
    let Some(second) = parts.next() else {
        return false;
    };
    let Some(last) = parts.next_back().or(Some(second)) else {
        return false;
    };
    if first.is_empty() || last.is_empty() {
        return false;
    }
    if !first.chars().all(|ch| ch.is_ascii_lowercase()) {
        return false;
    }
    if !label
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        return false;
    }
    label.contains('-') && last.chars().all(|ch| ch.is_ascii_digit())
}

fn object_path(key: &str) -> String {
    format!("/{}", key.trim_start_matches('/'))
}

fn ensure_status(status: u16, expected: &[u16], action: &str) -> Result<()> {
    if expected.contains(&status) {
        Ok(())
    } else {
        bail!("{action}失败，远端返回 HTTP {status}")
    }
}

fn ensure_response_status(response: &ResponseData, expected: &[u16], action: &str) -> Result<()> {
    let status = response.status_code();
    if expected.contains(&status) {
        return Ok(());
    }
    bail!(
        "{}",
        describe_http_failure(
            action,
            status,
            Some(response.as_slice()),
            Some(&response.headers())
        )
    )
}

fn describe_s3_error(action: &str, err: S3Error) -> anyhow::Error {
    match err {
        S3Error::HttpFailWithBody(status, body) => {
            anyhow::anyhow!(
                "{}",
                describe_http_failure(action, status, Some(body.as_bytes()), None)
            )
        }
        other => anyhow::anyhow!("{action}失败：{other}"),
    }
}

fn describe_http_failure(
    action: &str,
    status: u16,
    body: Option<&[u8]>,
    headers: Option<&std::collections::HashMap<String, String>>,
) -> String {
    let body_text = body
        .and_then(|value| std::str::from_utf8(value).ok())
        .unwrap_or_default();
    let aws_code = extract_xml_tag(body_text, "Code");
    let aws_message = extract_xml_tag(body_text, "Message");
    let request_id = extract_xml_tag(body_text, "RequestId").or_else(|| {
        headers.and_then(|values| get_header_case_insensitive(values, "x-amz-request-id"))
    });
    let host_id = extract_xml_tag(body_text, "HostId")
        .or_else(|| headers.and_then(|values| get_header_case_insensitive(values, "x-amz-id-2")));
    let body_preview = compact_body_preview(body_text);
    let mut parts = vec![format!("{action}失败，远端返回 HTTP {status}")];
    if let Some(value) = aws_code {
        parts.push(format!("aws_code={value}"));
    }
    if let Some(value) = aws_message {
        parts.push(format!("aws_message={value}"));
    }
    if let Some(value) = request_id {
        parts.push(format!("request_id={value}"));
    }
    if let Some(value) = host_id {
        parts.push(format!("host_id={value}"));
    }
    if !body_preview.is_empty() {
        parts.push(format!("body={body_preview}"));
    }
    parts.join(" ")
}

fn extract_xml_tag(body: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&close)? + start;
    Some(body[start..end].trim().to_string()).filter(|value| !value.is_empty())
}

fn get_header_case_insensitive(
    headers: &std::collections::HashMap<String, String>,
    target: &str,
) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(target))
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn compact_body_preview(body: &str) -> String {
    let compact = body.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = compact.chars();
    let preview: String = chars.by_ref().take(240).collect();
    if chars.next().is_some() {
        format!("{preview}...")
    } else {
        preview
    }
}

fn normalize_timestamp(value: &str) -> Option<String> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc).to_rfc3339())
}

fn parse_snapshot_name(key: &str) -> (Option<String>, String) {
    let file_name = key.rsplit('/').next().unwrap_or(key);
    let Some(raw) = file_name.strip_prefix("snapshot-") else {
        return (None, "unknown".to_string());
    };
    let Some(raw) = raw.strip_suffix(".zip") else {
        return (None, "unknown".to_string());
    };
    let Some((timestamp, trigger)) = raw.rsplit_once('-') else {
        return (None, "unknown".to_string());
    };
    let created_at = if timestamp.ends_with('Z') {
        DateTime::parse_from_str(timestamp, "%Y%m%dT%H%M%SZ")
            .ok()
            .map(|value| value.with_timezone(&Utc).to_rfc3339())
    } else if let Ok(value) = NaiveDate::parse_from_str(timestamp, "%Y%m%d") {
        value
            .and_hms_opt(0, 0, 0)
            .map(|value| Utc.from_utc_datetime(&value).to_rfc3339())
    } else {
        None
    };
    (created_at, trigger.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_region_prefers_explicit_value() {
        assert_eq!(
            resolve_region("ap-southeast-1", "https://objectstorageapi.example.com"),
            "ap-southeast-1"
        );
    }

    #[test]
    fn resolve_region_infers_from_endpoint() {
        assert_eq!(
            resolve_region(
                "",
                "https://objectstorageapi.ap-southeast-1.clawcloudrun.com"
            ),
            "ap-southeast-1"
        );
    }

    #[test]
    fn resolve_region_falls_back_to_us_east_1() {
        assert_eq!(
            resolve_region("", "https://minio.internal.example.com"),
            "us-east-1"
        );
    }

    #[test]
    fn describe_http_failure_includes_xml_details() {
        let body = br#"<?xml version="1.0" encoding="UTF-8"?><Error><Code>XMinioStorageFull</Code><Message>Storage backend has reached its minimum free drive threshold.</Message><RequestId>abc123</RequestId><HostId>host456</HostId></Error>"#;

        let message = describe_http_failure("上传备份", 507, Some(body), None);

        assert!(message.contains("HTTP 507"));
        assert!(message.contains("aws_code=XMinioStorageFull"));
        assert!(message.contains("request_id=abc123"));
        assert!(message.contains("host_id=host456"));
    }

    #[test]
    fn parse_snapshot_name_supports_date_only_timestamp() {
        let (created_at, trigger) =
            parse_snapshot_name("snapshots/2026/04/11/snapshot-20260411-daily.zip");

        assert_eq!(trigger, "daily");
        assert_eq!(created_at.as_deref(), Some("2026-04-11T00:00:00+00:00"));
    }
}

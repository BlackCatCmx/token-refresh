use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use s3::Bucket;
use s3::creds::Credentials;
use s3::region::Region;

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

    pub async fn put_object(&self, key: &str, bytes: &[u8]) -> Result<()> {
        let object_path = object_path(key);
        let response = self
            .bucket
            .put_object(object_path, bytes)
            .await
            .context("failed to upload backup object")?;
        ensure_status(response.status_code(), &[200, 201], "上传备份")?;
        Ok(())
    }

    pub async fn get_object(&self, key: &str) -> Result<Vec<u8>> {
        let response = self
            .bucket
            .get_object(object_path(key))
            .await
            .with_context(|| format!("failed to download backup object {key}"))?;
        ensure_status(response.status_code(), &[200], "下载备份")?;
        Ok(response.bytes().to_vec())
    }

    pub async fn delete_object(&self, key: &str) -> Result<()> {
        let response = self
            .bucket
            .delete_object(object_path(key))
            .await
            .with_context(|| format!("failed to delete backup object {key}"))?;
        ensure_status(response.status_code(), &[200, 204, 404], "删除旧备份")?;
        Ok(())
    }

    pub async fn list_snapshots(&self) -> Result<Vec<RemoteSnapshot>> {
        let prefix = self.snapshot_root_prefix();
        let results = self
            .bucket
            .list(prefix.clone(), None)
            .await
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
                    size: object.size as u64,
                    last_modified: normalize_timestamp(&object.last_modified),
                    created_at,
                    trigger,
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
    } else if let Ok(value) = NaiveDateTime::parse_from_str(timestamp, "%Y%m%d") {
        Some(Utc.from_utc_datetime(&value).to_rfc3339())
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
}

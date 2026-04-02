use std::collections::BTreeMap;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::jwt;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct CodexCredentialFile {
    #[serde(default)]
    pub id_token: String,
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(rename = "type", default)]
    pub provider_type: String,
    #[serde(default)]
    pub last_refresh: Option<String>,
    #[serde(default)]
    pub expired: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

impl CodexCredentialFile {
    pub fn is_codex(&self) -> bool {
        self.provider_type.trim().eq_ignore_ascii_case("codex")
    }

    pub fn normalized_key(&self) -> String {
        self.email
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("unknown")
            .to_string()
    }

    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        if let Ok(exp) = jwt::decode_expiration(&self.access_token) {
            return Some(exp);
        }
        self.expired
            .as_deref()
            .and_then(parse_rfc3339)
            .or_else(|| jwt::decode_expiration(&self.id_token).ok())
    }

    pub fn due_at(&self, lead_time: std::time::Duration) -> Option<DateTime<Utc>> {
        let expires_at = self.expires_at()?;
        Some(expires_at - chrono::Duration::from_std(lead_time).ok()?)
    }

    pub fn set_last_refresh_now(&mut self) {
        self.last_refresh = Some(Utc::now().to_rfc3339());
    }

    pub fn set_expired_at(&mut self, value: DateTime<Utc>) {
        self.expired = Some(value.to_rfc3339());
    }

    pub fn apply_id_token_metadata(&mut self, token: &str) -> Result<()> {
        let metadata = jwt::decode_id_token_metadata(token)?;
        if let Some(email) = metadata.email {
            self.email = Some(email);
        }
        if let Some(account_id) = metadata.account_id {
            self.account_id = Some(account_id);
        }
        Ok(())
    }
}

pub fn parse_rfc3339(value: &str) -> Option<DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_unknown_fields() {
        let raw = serde_json::json!({
            "id_token": "id",
            "access_token": "access",
            "refresh_token": "refresh",
            "type": "codex",
            "email": "a@example.com",
            "custom_flag": true,
            "nested": { "x": 1 }
        });
        let credential: CodexCredentialFile = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(
            credential.extra.get("custom_flag"),
            Some(&serde_json::Value::Bool(true))
        );
        let written = serde_json::to_value(&credential).unwrap();
        assert_eq!(written.get("nested"), raw.get("nested"));
    }
}

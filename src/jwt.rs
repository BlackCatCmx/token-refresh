use anyhow::{Context, Result, bail};
use base64::Engine;
use chrono::{DateTime, TimeZone, Utc};
use serde::Deserialize;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdTokenMetadata {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default, rename = "https://api.openai.com/auth")]
    pub auth: OpenAiAuthClaims,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct OpenAiAuthClaims {
    #[serde(default)]
    pub chatgpt_account_id: Option<String>,
    #[serde(default)]
    pub chatgpt_plan_type: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
}

impl IdTokenMetadata {
    pub fn account_id(&self) -> Option<String> {
        self.auth.chatgpt_account_id.clone()
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct ExpClaims {
    exp: Option<i64>,
}

pub fn decode_expiration(token: &str) -> Result<DateTime<Utc>> {
    let claims: ExpClaims = decode_claims(token)?;
    let exp = claims.exp.context("JWT missing exp")?;
    Utc.timestamp_opt(exp, 0)
        .single()
        .context("invalid JWT exp timestamp")
}

pub fn decode_id_token_metadata(token: &str) -> Result<DecodedIdTokenMetadata> {
    let claims: IdTokenMetadata = decode_claims(token)?;
    let account_id = claims.account_id();
    let plan_type = claims.auth.chatgpt_plan_type.clone();
    let user_id = claims.auth.user_id.clone();
    Ok(DecodedIdTokenMetadata {
        email: claims.email,
        account_id,
        plan_type,
        user_id,
    })
}

#[derive(Clone, Debug, Default)]
pub struct DecodedIdTokenMetadata {
    pub email: Option<String>,
    pub account_id: Option<String>,
    pub plan_type: Option<String>,
    pub user_id: Option<String>,
}

fn decode_claims<T>(token: &str) -> Result<T>
where
    T: for<'de> serde::Deserialize<'de>,
{
    let payload = token
        .split('.')
        .nth(1)
        .context("invalid JWT format")?
        .trim();
    if payload.is_empty() {
        bail!("invalid JWT payload");
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload))
        .context("failed to decode JWT payload")?;
    serde_json::from_slice(&decoded).context("failed to parse JWT payload")
}

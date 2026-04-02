use anyhow::{Context, Result};
use http::HeaderValue;

pub const DEFAULT_ORIGINATOR: &str = "codex_cli_rs";

pub fn validate(value: &str) -> Result<()> {
    HeaderValue::from_str(value).context("invalid originator header value")?;
    Ok(())
}

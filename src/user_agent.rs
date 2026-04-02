use anyhow::{Context, Result};
use http::HeaderValue;

pub const DEFAULT_USER_AGENT: &str =
    "codex_cli_rs/0.118.0 (Windows 10.0.19045; x86_64) WindowsTerminal";

pub fn validate(value: &str) -> Result<()> {
    HeaderValue::from_str(value).context("invalid User-Agent header value")?;
    Ok(())
}

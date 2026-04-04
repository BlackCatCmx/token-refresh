use anyhow::{Context, Result, bail};
use http::HeaderValue;
use rand::Rng;
use serde::{Deserialize, Serialize};

pub const DEFAULT_USER_AGENT: &str =
    "codex_cli_rs/0.118.0 (Windows 10.0.19045; x86_64) WindowsTerminal";
pub const DEFAULT_USER_AGENT_MODE: &str = "list";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserAgentRulesConfig {
    #[serde(default = "default_generated_versions")]
    pub versions: String,
    #[serde(default = "default_generated_profiles")]
    pub profiles: String,
    #[serde(default = "default_generated_terminals")]
    pub terminals: String,
}

impl Default for UserAgentRulesConfig {
    fn default() -> Self {
        Self {
            versions: default_generated_versions(),
            profiles: default_generated_profiles(),
            terminals: default_generated_terminals(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UserAgentMode {
    List,
    Generated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct VersionNumber {
    major: u32,
    minor: u32,
    patch: u32,
}

#[derive(Clone, Copy, Debug)]
struct OsProfileSpec {
    aliases: &'static [&'static str],
    key: &'static str,
    os_type: &'static str,
    versions: &'static [&'static str],
    arches: &'static [&'static str],
    terminals: &'static [&'static str],
}

const TERMINAL_ALIASES: [(&str, &str); 14] = [
    ("windowsterminal", "WindowsTerminal"),
    ("windows terminal", "WindowsTerminal"),
    ("apple_terminal", "Apple_Terminal"),
    ("apple terminal", "Apple_Terminal"),
    ("iterm.app", "iTerm.app"),
    ("iterm2", "iTerm.app"),
    ("iterm", "iTerm.app"),
    ("vscode", "vscode"),
    ("wezterm", "WezTerm"),
    ("ghostty", "Ghostty"),
    ("warpterminal", "WarpTerminal"),
    ("warp", "WarpTerminal"),
    ("kitty", "kitty"),
    ("windows_terminal", "WindowsTerminal"),
];

const PROFILE_SPECS: [OsProfileSpec; 5] = [
    OsProfileSpec {
        aliases: &["windows10", "win10"],
        key: "windows10",
        os_type: "Windows",
        versions: &["10.0.19044", "10.0.19045"],
        arches: &["x86_64"],
        terminals: &[
            "WindowsTerminal",
            "vscode",
            "WezTerm",
            "Ghostty",
            "WarpTerminal",
            "kitty",
        ],
    },
    OsProfileSpec {
        aliases: &["windows11", "win11"],
        key: "windows11",
        os_type: "Windows",
        versions: &["10.0.22631", "10.0.26100", "10.0.28000"],
        arches: &["x86_64"],
        terminals: &[
            "WindowsTerminal",
            "vscode",
            "WezTerm",
            "Ghostty",
            "WarpTerminal",
            "kitty",
        ],
    },
    OsProfileSpec {
        aliases: &["macos", "mac"],
        key: "macos",
        os_type: "macOS",
        versions: &["14.7", "15.7", "26.4"],
        arches: &["aarch64", "x86_64"],
        terminals: &[
            "Apple_Terminal",
            "iTerm.app",
            "vscode",
            "WezTerm",
            "Ghostty",
            "WarpTerminal",
            "kitty",
        ],
    },
    OsProfileSpec {
        aliases: &["ubuntu"],
        key: "ubuntu",
        os_type: "Ubuntu",
        versions: &["24.04", "24.10", "25.10"],
        arches: &["x86_64", "aarch64"],
        terminals: &["vscode", "WezTerm", "Ghostty", "WarpTerminal", "kitty"],
    },
    OsProfileSpec {
        aliases: &["debian"],
        key: "debian",
        os_type: "Debian",
        versions: &["12.11", "13.4"],
        arches: &["x86_64", "aarch64"],
        terminals: &["vscode", "WezTerm", "Ghostty", "WarpTerminal", "kitty"],
    },
];

pub fn validate(value: &str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("User-Agent cannot be empty");
    }
    HeaderValue::from_str(trimmed).context("invalid User-Agent header value")?;
    Ok(())
}

pub fn parse_list(value: &str) -> Result<Vec<String>> {
    let mut items = Vec::new();
    for line in value.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        validate(trimmed)?;
        items.push(trimmed.to_string());
    }
    Ok(items)
}

pub fn normalize_optional(value: Option<&str>) -> Result<Option<String>> {
    let Some(trimmed) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    validate(trimmed)?;
    Ok(Some(trimmed.to_string()))
}

pub fn validate_settings(
    originator: &str,
    mode: &str,
    list: &str,
    rules: &UserAgentRulesConfig,
) -> Result<()> {
    match parse_mode(mode)? {
        UserAgentMode::List => {
            parse_list(list)?;
            Ok(())
        }
        UserAgentMode::Generated => {
            let candidates = generate_candidates(originator.trim(), rules)?;
            if candidates.is_empty() {
                bail!("generated User-Agent rules did not produce any candidates");
            }
            Ok(())
        }
    }
}

pub fn assign(
    originator: &str,
    mode: &str,
    list: &str,
    rules: &UserAgentRulesConfig,
) -> Result<String> {
    match parse_mode(mode)? {
        UserAgentMode::List => assign_from_list_or_default(list),
        UserAgentMode::Generated => pick_generated_candidate(originator.trim(), rules, true),
    }
}

pub fn reassign_cli_version(
    existing_user_agent: &str,
    originator: &str,
    rules: &UserAgentRulesConfig,
) -> Result<Option<String>> {
    let existing_user_agent = existing_user_agent.trim();
    if existing_user_agent.is_empty() {
        return Ok(None);
    }
    let originator = originator.trim();
    if originator.is_empty() {
        bail!("User-Agent originator cannot be empty");
    }
    let prefix = format!("{originator}/");
    let Some(remainder) = existing_user_agent.strip_prefix(&prefix) else {
        return Ok(None);
    };
    let Some((current_version, suffix)) = remainder.split_once(' ') else {
        return Ok(None);
    };
    if parse_version_number(current_version).is_err() {
        return Ok(None);
    }
    let next_version = pick_rule_version(&rules.versions, true)?;
    Ok(Some(format!("{originator}/{next_version} {suffix}")))
}

pub fn preview_value(
    originator: &str,
    mode: &str,
    list: &str,
    rules: &UserAgentRulesConfig,
) -> String {
    preview_value_result(originator, mode, list, rules)
        .unwrap_or_else(|_| DEFAULT_USER_AGENT.to_string())
}

pub fn random_preview_value(
    originator: &str,
    mode: &str,
    list: &str,
    rules: &UserAgentRulesConfig,
) -> Result<String> {
    assign(originator, mode, list, rules)
}

fn preview_value_result(
    originator: &str,
    mode: &str,
    list: &str,
    rules: &UserAgentRulesConfig,
) -> Result<String> {
    match parse_mode(mode)? {
        UserAgentMode::List => Ok(parse_list(list)?
            .into_iter()
            .next()
            .unwrap_or_else(|| DEFAULT_USER_AGENT.to_string())),
        UserAgentMode::Generated => pick_generated_candidate(originator.trim(), rules, false),
    }
}

fn assign_from_list_or_default(value: &str) -> Result<String> {
    let items = parse_list(value)?;
    if items.is_empty() {
        return Ok(DEFAULT_USER_AGENT.to_string());
    }
    if items.len() == 1 {
        return Ok(items[0].clone());
    }
    let index = rand::rng().random_range(0..items.len());
    Ok(items[index].clone())
}

fn pick_generated_candidate(
    originator: &str,
    rules: &UserAgentRulesConfig,
    randomize: bool,
) -> Result<String> {
    let candidates = generate_candidates(originator, rules)?;
    if candidates.is_empty() {
        bail!("generated User-Agent rules did not produce any candidates");
    }
    if !randomize || candidates.len() == 1 {
        return Ok(candidates[0].clone());
    }
    let index = rand::rng().random_range(0..candidates.len());
    Ok(candidates[index].clone())
}

fn pick_rule_version(value: &str, randomize: bool) -> Result<String> {
    let versions = parse_version_tokens(value)?;
    if versions.is_empty() {
        bail!("User-Agent generated versions cannot be empty");
    }
    if !randomize || versions.len() == 1 {
        return Ok(versions[0].clone());
    }
    let index = rand::rng().random_range(0..versions.len());
    Ok(versions[index].clone())
}

fn generate_candidates(originator: &str, rules: &UserAgentRulesConfig) -> Result<Vec<String>> {
    let versions = parse_version_tokens(&rules.versions)?;
    if versions.is_empty() {
        bail!("User-Agent generated versions cannot be empty");
    }
    let profiles = parse_profiles(&rules.profiles)?;
    if profiles.is_empty() {
        bail!("User-Agent generated profiles cannot be empty");
    }
    let terminals = parse_terminals(&rules.terminals)?;
    if terminals.is_empty() {
        bail!("User-Agent generated terminals cannot be empty");
    }

    let mut candidates = Vec::new();
    for version in &versions {
        for profile in &profiles {
            for os_version in profile.versions {
                for arch in profile.arches {
                    for terminal in &terminals {
                        if profile.terminals.contains(terminal) {
                            let value = format!(
                                "{originator}/{version} ({} {}; {}) {terminal}",
                                profile.os_type, os_version, arch
                            );
                            validate(&value)?;
                            candidates.push(value);
                        }
                    }
                }
            }
        }
    }
    Ok(candidates)
}

fn parse_mode(value: &str) -> Result<UserAgentMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "list" => Ok(UserAgentMode::List),
        "generated" => Ok(UserAgentMode::Generated),
        other => bail!("invalid request_identity.user_agent_mode: {other}"),
    }
}

fn parse_version_tokens(value: &str) -> Result<Vec<String>> {
    let mut versions = Vec::new();
    for token in split_rule_lines(value) {
        if let Some((start, end)) = token.split_once(" - ") {
            versions.extend(expand_version_range(start.trim(), end.trim())?);
            continue;
        }
        let version = parse_version_number(token)?;
        versions.push(version.to_string());
    }
    Ok(dedup_preserving_order(versions))
}

fn expand_version_range(start: &str, end: &str) -> Result<Vec<String>> {
    let start = parse_version_number(start)?;
    let end = parse_version_number(end)?;
    if start > end {
        bail!("invalid User-Agent version range: {start} - {end}");
    }
    if start.major != end.major {
        bail!("User-Agent version range must stay within one major version");
    }
    if start.minor == end.minor {
        let mut items = Vec::new();
        for patch in start.patch..=end.patch {
            items.push(
                VersionNumber {
                    major: start.major,
                    minor: start.minor,
                    patch,
                }
                .to_string(),
            );
        }
        return Ok(items);
    }
    if start.patch != 0 || end.patch != 0 {
        bail!("cross-minor User-Agent version range must use .0 patch values");
    }
    let mut items = Vec::new();
    for minor in start.minor..=end.minor {
        items.push(
            VersionNumber {
                major: start.major,
                minor,
                patch: 0,
            }
            .to_string(),
        );
    }
    Ok(items)
}

fn parse_version_number(value: &str) -> Result<VersionNumber> {
    let trimmed = value.trim();
    let mut parts = trimmed.split('.');
    let major = parts
        .next()
        .context("missing User-Agent version major number")?
        .parse::<u32>()
        .with_context(|| format!("invalid User-Agent version: {trimmed}"))?;
    let minor = parts
        .next()
        .context("missing User-Agent version minor number")?
        .parse::<u32>()
        .with_context(|| format!("invalid User-Agent version: {trimmed}"))?;
    let patch = parts
        .next()
        .context("missing User-Agent version patch number")?
        .parse::<u32>()
        .with_context(|| format!("invalid User-Agent version: {trimmed}"))?;
    if parts.next().is_some() {
        bail!("invalid User-Agent version: {trimmed}");
    }
    Ok(VersionNumber {
        major,
        minor,
        patch,
    })
}

fn parse_profiles(value: &str) -> Result<Vec<&'static OsProfileSpec>> {
    let mut items: Vec<&'static OsProfileSpec> = Vec::new();
    for token in split_rule_lines(value) {
        let normalized = token.to_ascii_lowercase();
        let Some(profile) = PROFILE_SPECS.iter().find(|profile| {
            profile
                .aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(&normalized))
        }) else {
            bail!("unsupported User-Agent profile: {token}");
        };
        if !items.iter().any(|existing| existing.key == profile.key) {
            items.push(profile);
        }
    }
    Ok(items)
}

fn parse_terminals(value: &str) -> Result<Vec<&'static str>> {
    let mut items = Vec::new();
    for token in split_rule_lines(value) {
        let normalized = token.trim().to_ascii_lowercase();
        let Some((_, terminal)) = TERMINAL_ALIASES
            .iter()
            .find(|(alias, _)| alias.eq_ignore_ascii_case(&normalized))
        else {
            bail!("unsupported User-Agent terminal: {token}");
        };
        if !items.contains(terminal) {
            items.push(*terminal);
        }
    }
    Ok(items)
}

fn split_rule_lines(value: &str) -> Vec<&str> {
    value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
}

fn dedup_preserving_order(values: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for value in values {
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    unique
}

fn default_generated_versions() -> String {
    "0.114.0 - 0.118.0".to_string()
}

fn default_generated_profiles() -> String {
    "windows10\nwindows11\nmacos\nubuntu\ndebian".to_string()
}

fn default_generated_terminals() -> String {
    "WindowsTerminal\nApple_Terminal\niTerm.app\nvscode\nWezTerm\nGhostty\nWarpTerminal\nkitty"
        .to_string()
}

impl std::fmt::Display for VersionNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multiline_list() {
        let items = parse_list("ua-1\n\n  ua-2  \r\nua-3").unwrap();
        assert_eq!(items, vec!["ua-1", "ua-2", "ua-3"]);
    }

    #[test]
    fn list_mode_falls_back_to_default_when_empty() {
        let assigned = assign(
            "codex_cli_rs",
            "list",
            " \r\n ",
            &UserAgentRulesConfig::default(),
        )
        .unwrap();
        assert_eq!(assigned, DEFAULT_USER_AGENT);
    }

    #[test]
    fn expands_minor_version_range() {
        let versions = parse_version_tokens("0.114.0 - 0.118.0").unwrap();
        assert_eq!(
            versions,
            vec!["0.114.0", "0.115.0", "0.116.0", "0.117.0", "0.118.0"]
        );
    }

    #[test]
    fn generated_preview_uses_first_valid_combination() {
        let rules = UserAgentRulesConfig {
            versions: "0.117.0\n0.118.0".to_string(),
            profiles: "windows11\nmacos".to_string(),
            terminals: "Apple_Terminal\nWindowsTerminal\nvscode".to_string(),
        };
        let preview = preview_value("codex_cli_rs", "generated", "", &rules);
        assert_eq!(
            preview,
            "codex_cli_rs/0.117.0 (Windows 10.0.22631; x86_64) WindowsTerminal"
        );
    }

    #[test]
    fn generated_mode_rejects_incompatible_matrix() {
        let rules = UserAgentRulesConfig {
            versions: "0.118.0".to_string(),
            profiles: "windows10".to_string(),
            terminals: "Apple_Terminal".to_string(),
        };
        let err = validate_settings("codex_cli_rs", "generated", "", &rules).unwrap_err();
        assert!(err.to_string().contains("did not produce any candidates"));
    }

    #[test]
    fn generated_mode_accepts_aliases() {
        let rules = UserAgentRulesConfig {
            versions: "0.118.0".to_string(),
            profiles: "win11\nmac".to_string(),
            terminals: "windows terminal\nwarp".to_string(),
        };
        validate_settings("codex_cli_rs", "generated", "", &rules).unwrap();
    }

    #[test]
    fn reassign_cli_version_only_replaces_version_segment() {
        let rules = UserAgentRulesConfig {
            versions: "9.9.9".to_string(),
            ..UserAgentRulesConfig::default()
        };
        let updated = reassign_cli_version(
            "codex_cli_rs/0.118.0 (Windows 10.0.19045; x86_64) WezTerm",
            "codex_cli_rs",
            &rules,
        )
        .unwrap();
        assert_eq!(
            updated.as_deref(),
            Some("codex_cli_rs/9.9.9 (Windows 10.0.19045; x86_64) WezTerm")
        );
    }

    #[test]
    fn reassign_cli_version_skips_non_matching_originator() {
        let rules = UserAgentRulesConfig {
            versions: "9.9.9".to_string(),
            ..UserAgentRulesConfig::default()
        };
        let updated = reassign_cli_version(
            "custom_cli/0.118.0 (Windows 10.0.19045; x86_64) WezTerm",
            "codex_cli_rs",
            &rules,
        )
        .unwrap();
        assert_eq!(updated, None);
    }

    #[test]
    fn reassign_cli_version_skips_invalid_version_segment() {
        let rules = UserAgentRulesConfig {
            versions: "9.9.9".to_string(),
            ..UserAgentRulesConfig::default()
        };
        let updated = reassign_cli_version(
            "codex_cli_rs/not-a-version (Windows 10.0.19045; x86_64) WezTerm",
            "codex_cli_rs",
            &rules,
        )
        .unwrap();
        assert_eq!(updated, None);
    }
}

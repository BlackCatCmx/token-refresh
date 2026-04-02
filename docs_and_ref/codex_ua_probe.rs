use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

const DEFAULT_ORIGINATOR: &str = "codex_cli_rs";

fn main() {
    let cargo_toml_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/Cargo.toml".to_string());

    let version = read_workspace_version(Path::new(&cargo_toml_path))
        .unwrap_or_else(|err| format!("error:{err}"));
    let originator = DEFAULT_ORIGINATOR.to_string();
    let os_type = "Windows".to_string();
    let os_version = detect_windows_version().unwrap_or_else(|| "unknown".to_string());
    let arch = detect_architecture();
    let terminal_token = detect_terminal_token();
    let user_agent = sanitize_user_agent(format!(
        "{originator}/{version} ({os_type} {os_version}; {arch}) {terminal_token}"
    ));

    println!("originator={originator}");
    println!("version={version}");
    println!("os_type={os_type}");
    println!("os_version={os_version}");
    println!("arch={arch}");
    println!("terminal_token={terminal_token}");
    println!("user_agent={user_agent}");
}

fn read_workspace_version(path: &Path) -> Result<String, String> {
    let content = fs::read_to_string(path).map_err(|err| err.to_string())?;
    let mut in_workspace_package = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_workspace_package = trimmed == "[workspace.package]";
            continue;
        }
        if in_workspace_package && trimmed.starts_with("version") {
            let (_, raw_value) = trimmed
                .split_once('=')
                .ok_or_else(|| "invalid version line".to_string())?;
            let value = raw_value.trim().trim_matches('"');
            if !value.is_empty() {
                return Ok(value.to_string());
            }
        }
    }

    Err("workspace.package.version not found".to_string())
}

fn detect_windows_version() -> Option<String> {
    let output = Command::new("pwsh")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "(Get-CimInstance Win32_OperatingSystem).Version",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let version = String::from_utf8(output.stdout).ok()?;
    let version = version.trim();
    (!version.is_empty()).then(|| version.to_string())
}

fn detect_architecture() -> String {
    match env::var("PROCESSOR_ARCHITECTURE")
        .unwrap_or_else(|_| env::consts::ARCH.to_string())
        .to_ascii_uppercase()
        .as_str()
    {
        "AMD64" | "X86_64" => "x86_64".to_string(),
        "ARM64" | "AARCH64" => "aarch64".to_string(),
        "ARM" => "arm".to_string(),
        "IA64" => "ia64".to_string(),
        "X86" | "I386" => "i386".to_string(),
        other => other.to_ascii_lowercase(),
    }
}

fn detect_terminal_token() -> String {
    let multiplexer = detect_multiplexer();

    if let Some(term_program) = var_non_empty("TERM_PROGRAM") {
        if term_program.eq_ignore_ascii_case("tmux")
            && matches!(multiplexer.as_deref(), Some("tmux"))
            && let Some(token) = terminal_from_tmux_client_info()
        {
            return token;
        }

        let version = var_non_empty("TERM_PROGRAM_VERSION");
        return sanitize_header_value(match version {
            Some(version) => format!("{term_program}/{version}"),
            None => term_program,
        });
    }

    if let Some(version) = var_non_empty("WEZTERM_VERSION") {
        return sanitize_header_value(format!("WezTerm/{version}"));
    }

    if has_any(&["ITERM_SESSION_ID", "ITERM_PROFILE", "ITERM_PROFILE_NAME"]) {
        return "iTerm.app".to_string();
    }

    if var_non_empty("TERM_SESSION_ID").is_some() {
        return "Apple_Terminal".to_string();
    }

    if var_non_empty("KITTY_WINDOW_ID").is_some() || term_contains("kitty") {
        return "kitty".to_string();
    }

    if var_non_empty("ALACRITTY_SOCKET").is_some() || var_non_empty("TERM").as_deref() == Some("alacritty") {
        return "Alacritty".to_string();
    }

    if let Some(version) = var_non_empty("KONSOLE_VERSION") {
        return sanitize_header_value(format!("Konsole/{version}"));
    }

    if var_non_empty("GNOME_TERMINAL_SCREEN").is_some() {
        return "gnome-terminal".to_string();
    }

    if let Some(version) = var_non_empty("VTE_VERSION") {
        return sanitize_header_value(format!("VTE/{version}"));
    }

    if var_non_empty("WT_SESSION").is_some() {
        return "WindowsTerminal".to_string();
    }

    if let Some(term) = var_non_empty("TERM") {
        return sanitize_header_value(term);
    }

    "unknown".to_string()
}

fn detect_multiplexer() -> Option<String> {
    if has_any(&["TMUX", "TMUX_PANE"]) {
        return Some("tmux".to_string());
    }

    if has_any(&["ZELLIJ", "ZELLIJ_SESSION_NAME", "ZELLIJ_VERSION"]) {
        return Some("zellij".to_string());
    }

    None
}

fn terminal_from_tmux_client_info() -> Option<String> {
    let termtype = tmux_display_message("#{client_termtype}");
    let termname = tmux_display_message("#{client_termname}");

    if let Some(termtype) = termtype {
        let mut parts = termtype.split_whitespace();
        let program = parts.next().unwrap_or_default().to_string();
        let version = parts.next().map(ToString::to_string);
        let token = match version {
            Some(version) if !version.is_empty() => format!("{program}/{version}"),
            _ => program,
        };
        return Some(sanitize_header_value(token));
    }

    termname.map(sanitize_header_value)
}

fn tmux_display_message(format: &str) -> Option<String> {
    let output = Command::new("tmux")
        .args(["display-message", "-p", format])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn has_any(names: &[&str]) -> bool {
    names.iter().any(|name| var_non_empty(name).is_some())
}

fn term_contains(fragment: &str) -> bool {
    var_non_empty("TERM")
        .map(|term| term.contains(fragment))
        .unwrap_or(false)
}

fn var_non_empty(name: &str) -> Option<String> {
    env::var(name).ok().map(|value| value.trim().to_string()).filter(|value| !value.is_empty())
}

fn sanitize_header_value(value: String) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn sanitize_user_agent(value: String) -> String {
    value
        .chars()
        .map(|ch| if (' '..='~').contains(&ch) { ch } else { '_' })
        .collect()
}

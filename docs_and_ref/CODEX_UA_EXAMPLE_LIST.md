# Codex 官方 UA 示例列表

更新时间：2026-04-04

## 1. 生成规则

Codex 官方 Rust 实现当前使用如下结构生成请求头里的 `User-Agent`：

```text
<originator>/<version> (<os_type> <os_version>; <arch>) <terminal_token>
```

基线取值：

- `originator`：`codex_cli_rs`
- `version`：`0.118.0`
- `os_type`：来自 `os_info`
- `terminal_token`：来自 `codex_terminal_detection`

示例：

```text
codex_cli_rs/0.118.0 (Windows 10.0.19045; x86_64) WindowsTerminal
```

## 2. 官方终端 Token 一览

| Terminal token | 说明 | 常见平台 |
| --- | --- | --- |
| `Apple_Terminal` | Apple Terminal.app | macOS |
| `Ghostty` | Ghostty | macOS / Linux / Windows |
| `iTerm.app` | iTerm2 | macOS |
| `WarpTerminal` | Warp | macOS / Linux / Windows |
| `vscode` | VS Code 集成终端 | macOS / Linux / Windows |
| `WezTerm` | WezTerm | macOS / Linux / Windows |
| `kitty` | kitty | macOS / Linux / Windows |
| `WindowsTerminal` | Windows Terminal | Windows |

补充规则：

- `TERM_PROGRAM_VERSION` 存在时，官方会输出 `Terminal/Version`，例如 `vscode/1.99.0`、`WezTerm/20240203-110809`。
- `tmux` 与 `zellij` 是复用器元数据，不是固定终端 token。
- `tmux` 下如果能拿到 client termtype，官方优先透出外层真实终端，而不是直接写成 `tmux`。
- `powershell` 与 `pwsh` 是 shell，不是 terminal token。
- 官方仍然支持若干回退值与偏底层类别，例如 `VTE`、`dumb`、`unknown`、原始 `TERM` 值，但本文档不再列为常用示例。

## 3. OS 版本基线

本表用于给示例 UA 选取不过时的版本基线。

| 平台 | UA 中的 `os_type` | 版本基线 | 说明 |
| --- | --- | --- | --- |
| macOS | `macOS` | `26.4` | Apple 当前最新主线版本 |
| Ubuntu | `Ubuntu` | `24.04` | 当前仍广泛使用的 LTS 基线 |
| Ubuntu | `Ubuntu` | `25.10` | 当前非 LTS 新版本 |
| Debian | `Debian` | `13.4` | 当前稳定版 `trixie` 点版本 |
| Windows 11 | `Windows` | `10.0.28000` | 对应 Windows 11 26H1 主构建号 |
| Windows 10 | `Windows` | `10.0.19045` | 对应 Windows 10 22H2 主构建号 |

说明：

- Windows 10 与 Windows 11 在官方 UA 里都写成 `Windows`，不是两个不同的 `os_type`。
- Win10 / Win11 的差异主要体现在版本号，例如 `10.0.19045` 与 `10.0.28000`。
- macOS 示例默认采用 `aarch64`，Linux / Windows 示例默认采用 `x86_64`。

## 4. UA 示例

### 4.1 macOS 26.4

```text
codex_cli_rs/0.118.0 (macOS 26.4; aarch64) Apple_Terminal
codex_cli_rs/0.118.0 (macOS 26.4; aarch64) iTerm.app
codex_cli_rs/0.118.0 (macOS 26.4; aarch64) Ghostty
codex_cli_rs/0.118.0 (macOS 26.4; aarch64) WarpTerminal
codex_cli_rs/0.118.0 (macOS 26.4; aarch64) vscode
codex_cli_rs/0.118.0 (macOS 26.4; aarch64) WezTerm
codex_cli_rs/0.118.0 (macOS 26.4; aarch64) kitty
```

### 4.2 Ubuntu 24.04

```text
codex_cli_rs/0.118.0 (Ubuntu 24.04; x86_64) vscode
codex_cli_rs/0.118.0 (Ubuntu 24.04; x86_64) WezTerm
codex_cli_rs/0.118.0 (Ubuntu 24.04; x86_64) Ghostty
codex_cli_rs/0.118.0 (Ubuntu 24.04; x86_64) WarpTerminal
codex_cli_rs/0.118.0 (Ubuntu 24.04; x86_64) kitty
```

### 4.3 Debian 13.4

```text
codex_cli_rs/0.118.0 (Debian 13.4; x86_64) vscode
codex_cli_rs/0.118.0 (Debian 13.4; x86_64) WezTerm
codex_cli_rs/0.118.0 (Debian 13.4; x86_64) Ghostty
codex_cli_rs/0.118.0 (Debian 13.4; x86_64) kitty
```

### 4.4 Windows 11 26H1

```text
codex_cli_rs/0.118.0 (Windows 10.0.28000; x86_64) WindowsTerminal
codex_cli_rs/0.118.0 (Windows 10.0.28000; x86_64) vscode
codex_cli_rs/0.118.0 (Windows 10.0.28000; x86_64) WezTerm
codex_cli_rs/0.118.0 (Windows 10.0.28000; x86_64) Ghostty
codex_cli_rs/0.118.0 (Windows 10.0.28000; x86_64) WarpTerminal
codex_cli_rs/0.118.0 (Windows 10.0.28000; x86_64) kitty
```

### 4.5 Windows 10 22H2

```text
codex_cli_rs/0.118.0 (Windows 10.0.19045; x86_64) WindowsTerminal
codex_cli_rs/0.118.0 (Windows 10.0.19045; x86_64) vscode
codex_cli_rs/0.118.0 (Windows 10.0.19045; x86_64) WezTerm
codex_cli_rs/0.118.0 (Windows 10.0.19045; x86_64) Ghostty
codex_cli_rs/0.118.0 (Windows 10.0.19045; x86_64) WarpTerminal
codex_cli_rs/0.118.0 (Windows 10.0.19045; x86_64) kitty
```

## 5. Shell 与 Terminal 的边界

以下名称不属于官方 terminal token：

- `powershell`
- `pwsh`
- `bash`
- `zsh`
- `sh`
- `cmd`

这些是 shell。官方 UA 里真正进入最后一段的是终端宿主或终端能力值。

典型结果：

```text
Windows Terminal + powershell  -> WindowsTerminal
Windows Terminal + pwsh        -> WindowsTerminal
VS Code + bash                -> vscode 或 vscode/<ver>
VS Code + pwsh                -> vscode 或 vscode/<ver>
tmux + WezTerm                -> WezTerm 或 WezTerm/<ver>
未识别终端但 TERM=xterm-256color -> xterm-256color
```

## 6. 依据

- Codex 官方 UA 拼装：`C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/login/src/auth/default_client.rs`
- Codex 官方终端探测：`C:/Users/Administrator/Desktop/github/cli/codex/codex-rs/terminal-detection/src/lib.rs`
- `os_info` 支持的 `os_type`：<https://docs.rs/os_info/latest/os_info/enum.Type.html>
- Apple 最新 macOS 版本表：<https://support.apple.com/en-us/109033>
- Ubuntu 官方发布周期：<https://ubuntu.com/about/release-cycle>
- Debian 13 `trixie` 发布信息：<https://www.debian.org/releases/trixie/>
- Windows 11 发布信息：<https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information>
- Windows 10 发布信息：<https://learn.microsoft.com/en-us/windows/release-health/release-information>

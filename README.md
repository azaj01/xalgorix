<div align="center">

<img src="assets/banner.png?v=4.4.9" alt="Xalgorix" width="860" />

<br />

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-10b981?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-111111?style=for-the-badge&logo=linux&logoColor=white)](#installation)

Autonomous web application security testing with a local Web UI, live agent telemetry, verified findings, and branded PDF reports.

</div>

---

## Overview

Xalgorix is a self-hosted AI security testing platform for authorized penetration testing and bug bounty workflows. It combines an LLM-driven agent, browser automation, terminal tooling, a 22-phase testing methodology, live WebSocket events, finding management, report generation, and integrations for AgentMail and Discord.

The default experience is the Web UI. You can start scans, monitor active runs, inspect findings, configure model/provider settings, manage environment variables, generate PDF reports with target branding, and delete or resume historical scans from one local dashboard.

Use Xalgorix only on systems you own or have explicit permission to test.

## Screenshots

### Overview Dashboard

![Xalgorix overview dashboard](assets/screenshot-1.png)

### Scan Detail

![Xalgorix scan detail](assets/screenshot-2.png)

### Findings

![Xalgorix findings](assets/screenshot-3.png)

## Features

- Local Web UI on `127.0.0.1:9137` by default.
- Single target, DAST, wildcard, and multi-target scan flows.
- 22-phase methodology with selectable phases per scan.
- Live feed for tool calls, agent messages, findings, errors, HTTP activity, and LLM activity.
- Scan detail pages with phase progress, risk overview, findings, events, and configuration.
- Findings index across recent scans with severity filters and CVSS details.
- Branded PDF reports with target/company name and uploaded logo.
- Report list with open, download, and delete actions.
- Bulk scan management with row selection, select all, action menu, and delete support.
- AgentMail integration for test inboxes, verification emails, OTP flows, and email triage events.
- Discord webhook notifications with configurable minimum severity.
- LLM settings in the dashboard, including model, API base, API key, retries, reasoning effort, and Gemini web-search key.
- Environment variable editor in Settings for LLM, AgentMail, Discord, proxy, runtime, browser, auth, rate limits, and resource settings.
- Resource-aware instance limits based on CPU, RAM, disk, and configured scan budget.
- Loopback-only binding by default, with authentication required before exposing externally.

## Installation

### Requirements

- Linux
- Go `1.24.2` or newer
- Node.js and npm for building the bundled React Web UI
- Common security tools are installed on demand when auto-install is enabled

Check your Go version:

```bash
go version
```

### Build From Source

```bash
git clone https://github.com/xalgord/xalgorix.git
cd xalgorix
make build
```

Install the built binary:

```bash
sudo install -m 755 build/xalgorix /usr/local/bin/xalgorix
```

The `make build` target builds the React Web UI into `internal/web/static` and then builds the Go binary.

### Install With Go

```bash
GOPROXY=direct GOSUMDB=off go install github.com/xalgord/xalgorix/v4/cmd/xalgorix@latest
```

## Configuration

Xalgorix loads configuration from:

1. `/etc/xalgorix.env`
2. `/home/<sudo-user>/.xalgorix.env` when launched through sudo
3. `~/.xalgorix.env`
4. Environment variables already present in the process

Create `~/.xalgorix.env`:

```bash
nano ~/.xalgorix.env
```

Minimal configuration:

```bash
XALGORIX_LLM=minimax/MiniMax-M2.7
XALGORIX_API_KEY=your_provider_api_key
```

OpenAI example:

```bash
XALGORIX_LLM=openai/gpt-5.4
XALGORIX_API_KEY=sk-...
```

Custom OpenAI-compatible provider:

```bash
XALGORIX_LLM=custom/security-model
XALGORIX_API_BASE=https://your-provider.example/v1
XALGORIX_API_KEY=your_provider_api_key
```

Optional integrations:

```bash
GEMINI_API_KEY=AIza...
AGENTMAIL_POD=am_us_pod_47
AGENTMAIL_API_KEY=ak_...
XALGORIX_DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
XALGORIX_DISCORD_MIN_SEVERITY=high
```

Dashboard authentication:

```bash
XALGORIX_USERNAME=admin
XALGORIX_PASSWORD=change-this-password
```

Prefer `XALGORIX_PASSWORD_HASH` for production deployments.

## Running

Start the Web UI:

```bash
xalgorix --web
```

Open:

```text
http://127.0.0.1:9137
```

Use a different port:

```bash
xalgorix --web --port 8080
```

Bind to a different interface:

```bash
XALGORIX_USERNAME=admin XALGORIX_PASSWORD=change-this xalgorix --web --bind 0.0.0.0
```

The server refuses external binding without dashboard authentication.

Run a CLI scan:

```bash
xalgorix --target https://example.com
```

Run with custom instructions:

```bash
xalgorix --target https://app.example.com --instruction "Focus on SQL injection, IDOR, and auth bypass. Avoid destructive tests."
```

## Service Mode

Install and start as a system service:

```bash
sudo xalgorix --start
```

Manage the service:

```bash
sudo xalgorix --restart
sudo xalgorix --stop
sudo xalgorix --uninstall
```

Expose the service to remote browsers only after enabling dashboard auth:

```bash
sudo tee -a /root/.xalgorix.env >/dev/null <<'EOF'
XALGORIX_BIND=0.0.0.0
XALGORIX_USERNAME=admin
XALGORIX_PASSWORD=change-this
EOF
sudo xalgorix --restart
```

Then open `http://<server-ip>:9137`. If the process is listening but the page still does not load remotely, allow TCP port `9137` in the server firewall or cloud security group.

View logs:

```bash
journalctl -u xalgorix -f
```

## Web UI Workflow

1. Open the dashboard at `http://127.0.0.1:9137`.
2. Go to Settings and confirm the LLM provider, API key, rate limits, and optional integrations.
3. Create a scan from New Scan.
4. Choose scan mode:
   - `Single target`: test one URL or host.
   - `Wildcard / multi`: enumerate subdomains and scan each target.
   - `DAST`: browser-driven application testing.
5. Select methodology phases when you want a focused run.
6. Set severity filters when you only want certain severities reported.
7. Add company name and upload a logo if you need branded reports.
8. Monitor live progress from Overview, Scan Detail, or Live Feed.
9. Open finding details, download the report, or manage historical scans from Scans and Reports.

## Scan Modes

| Mode | Purpose |
| --- | --- |
| Single target | Test the exact target you provide. Best for a known URL or host. |
| Wildcard / multi | Enumerate related targets and run scans across the discovered attack surface. |
| DAST | Browser-assisted testing for web applications, auth flows, forms, and runtime behavior. |

## Methodology

Xalgorix organizes autonomous testing into 22 phases:

1. Reconnaissance
2. Manual vulnerability discovery
3. Directory and file discovery
4. CORS and cookie analysis
5. Authentication and session testing
6. Injection testing
7. SSRF testing
8. IDOR and broken access control
9. API and GraphQL testing
10. File upload testing
11. Deserialization and RCE
12. Race conditions and business logic
13. Subdomain takeover
14. Open redirect testing
15. Email security testing
16. Cloud and infrastructure
17. WebSocket testing
18. CMS-specific testing
19. Broken link hijacking and content spoofing
20. Exploit verification
21. Zero-day discovery
22. Final report

Phase selection in the Web UI lets you run all phases or only the subset needed for a specific engagement.

## Reports

Reports are generated as PDF files and can include:

- Executive summary
- Target and scan metadata
- Severity and CVSS overview
- Verified findings
- Technical analysis
- Proof of concept commands or scripts
- Exploitation proof
- Remediation guidance
- Company/target branding and uploaded logo

Reports are available from the scan detail page and the Reports page. Report rows support opening, downloading, and deletion.

## Settings

Most operational settings can be changed from the Web UI under Settings.

| Area | Examples |
| --- | --- |
| Engagement | Dashboard request rate limits |
| LLM | Model, API key, API base, reasoning effort, retries, max iterations |
| AgentMail | Pod and API key |
| Notifications | Discord webhook and minimum severity |
| Proxy | Proxy URL, proxy file, rotation, TLS verification |
| Runtime | Workspace, browser path, auto-install controls |
| Security | Dashboard username, password, password hash, bind address |
| Resources | CPU/RAM/disk thresholds and scan concurrency budget |

Some settings require a restart because they affect process startup or server binding. The UI marks those fields.

## Environment Variables

Core variables:

| Variable | Default | Description |
| --- | --- | --- |
| `XALGORIX_LLM` | none | Required model name, usually with provider prefix. |
| `XALGORIX_API_KEY` | none | Required LLM provider API key. |
| `XALGORIX_API_BASE` | provider default | Custom OpenAI-compatible API base URL. |
| `XALGORIX_REASONING_EFFORT` | `high` | Reasoning effort: `low`, `medium`, `high`, or `xhigh`. |
| `XALGORIX_LLM_MAX_RETRIES` | `5` | Retry count for transient LLM failures. |
| `XALGORIX_MEMORY_COMPRESSOR_TIMEOUT` | `30` | Timeout in seconds for context compression. |
| `XALGORIX_MAX_ITERATIONS` | `0` | Agent iteration cap. `0` means unlimited. |
| `GEMINI_API_KEY` | none | Optional Gemini key for web-search enrichment. |

Web and security:

| Variable | Default | Description |
| --- | --- | --- |
| `XALGORIX_BIND` | `127.0.0.1` | Web server listen address. |
| `XALGORIX_USERNAME` | none | Dashboard username. |
| `XALGORIX_PASSWORD` | none | Dashboard password. |
| `XALGORIX_PASSWORD_HASH` | none | Preferred bcrypt password hash. |
| `XALGORIX_WORKSPACE` | current directory | Workspace root for scan execution. |

Integrations:

| Variable | Default | Description |
| --- | --- | --- |
| `AGENTMAIL_POD` | none | AgentMail pod identifier. |
| `AGENTMAIL_API_KEY` | none | AgentMail API key. |
| `XALGORIX_DISCORD_WEBHOOK` | none | Global Discord webhook. |
| `XALGORIX_DISCORD_MIN_SEVERITY` | none | Minimum severity sent to Discord. |
| `CAIDO_PORT` | `0` | Caido proxy port. `0` means auto-detect. |
| `CAIDO_API_TOKEN` | none | Caido API token. |

Rate limits, proxy, and runtime:

| Variable | Default | Description |
| --- | --- | --- |
| `XALGORIX_RATE_LIMIT_REQUESTS` | `60` | Dashboard requests per window. |
| `XALGORIX_RATE_LIMIT_WINDOW` | `60` | Dashboard rate-limit window in seconds. |
| `XALGORIX_RATE_RPS` | `10` | Sustained outbound request rate. |
| `XALGORIX_RATE_BURST` | `20` | Outbound burst size. |
| `XALGORIX_USE_PROXY` | `false` | Enable proxy routing. |
| `XALGORIX_PROXY_URL` | none | Single proxy URL. Overrides proxy file. |
| `XALGORIX_PROXY_FILE` | none | File containing one proxy per line. |
| `XALGORIX_PROXY_ROTATION` | `roundrobin` | Proxy rotation strategy: `roundrobin` or `random`. |
| `XALGORIX_TLS_SKIP_VERIFY` | `false` | Skip TLS verification for testing traffic. |
| `XALGORIX_DISABLE_BROWSER` | `false` | Disable browser automation. |
| `XALGORIX_BROWSER_PATH` | auto | Custom Chrome/Chromium executable path. |
| `XALGORIX_ALLOW_AUTO_INSTALL` | root only | Permit automatic package installation. |
| `XALGORIX_AUTO_INSTALL_SUDO` | `false` | Permit sudo-prefixed auto-installs. |

## Provider Prefixes

When `XALGORIX_API_BASE` is empty, Xalgorix infers provider defaults from the model prefix.

| Prefix | Default API base |
| --- | --- |
| `openai/` | `https://api.openai.com/v1` |
| `anthropic/` | `https://api.anthropic.com` |
| `deepseek/` | `https://api.deepseek.com/v1` |
| `groq/` | `https://api.groq.com/openai/v1` |
| `google/` | `https://generativelanguage.googleapis.com/v1` |
| `gemini/` | `https://generativelanguage.googleapis.com/v1` |
| `ollama/` | `http://localhost:11434/v1` |
| `minimax/` | `https://api.minimax.io/v1` |

Model names are not hard-coded to this list. The Settings page accepts typed model IDs so you can use newer provider models without waiting for a UI dropdown update.

## CLI Reference

| Flag | Alias | Description |
| --- | --- | --- |
| `--web` | `-w` | Start the Web UI. |
| `--port <port>` | `-p` | Web UI port. Default: `9137`. |
| `--bind <addr>` | none | Bind address. Default: `127.0.0.1`. |
| `--target <target>` | `-t` | Target URL, host, IP, or path. Repeatable. |
| `--instruction <text>` | `-i` | Custom scan instructions. |
| `--model <model>` | `-m` | Override `XALGORIX_LLM` for this run. |
| `--update` | `-up` | Update to the latest release. |
| `--version` | `-v` | Print version. |
| `--start` | none | Install and start the system service. |
| `--stop` | none | Stop the system service. |
| `--restart` | none | Restart the system service. |
| `--uninstall` | none | Remove the system service. |
| `--help` | `-h` | Show help. |

## API Summary

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `POST` | `/api/scan` | Start or save a scan. |
| `POST` | `/api/stop` | Stop all running scans. |
| `GET` | `/api/status` | Current global status. |
| `GET` | `/api/scans` | List scans. |
| `GET` | `/api/scans/:id` | Get scan detail. |
| `DELETE` | `/api/scans/:id` | Delete a scan and its report data. |
| `GET` | `/api/report/:id` | Download a PDF report. |
| `GET` | `/api/instances` | List live and historical instances. |
| `GET` | `/api/instances/:id/events` | Get buffered event history. |
| `POST` | `/api/instances/:id/stop` | Stop a specific instance. |
| `POST` | `/api/instances/:id/start` | Start a saved or completed scan as a new run. |
| `POST` | `/api/instances/:id/restart` | Restart with the same configuration. |
| `POST` | `/api/instances/:id/pause` | Pause a running scan. |
| `POST` | `/api/instances/:id/resume` | Resume a paused scan. |
| `POST` | `/api/upload-logo` | Upload a report logo. |
| `POST` | `/api/upload-targets` | Upload a target list. |
| `GET` | `/api/settings/environment` | List editable environment settings. |
| `POST` | `/api/settings/environment` | Save environment settings. |
| `GET` | `/api/settings/llm` | Get LLM settings. |
| `POST` | `/api/settings/llm` | Save LLM settings. |
| `GET` | `/api/settings/agentmail` | Get AgentMail settings. |
| `POST` | `/api/settings/agentmail` | Save AgentMail settings. |
| `GET` | `/ws` | WebSocket live event stream. |

## Data Storage

Web-mode scan data is stored under:

```text
~/xalgorix-data/
|-- _saved/
|-- logos/
|-- queue_state.json
`-- <target>/
    `-- <date>/
        `-- <scan-id>/
            |-- scan.json
            `-- report.pdf
```

The server keeps historical scan records on disk so the UI can recover after refresh or restart.

## Development

Install Web UI dependencies:

```bash
make webui-install
```

Build everything:

```bash
make build
```

Run tests:

```bash
go test ./...
```

Run the Web UI from source:

```bash
go run ./cmd/xalgorix --web
```

Run only the frontend dev server:

```bash
make webui-dev
```

## Safety Notes

- Use Xalgorix only against authorized targets.
- Do not run active testing against third-party systems without permission.
- Review scan instructions before launching.
- Configure rate limits and proxy settings to match engagement rules.
- Exposing the dashboard externally requires authentication.
- Auto-install is disabled by default for non-root users and should be enabled only when you trust the environment.

## License

Xalgorix is released under the MIT License. See [LICENSE](LICENSE).

## Links

- Documentation: [docs.xalgorix.com](https://docs.xalgorix.com)
- Issues: [github.com/xalgord/xalgorix/issues](https://github.com/xalgord/xalgorix/issues)
- Support: [buymeacoffee.com/xalgord](https://buymeacoffee.com/xalgord)

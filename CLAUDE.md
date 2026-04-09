# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Xalgorix is an autonomous AI pentesting agent written in Go. It uses an LLM-driven agent loop that executes security tools to discover vulnerabilities, with both a Web UI dashboard and a CLI interface.

**Key technologies:** Go 1.24+, gorilla/websocket, charmbracelet/bubbletea (TUI), go-rod (browser automation)

## Build Commands

```bash
make build       # Build binary to ./build/xalgorix (v4.0.5 with injected LDFLAGS)
make run         # Run with: go run ./cmd/xalgorix/ [args]
make test        # Run all tests
make lint        # go fmt + go vet
make tidy        # go mod tidy
make all         # tidy + lint + build
make install     # Build and install to /usr/local/bin/xalgorix
make clean       # Remove ./build and run go clean
go test ./... -v -run TestName    # Run a single test
```

Binary is also pre-built at `./xalgorix` (Linux amd64).

## Architecture

### Core Layers

1. **cmd/xalgorix/** — CLI entry point; parses flags, handles systemd service lifecycle (--start/--stop/--restart/--uninstall), triggers auto-update from GitHub
2. **internal/agent/** — Agent loop: LLM client + tool registry + event emitter; runs the 20-phase pentest methodology
3. **internal/llm/** — LLM client wrapping OpenAI/Anthropic/etc. API with streaming support
4. **internal/web/** — HTTP+WebSocket server for the dashboard; serves embedded static UI
5. **internal/tui/** — Terminal UI using charmbracelet/bubbletea
6. **internal/config/** — Environment-based configuration (XALGORIX_* env vars)
7. **internal/tools/** — Tool implementations registered via registry

### Tool System

Tools are registered in `internal/tools/registry.go` via `Register(*tools.Registry)` in each sub-package:

| Package | Tool Name | Purpose |
|---------|-----------|---------|
| `terminal` | `terminal_action` | Shell command execution with safety filters + auto-install |
| `browser` | `browser_action` | Headless Chrome via go-rod |
| `python` | `python_action` | Python script execution |
| `reporting` | `report_vulns` | Vulnerability report generation with strict gates |
| `websearch` | `websearch_action` | Web search via Gemini/Brave/Google |
| `fileedit` | `file_edit` | Restricted file read/write |
| `finish` | `finish_scan` | Mark scan complete |
| `notes` | `notes_action` | Scan notes |
| `proxy` | `proxy_action` | Caido proxy integration |
| `agentmail` | `agentmail_action` | Temp email for sign-up verification |
| `skills` | `skills_action` | Vulnerability methodology knowledge |
| `agentsgraph` | — | Spawns sub-agents via callback |

Skills are loaded from `internal/tools/skills/data/` (40+ skill files covering vulnerabilities, frameworks, protocols, cloud, reconnaissance).

### Agent Loop (internal/agent/agent.go Run())

1. Build system prompt with tool schema, targets, and 20-phase methodology checklist
2. Iteratively call `client.Chat(messages)` → parse XML tool calls → execute tools → append results
3. `canFinish()` gate: rejects finish if recon not done, < 5 commands, or missing key phases
4. Watchdog: 30min per-process timeout, 20hr scan timeout, 60min idle kill
5. Message pruning after 100 messages: keeps system prompt + continuation marker + 60 recent
6. Circuit breaker: 5 consecutive failures → 60s block per tool

### Scan Modes

- **Single Scan** — Direct target scan
- **DAST Scan** — URL crawl → param discovery → vulnerability testing
- **Wildcard Scan** — Two-phase: Phase 1 subdomain enum via agent → Phase 2 per-subdomain full scan (10s cooldown between subs, runtime.GC() between scans)

### Data Flow

```
User → Web Server → Agent → Tools → Results
              ↓              ↓
         WebSocket       scan.json
         (live feed)     ~/xalgorix-data/<target>/<date>/<slug>/
```

### Web Server Architecture

The HTTP server (`internal/web/server.go`) handles:
- Static file serving (embedded via `go:embed static/*`)
- WebSocket endpoint (`/ws`) for live agent events
- REST API (`/api/scan`, `/api/stop`, `/api/status`, `/api/chat`, etc.)
- Rate limiting per client IP
- Optional dashboard authentication
- Discord webhook notifications on scan start/vuln/completion

### Auto-Install System

The `terminal` tool pre-checks and auto-installs missing tools before running (70+ tool→package mappings: apt, go install, cargo, pip, etc.). A `fixHttpxConflict()` at agent init removes Python httpx if it shadows ProjectDiscovery's httpx.

## Configuration

All config via environment variables (loaded from `~/.xalgorix.env` and `/etc/xalgorix.env`):

| Variable | Required | Description |
|----------|----------|-------------|
| `XALGORIX_LLM` | Yes | Model e.g. `openai/gpt-5.4`, `anthropic/claude-sonnet-4-6` |
| `XALGORIX_API_KEY` | Yes | API key |
| `XALGORIX_API_BASE` | No | Custom endpoint (auto-detected from provider prefix) |
| `XALGORIX_DISCORD_WEBHOOK` | No | Discord alerts |
| `XALGORIX_RATE_LIMIT_REQUESTS` | No | Default 60 |
| `XALGORIX_RATE_LIMIT_WINDOW` | No | Default 60s |
| `XALGORIX_DISABLE_BROWSER` | No | Set `true` to disable headless Chrome |
| `XALGORIX_MAX_ITERATIONS` | No | 0 = unlimited |

Supported provider prefixes: `openai/`, `anthropic/`, `deepseek/`, `groq/`, `google/`, `gemini/`, `ollama/`, `minimax/`

## Key Implementation Details

- Agent uses `messages []llm.Message` as conversation history; append-only with pruning
- Tools return `tools.Result` with `stdout`, `stderr`, `error`, `success` fields
- Safety filters block destructive commands (rm -rf /, DROP TABLE, etc.) and detect encoding bypasses (base64, hex, URL encoding)
- Process group tracking: all spawned processes tracked in `processGroup` map, killed via `KillAllProcesses()` (SIGKILL to process group)
- Scan state persisted to `~/xalgorix-data/<target>/<date>/scan.json`; 30-day auto-cleanup
- Binary pre-built at `./xalgorix` (Linux amd64); `xalgorix --update` or `go install` for updates

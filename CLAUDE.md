# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Xalgorix is an autonomous AI pentesting agent written in Go. It uses an LLM-driven agent loop that executes security tools to discover vulnerabilities, with both a Web UI dashboard and a CLI interface.

**Key technologies:** Go 1.24+, gorilla/websocket, charmbracelet/bubbletea (TUI), go-rod (browser automation)

## Build Commands

```bash
make build       # Build binary to ./build/xalgorix
make run         # Run with: go run ./cmd/xalgorix/ [args]
make test        # Run all tests
make lint        # go fmt + go vet
make tidy        # go mod tidy
make all         # tidy + lint + build
```

Binary is also pre-built at `./xalgorix` (Linux amd64).

## Architecture

### Core Layers

1. **cmd/xalgorix/** — CLI entry point; parses flags, starts web server or runs agent
2. **internal/agent/** — Agent loop: LLM client + tool registry + event emitter; runs the 20-phase pentest methodology
3. **internal/llm/** — LLM client wrapping OpenAI/Anthropic/etc. API with streaming support
4. **internal/web/** — HTTP+WebSocket server for the dashboard; serves embedded static UI
5. **internal/tui/** — Terminal UI using charmbretea
6. **internal/config/** — Environment-based configuration (XALGORIX_* env vars)
7. **internal/tools/** — Tool implementations (11 built-in tools registered via registry)

### Tool System

Tools are registered in `internal/tools/registry.go` via `Register(*tools.Registry)` functions in each sub-package:

| Package | Tool Name | Purpose |
|---------|-----------|---------|
| `terminal` | `terminal_action` | Shell command execution with safety filters |
| `browser` | `browser_action` | Headless Chrome via go-rod |
| `python` | `python_action` | Python script execution |
| `reporting` | `report_vulns` | Vulnerability report generation |
| `websearch` | `websearch_action` | Web search via Gemini/Brave/Google |
| `fileedit` | `file_edit` | File read/write (restricted) |
| `finish` | `finish_scan` | Mark scan complete |
| `notes` | `notes_action` | Notes |
| `proxy` | `proxy_action` | Caido proxy integration |
| `agentmail` | `agentmail_action` | Temp email for sign-up verification |
| `skills` | `skills_action` | Vulnerability methodology knowledge |

### Data Flow

```
User → Web Server → Agent → Tools → Results
              ↓              ↓
         WebSocket       State File
         (live feed)     (scan.json)
```

### Web Server Architecture

The HTTP server (`internal/web/server.go`) handles:
- Static file serving (embedded via `go:embed static/*`)
- WebSocket endpoint for live agent events
- REST API (`/api/scan`, `/api/stop`, `/api/status`, etc.)
- Rate limiting per client IP
- Optional dashboard authentication

### Scan Modes

- **Single Scan** — One target, full vulnerability testing
- **DAST Scan** — Specific URL with crawling → param discovery → vuln testing
- **Wildcard Scan** — Subdomain enumeration then scan each subdomain

## Configuration

All config is via environment variables (loaded from `~/.xalgorix.env` and `/etc/xalgorix.env`):

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

- Agent uses a `messages []llm.Message` slice as conversation history; append-only with memory compression when context exceeds limits
- Tools return `tools.Result` with `stdout`, `stderr`, `error`, `success` fields
- Safety filters in `terminal` tool block destructive commands (rm -rf /, DROP TABLE, etc.) and detect encoding bypasses (base64, hex, URL encoding)
- Circuit breaker: after 5 consecutive failures, a tool is blocked for 60s
- Scan state persisted to `~/xalgorix-data/<target>/<date>/scan.json` for resume support

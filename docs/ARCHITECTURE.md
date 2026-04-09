# Xalgorix Architecture Diagram

## Overall System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           XALGORIX v1.0                                    │
│              The Most Powerful Open-Source AI Pentesting Agent             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER LAYER                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │  Web UI     │  │   CLI       │  │   API       │  │  Discord    │    │
│  │  Dashboard  │  │  Terminal   │  │  Endpoints  │  │  Webhook    │    │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘    │
│         │                │                │                │               │
│         └────────────────┼────────────────┼────────────────┘               │
│                          │                │                                │
└──────────────────────────┼────────────────┼──────────────────────────────────┘
                           │                │
                           ▼                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            CORE LAYER                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      WEB SERVER (Go)                                 │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────┐ │   │
│  │  │   HTTP      │  │   WebSocket │  │   Queue     │  │  Config  │ │   │
│  │  │   Server    │  │   Handler   │  │  Manager    │  │  Manager │ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └──────────┘ │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│  ┌─────────────────────────────────┼─────────────────────────────────────┐  │
│  │                          AGENT ENGINE                                 │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────┐  │  │
│  │  │   LLM      │  │   Tool     │  │   State    │  │  Memory  │  │  │
│  │  │   Client   │  │  Executor  │  │  Machine   │  │  Manager │  │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └──────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                           │                                    │
                           ▼                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TOOL LAYER                                        │
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  RECON       │  │  SCANNING    │  │  EXPLOIT    │  │  UTILITY   │  │
│  │  TOOLS       │  │  TOOLS       │  │  TOOLS      │  │  TOOLS     │  │
│  ├──────────────┤  ├──────────────┤  ├──────────────┤  ├──────────────┤  │
│  │  subfinder   │  │  nuclei      │  │  sqlmap     │  │  terminal   │  │
│  │  amass      │  │  nmap        │  │  xssed      │  │  browser    │  │
│  │  dnsx       │  │  nikto       │  │  commix     │  │  playwright  │  │
│  │  assetfinder│  │  ffuf        │  │  gospider   │  │  websearch  │  │
│  │  findomain  │  │  gobuster    │  │  katana     │  │  cvesearch  │  │
│  │  httpx      │  │  dirsearch   │  │  arjun      │  │  report     │  │
│  │  whatweb   │  │  feroxbuster │  │  paramspider│  │  pdfgen     │  │
│  │  gospider   │  │  zap         │  │  ssrfmap    │  │             │  │
│  │  katana     │  │              │  │  kxss       │  │             │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         INTEGRATION LAYER                                   │
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  OpenAI      │  │  Anthropic  │  │  DeepSeek   │  │  Google     │  │
│  │  API         │  │  API         │  │  API        │  │  Gemini     │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  │
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  NIST NVD    │  │  Exploit-DB  │  │  Discord    │  │   Caido     │  │
│  │  (CVE)       │  │  (Exploits)  │  │  Webhook    │  │   Proxy      │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  │
│                                                                             │
│  Caido Integration:                                                       │
│  • Auto-install if not present                                            │
│  • Auto-start if not running                                              │
│  • HTTP request capture                                                   │
│  • Request replay/modification                                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘


SCAN MODES
══════════

┌─────────────────────────────────────────────────────────────────────────────┐
│  SINGLE SCAN                    │  DAST SCAN                              │
│  ─────────────────              │  ────────────────                        │
│  • Single URL/Target           │  • Specific URL deep scan               │
│  • Full vuln testing           │  • Crawl → Param Discovery → Vuln Test  │
│  • No subdomain enum           │  • Nuclei on all discovered URLs         │
│                                │  • Manual exploitation                   │
├────────────────────────────────┼───────────────────────────────────────────┤
│  WILDCARD SCAN                 │  SCAN QUEUE                             │
│  ───────────────               │  ────────────                            │
│  • Subdomain Enum (Passive)    │  • Multiple targets                      │
│  • Subdomain Enum (Active)     │  • Sequential processing                 │
│  • DNS Resolution              │  • Resume support                        │
│  • For EACH subdomain:         │  • Status tracking                       │
│    → Full vuln scan            │                                         │
│    → DAST-level testing        │                                         │
└────────────────────────────────┴───────────────────────────────────────────┘


DATA FLOW
═════════

User Input ──► Web Server ──► Agent ──► Tools ──► Results
                  │            │                   │
                  │            │                   ▼
                  │            │              Reports/PDF
                  │            │
                  ▼            ▼
            Discord       State File
           Webhook        (JSON)


CONFIGURATION
═════════════

~/.xalgorix.env:
├── XALGORIX_LLM          = "openai/gpt-5.4"
├── XALGORIX_API_KEY     = "sk-..."
├── XALGORIX_API_BASE    = "https://api.openai.com/"
├── GEMINI_API_KEY        = "AIza..."    (optional)
├── XALGORIX_DISCORD_WEBHOOK = "https://discord.com/..." (optional)
└── XALGORIX_RATE_LIMIT  = 60 req/60s

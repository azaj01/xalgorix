# Xalgorix — AI autonomous penetration testing platform (Kali, batteries-included).
#
# The runtime is based on Kali Linux and pulls in Kali's pentest metapackages,
# so hundreds of offensive-security tools are preinstalled. On top of that every
# package manager the agent uses (apt, go, cargo, pipx/pip, npm) is available at
# runtime, so the LLM-driven terminal can still auto-install anything missing.
#
# It runs as ROOT on purpose: the engine only enables package auto-install for
# uid 0 (internal/config: AllowAutoInstall defaults to os.Getuid()==0), and
# apt/go/cargo installs need write access to system paths. The container is the
# isolation boundary — treat it as a disposable, network-isolated scanning
# sandbox and never expose the dashboard without auth.
#
# This is a large image (many GB — the full Kali toolset + wordlists + Go/Rust
# toolchains). That is intentional; size is traded for a complete toolbox.
#
# Build:  docker build -t xalgorix .
# Run:    docker run --rm -p 9137:9137 \
#           -e XALGORIX_LLM=minimax/MiniMax-M3 \
#           -e XALGORIX_API_KEY=your_provider_api_key \
#           -v xalgorix-data:/data \
#           ghcr.io/xalgord/xalgorix:latest
#
# Then open http://127.0.0.1:9137
#
# amd64 image. The release BINARIES remain multi-arch (Linux amd64/arm64) via
# the one-line installer.

# ── Stage 1: build the React web UI ──────────────────────────────────────────
FROM node:20-bookworm-slim AS webui
WORKDIR /src
COPY webui/package.json webui/package-lock.json* ./webui/
RUN cd webui && npm install --no-audit --no-fund
COPY webui ./webui
COPY internal/web ./internal/web
RUN cd webui && npm run build

# ── Stage 2: build the Go binary + the latest Go security toolset ────────────
FROM golang:1.25-bookworm AS gobuild
# libpcap-dev is needed to compile naabu (CGO); git for module fetches.
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=webui /src/internal/web/static ./internal/web/static
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/xalgorix ./cmd/xalgorix/

# Latest versions of the Go tools the engine knows how to auto-install
# (packageMap → goTools), into /go/bin. Best-effort per tool so one flaky
# module never fails the image; anything missing stays runtime-installable.
ENV GOBIN=/go/bin
RUN set -eux; \
    for pkg in \
      github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
      github.com/projectdiscovery/httpx/cmd/httpx@latest \
      github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
      github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
      github.com/projectdiscovery/katana/cmd/katana@latest \
      github.com/jaeles-project/gospider@latest \
      github.com/lc/gau/v2/cmd/gau@latest \
      github.com/tomnomnom/waybackurls@latest \
      github.com/tomnomnom/assetfinder@latest \
      github.com/tomnomnom/qsreplace@latest \
      github.com/tomnomnom/gf@latest \
      github.com/tomnomnom/anew@latest \
      github.com/hakluke/hakrawler@latest \
      github.com/OJ/gobuster/v3@latest \
      github.com/ffuf/ffuf/v2@latest \
      github.com/hahwul/dalfox/v2@latest \
      github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest \
      github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest \
      github.com/projectdiscovery/notify/cmd/notify@latest \
    ; do go install -v "$pkg" || echo "WARN: go install $pkg failed (installable at runtime)"; done; \
    CGO_ENABLED=1 go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
      || echo "WARN: naabu build failed (installable at runtime)"

# ── Stage 3: runtime — Kali Linux, full toolset, runs as root ────────────────
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Kali metapackages = the extensive toolset. Recommends are left ON so the
# metapackages pull their full tool set. Covers the web/app-pentest domains the
# agent uses plus general coverage, and adds the package managers required for
# runtime auto-install (go/cargo/pipx/npm) and Chromium for browser DAST.
RUN apt-get update && apt-get install -y \
      kali-linux-headless \
      kali-tools-information-gathering \
      kali-tools-web \
      kali-tools-vulnerability \
      kali-tools-fuzzing \
      kali-tools-passwords \
      kali-tools-exploitation \
      kali-tools-post-exploitation \
    && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git jq unzip zip p7zip-full file tree bc xxd \
      seclists wordlists \
      python3 python3-pip python3-venv pipx \
      cargo \
      nodejs npm \
      build-essential pkg-config libpcap-dev \
      chromium \
    && rm -rf /var/lib/apt/lists/*

# Go toolchain at runtime so the agent can `go install` anything not baked in.
COPY --from=gobuild /usr/local/go /usr/local/go
# Prebuilt latest Go security tools → on PATH via /root/go/bin.
COPY --from=gobuild /go/bin/ /root/go/bin/
# The xalgorix binary itself.
COPY --from=gobuild /out/xalgorix /usr/local/bin/xalgorix

ENV PATH="/usr/local/go/bin:/root/go/bin:/root/.cargo/bin:/root/.local/bin:${PATH}" \
    GOBIN=/root/go/bin \
    HOME=/root

# feroxbuster (Rust) — Kali packages it, but grab the latest release binary too
# so it's current; cargo stays available at runtime as the engine's fallback.
RUN curl -sSLo /tmp/ferox.zip https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip \
    && unzip -o /tmp/ferox.zip -d /usr/local/bin feroxbuster \
    && chmod +x /usr/local/bin/feroxbuster \
    && rm -f /tmp/ferox.zip \
    || echo "WARN: feroxbuster prefetch failed (present via Kali/cargo)"

# Python tools the engine auto-installs via pipx (best-effort at build).
RUN pipx install scrapling || pip3 install --break-system-packages scrapling || echo "WARN: scrapling prefetch failed (installable at runtime)"

# Bake nuclei templates so first-run scans don't stall on a template fetch.
RUN /root/go/bin/nuclei -update-templates >/dev/null 2>&1 || echo "WARN: nuclei template prefetch skipped"

ENV XALGORIX_BIND=0.0.0.0 \
    XALGORIX_BROWSER_PATH=/usr/bin/chromium \
    XALGORIX_DATA_DIR=/data \
    XALGORIX_ALLOW_AUTO_INSTALL=1 \
    XALGORIX_NO_AUTO_UPDATE=1

# Entrypoint generates dashboard credentials when none are supplied (the image
# binds 0.0.0.0, which the engine won't do without auth) so a plain
# `docker run` starts cleanly and securely.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 9137

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["--web"]

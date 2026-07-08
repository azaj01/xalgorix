# Xalgorix — AI autonomous penetration testing platform.
#
# Build:  docker build -t xalgorix .
# Run:    docker run --rm -p 9137:9137 \
#           -e XALGORIX_LLM=minimax/MiniMax-M2.7 \
#           -e XALGORIX_API_KEY=your_provider_api_key \
#           xalgorix
#
# Then open http://127.0.0.1:9137
#
# The binary binds to 127.0.0.1 by default; inside the container we set
# XALGORIX_BIND=0.0.0.0 so the published port is reachable. External access
# without dashboard auth is refused, so set XALGORIX_USERNAME / XALGORIX_PASSWORD
# when exposing this beyond localhost.

# ── Stage 1: build the React web UI ──────────────────────────────────────────
FROM node:20-bookworm-slim AS webui
WORKDIR /src
COPY webui/package.json webui/package-lock.json* ./webui/
RUN cd webui && npm install --no-audit --no-fund
COPY webui ./webui
COPY internal/web ./internal/web
RUN cd webui && npm run build

# ── Stage 2: build the Go binary (embeds the UI from stage 1) ────────────────
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Bring in the freshly built static assets so //go:embed picks them up.
COPY --from=webui /src/internal/web/static ./internal/web/static
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/xalgorix ./cmd/xalgorix/

# ── Stage 3: runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim
# chromium for browser-assisted DAST; ca-certificates for outbound TLS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends chromium ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV XALGORIX_BIND=0.0.0.0 \
    XALGORIX_BROWSER_PATH=/usr/bin/chromium \
    XALGORIX_DATA_DIR=/data

COPY --from=build /out/xalgorix /usr/local/bin/xalgorix

# Non-root runtime user; /data holds scan output and reports (mount a volume).
RUN useradd --create-home --uid 10001 xalgorix \
    && mkdir -p /data && chown xalgorix:xalgorix /data
USER xalgorix
VOLUME ["/data"]
EXPOSE 9137

ENTRYPOINT ["xalgorix"]
CMD ["--web"]

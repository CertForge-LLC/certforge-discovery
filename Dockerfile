FROM golang:1.26.6-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w -X main.Version=${VERSION}" \
    -o /certforge-discovery \
    ./cmd/certforge-discovery

# ── runtime ───────────────────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /certforge-discovery /certforge-discovery

# Config file is expected at /etc/certforge-discovery/config.yaml
# Mount it as a read-only volume or supply all settings via environment variables.
#
# Required environment variables (when no config file is mounted):
#   CERTFORGE_URL     — https://app.certgovernance.app
#   API_KEY           — from CertForge Settings → API Keys
#
# The agent command runs continuously on the configured poll_interval (default 6h).
ENTRYPOINT ["/certforge-discovery"]
CMD ["agent"]

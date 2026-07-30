# certforge-discovery

Certificate discovery agent for [CertForge](https://certgovernance.app). Finds TLS certificates across your infrastructure and reports them to CertForge for governance, expiry tracking, and compliance.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

Most certificate problems start with not knowing what you have. **certforge-discovery** scans your infrastructure for TLS certificates — public CT logs, live network endpoints, local filesystems, and Kubernetes secrets — and surfaces them in CertForge so you can track, govern, and renew them before they cause an outage.

## What it scans

| Source | What it finds |
|--------|--------------|
| **CT log** | All certificates ever issued for your domains (via crt.sh) |
| **TLS scan** | Certificates live on network endpoints — hostnames, IPs, CIDR ranges |
| **Local filesystem** | Cert files on the host (`/etc/ssl`, nginx, apache, letsencrypt paths) |
| **Kubernetes** | All `kubernetes.io/tls` secrets across every namespace |

## Prerequisites

No CertForge account required for standalone scanning — use `-domain`, `-target`, and `-out` to scan and save results locally without any account. A CertForge account unlocks full governance workflows, expiry tracking, alerting, and the continuous agent mode.

## Installation

Download the binary for your platform from the [latest release](https://github.com/CertForge-LLC/certforge-discovery/releases/latest):

```bash
# Linux (AMD64)
curl -Lo certforge-discovery https://github.com/CertForge-LLC/certforge-discovery/releases/latest/download/certforge-discovery-linux-amd64
chmod +x certforge-discovery
sudo mv certforge-discovery /usr/local/bin/
```

**Verify the download** (optional but recommended):

```bash
curl -Lo checksums.txt https://github.com/CertForge-LLC/certforge-discovery/releases/latest/download/checksums.txt
sha256sum -c checksums.txt --ignore-missing
```

Or install from source (requires Go 1.22+):

```bash
go install github.com/certforge-llc/certforge-discovery/cmd/certforge-discovery@latest
```

## Quick start

### Without a CertForge account

Scan any domain or network target and write results locally — no account needed:

```bash
# CT log scan → pretty table to stdout
certforge-discovery scan -domain example.com

# CT log + TLS live scan → CSV file
certforge-discovery scan -domain example.com -target 10.0.1.0/24 -out certs.csv

# Local filesystem scan → JSON file
certforge-discovery scan -local -out certs.json

# All sources → JSON
certforge-discovery scan -domain example.com -target 10.0.1.0/24 -local -k8s -out certs.json
```

### With a CertForge account

**1. Run setup** — picks your data region and connects to your CertForge account:

```bash
certforge-discovery setup
```

**2. Run a scan:**

```bash
certforge-discovery scan
```

Results appear immediately in CertForge → Discovery.

**3. Run continuously** (recommended — polls on the configured interval, default 6h):

```bash
certforge-discovery agent
```

## Scan flags

```
-config <path>    Config file (default: ~/.certforge-discovery/config.yaml)
-domain <domain>  Scan CT log for this domain (repeatable)
-target <host>    TLS-scan this host, IP, or CIDR (repeatable)
-ports <ports>    Ports for TLS scan (default: 443,8443)
-local            Scan local filesystem for cert files
-k8s              Scan Kubernetes TLS secrets
-out <file>       Write to file (.csv or .json); stdout table if omitted
```

## Configuration

Setup writes a config file to `~/.certforge-discovery/config.yaml`:

```yaml
certforge_url: https://app.certgovernance.app  # your region's URL
api_key: cf_...                                 # from CertForge Settings → API Keys
poll_interval: 6h                               # how often agent re-scans

# Optional
scan_local: false        # scan local filesystem for cert files
scan_k8s: false          # scan Kubernetes TLS secrets
kubeconfig: ""           # path to kubeconfig; empty = in-cluster config
storage_paths:           # additional filesystem paths to scan
  - /opt/app/certs
```

**EU West (GDPR) example:**

```yaml
certforge_url: https://eu.certgovernance.app
api_key: cf_...
poll_interval: 6h
```

## Running as a systemd service

```ini
[Unit]
Description=CertForge Discovery Agent
After=network.target

[Service]
ExecStart=/usr/local/bin/certforge-discovery agent
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now certforge-discovery
```

## Running in Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: certforge-discovery
  namespace: certforge-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: certforge-discovery
  template:
    metadata:
      labels:
        app: certforge-discovery
    spec:
      serviceAccountName: certforge-discovery
      containers:
        - name: agent
          image: ghcr.io/certforge-llc/certforge-discovery:latest
          env:
            - name: CERTFORGE_URL
              value: https://app.certgovernance.app
            - name: API_KEY
              valueFrom:
                secretKeyRef:
                  name: certforge-discovery-credentials
                  key: api_key
```

Use `scan_k8s: true` in your config (or set via environment variables) to enable Kubernetes secret scanning. The agent reads `kubernetes.io/tls` secrets across all namespaces — grant it a ClusterRole with `secrets: [get, list]`.

## Corporate proxy

If your network requires an outbound proxy, set the standard environment variables before running:

```bash
export HTTPS_PROXY=http://proxy.corp.com:8080
export NO_PROXY=localhost,127.0.0.1,10.0.0.0/8
certforge-discovery scan -domain example.com
```

This applies to CT log queries (crt.sh) and CertForge API calls. Live TLS scanning (`-target`) makes direct TCP connections and is not proxied — run the agent on a host that can reach the targets directly.

For a systemd service, set the proxy in the unit file:

```ini
[Service]
Environment=HTTPS_PROXY=http://proxy.corp.com:8080
Environment=NO_PROXY=localhost,10.0.0.0/8
ExecStart=/usr/local/bin/certforge-discovery agent -domain example.com
```

## What is reported to CertForge

When a CertForge account is configured, the agent posts **certificate metadata only** to your CertForge region. The exact fields sent for each certificate:

| Field | Example | Notes |
|-------|---------|-------|
| `fingerprint` | `sha256:3f2a...` | SHA-256 of the DER-encoded cert |
| `serial` | `0x1A2B3C...` | Certificate serial number |
| `issuer` | `C=US, O=Let's Encrypt, CN=R11` | Issuer distinguished name |
| `subject` | `example.com` | Subject common name |
| `sans` | `example.com, www.example.com` | Subject alternative names |
| `not_before` | `2024-01-01T00:00:00Z` | Validity start |
| `not_after` | `2024-04-01T00:00:00Z` | Expiry |
| `source` | `ct_log`, `tls_scan`, `local`, `k8s` | How the cert was found |
| `source_detail` | `192.168.1.50:443` | Specific endpoint or path |
| `seen_deployed` | `true` | Whether a live TLS handshake confirmed it |
| `eku` | `["TLS Web Server Authentication"]` | Extended key usages |

**Never read or transmitted:**
- Private keys or key material of any kind
- Plaintext traffic or HTTP request/response bodies
- Filesystem contents beyond recognized certificate file formats
- Kubernetes secrets other than `kubernetes.io/tls` type (and even those: only the `tls.crt` field, never `tls.key`)

### Inspect before you trust: `-dry-run`

Run any scan with `-dry-run` to print the exact JSON payload that *would* be sent to CertForge — without posting anything:

```bash
certforge-discovery scan -domain example.com -dry-run
certforge-discovery scan -domain example.com -target 10.0.1.0/24 -dry-run | jq .
```

The output is the verbatim request body. You can confirm it contains only the fields listed above before allowing the agent outbound access to CertForge.

## Data residency

certforge-discovery sends certificate metadata only to your configured `certforge_url`. No certificate private keys are ever read or transmitted — the agent only reads the public certificate portion of TLS secrets and cert files.

Your data stays in the region you chose during setup. See [CertForge data residency](https://docs.certgovernance.app/architecture) for details.

## License

Apache 2.0

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

- A CertForge account — [free tier](https://certgovernance.app) includes full discovery, expiry tracking, and governance workflows. No credit card required.
- Domains and scan targets configured in CertForge → Discovery.

## Installation

Download the binary for your platform from the [latest release](https://github.com/CertForge-LLC/certforge-discovery/releases/latest):

```bash
# Linux (AMD64)
curl -Lo certforge-discovery https://github.com/CertForge-LLC/certforge-discovery/releases/latest/download/certforge-discovery-linux-amd64
chmod +x certforge-discovery
sudo mv certforge-discovery /usr/local/bin/
```

Or install from source (requires Go 1.22+):

```bash
go install github.com/certforge-llc/certforge-discovery/cmd/certforge-discovery@latest
```

## Quick start

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

## Data residency

certforge-discovery sends certificate metadata only to your configured `certforge_url`. No certificate private keys are ever read or transmitted — the agent only reads the public certificate portion of TLS secrets and cert files.

Your data stays in the region you chose during setup. See [CertForge data residency](https://certgovernance.app/docs/architecture) for details.

## License

Apache 2.0

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/certforge-llc/certforge-discovery/internal/client"
	"github.com/certforge-llc/certforge-discovery/internal/config"
	"github.com/certforge-llc/certforge-discovery/internal/output"
	"github.com/certforge-llc/certforge-discovery/internal/scan"
)

var Version = "dev"

const defaultBaseURL = "https://app.certgovernance.app"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "setup":
		cmdSetup()
	case "enroll":
		cmdEnroll(os.Args[2:])
	case "roll":
		cmdRoll()
	case "scan":
		cmdScan(os.Args[2:])
	case "agent":
		cmdAgent(os.Args[2:])
	case "status":
		cmdStatus()
	case "clear":
		cmdClear()
	case "version":
		fmt.Println(Version)
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `certforge-discovery %s — TLS certificate discovery

No account required. Scan any domain or network and write results locally:

  certforge-discovery scan -domain example.com
  certforge-discovery scan -domain example.com -out certs.csv
  certforge-discovery scan -domain example.com -target 10.0.1.0/24 -out certs.json
  certforge-discovery scan -local
  certforge-discovery agent -domain example.com          (runs continuously)

Commands:
  scan    [flags]   Run a single scan and exit
  agent   [flags]   Run continuously on the configured poll interval
  status            Show how many certs CertForge has stored for your org
  clear             Delete all discovered certs for your org (use before re-scan)
  setup             Connect to a CertForge account (optional — enables reporting
                    results to CertForge, pulling domain lists centrally, and
                    scanning internal networks from this host)
  roll              Replace the stored API key (after rotating it in CertForge)
  version           Print version

Scan flags:
  -domain <domain>         CT log scan for this domain (repeatable)
  -target <host>           TLS-scan this host, IP, or CIDR (repeatable)
  -ports <ports>           Ports for TLS scan (default: 443,8443)
  -local                   Scan local filesystem for cert files
  -k8s                     Scan Kubernetes TLS secrets
  -k8s-namespace <ns>      Limit K8s scan to this namespace (repeatable; default: all namespaces)
  -out <file>              Write to file (.csv or .json); prints table to stdout if omitted
  -dry-run                 Print the JSON payload that would be sent to CertForge; do not post
  -config <path>           Config file (default: ~/.certforge-discovery/config.yaml)

`, Version)
}

// ── setup ─────────────────────────────────────────────────────────────────────

func cmdSetup() {
	cfgPath := config.DefaultPath()
	stdin := bufio.NewReader(os.Stdin)

	fmt.Println("CertForge Discovery — Setup")
	fmt.Println()

	baseURL := defaultBaseURL
	fmt.Printf("Fetching available regions from %s...\n", baseURL)
	regions, err := client.ListRegions(baseURL)
	if err != nil {
		fmt.Printf("Warning: could not fetch regions (%v). Using default URL.\n", err)
	}

	var chosenURL string
	if len(regions) > 1 {
		fmt.Println()
		for i, r := range regions {
			suffix := ""
			if r.ComingSoon {
				suffix = " (coming soon)"
			}
			u := r.URL
			if u == "" {
				u = baseURL
			}
			fmt.Printf("  %d. %-30s %s%s\n", i+1, r.Name, u, suffix)
		}
		fmt.Print("\nSelect your data region [1]: ")
		line, _ := stdin.ReadString('\n')
		line = strings.TrimSpace(line)
		idx := 0
		if line != "" {
			fmt.Sscanf(line, "%d", &idx)
			idx--
		}
		if idx < 0 || idx >= len(regions) {
			idx = 0
		}
		chosenURL = regions[idx].URL
		if chosenURL == "" {
			chosenURL = baseURL
		}
	} else {
		chosenURL = baseURL
		fmt.Printf("Using region: %s\n", chosenURL)
	}

	fmt.Println()
	fmt.Printf("Open %s/settings/api-keys in your browser to create an API key.\n", chosenURL)
	fmt.Println("(If you don't have an account yet, sign up first at that URL.)")
	fmt.Println()
	fmt.Println("Required permissions: Read, Enroll")
	fmt.Println()
	fmt.Print("Paste your API key here: ")
	apiKey, _ := stdin.ReadString('\n')
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "Error: API key is required.")
		os.Exit(1)
	}

	fmt.Print("Verifying API key... ")
	c := client.New(chosenURL, apiKey, "")
	if _, err := c.GetConfig(); err != nil {
		fmt.Println("failed.")
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("ok.")

	cfg := &config.Config{
		CertForgeURL: chosenURL,
		APIKey:       apiKey,
		PollInterval: 6 * time.Hour,
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nConfig saved to %s\n", cfgPath)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  Run a scan now:")
	fmt.Println("    certforge-discovery scan -domain example.com")
	fmt.Println("    certforge-discovery scan -domain example.com -target 10.0.1.0/24")
	fmt.Println()
	fmt.Println("  Or run continuously (polls every 6h):")
	fmt.Println("    certforge-discovery agent -domain example.com")
	fmt.Println()
	fmt.Println("  Optionally, add domains in CertForge → Discovery to manage them centrally")
	fmt.Println("  (the agent will pull that list automatically alongside any -domain flags).")
}

// ── status ────────────────────────────────────────────────────────────────────

func cmdStatus() {
	cfgPath := config.DefaultPath()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("no config found — run 'certforge-discovery setup' first\n(%v)", err)
	}
	c, err := newClient(cfg)
	if err != nil {
		log.Fatalf("client setup: %v", err)
	}
	stats, err := c.GetStats()
	if err != nil {
		log.Fatalf("status: %v", err)
	}
	fmt.Printf("CertForge URL : %s\n", cfg.CertForgeURL)
	fmt.Printf("Org ID        : %s\n", stats.OrgID)
	fmt.Printf("Discovered    : %d cert(s) in inventory\n", stats.DiscoveredCerts)
}

// ── clear ─────────────────────────────────────────────────────────────────────

func cmdClear() {
	cfgPath := config.DefaultPath()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("no config found — run 'certforge-discovery setup' first\n(%v)", err)
	}
	c, err := newClient(cfg)
	if err != nil {
		log.Fatalf("client setup: %v", err)
	}

	before, _ := c.GetStats()
	if before != nil {
		fmt.Printf("Clearing %d cert(s) from %s...\n", before.DiscoveredCerts, cfg.CertForgeURL)
	}
	if err := c.ClearCerts(); err != nil {
		log.Fatalf("clear: %v", err)
	}
	fmt.Println("Done. Inventory is now empty for this org.")
}

// ── roll ──────────────────────────────────────────────────────────────────────

func cmdRoll() {
	cfgPath := config.DefaultPath()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("no config found — run 'certforge-discovery setup' first\n(%v)", err)
	}

	stdin := bufio.NewReader(os.Stdin)
	fmt.Printf("Rolling API key for %s\n", cfg.CertForgeURL)
	fmt.Println()
	fmt.Printf("Open %s/settings/api-keys in your browser to create a new key.\n", cfg.CertForgeURL)
	fmt.Println("Required permissions: Read, Enroll")
	fmt.Println()
	fmt.Print("Paste new API key here: ")
	newKey, _ := stdin.ReadString('\n')
	newKey = strings.TrimSpace(newKey)
	if newKey == "" {
		fmt.Fprintln(os.Stderr, "Error: API key is required.")
		os.Exit(1)
	}

	fmt.Print("Verifying... ")
	// For the verification step use a fresh bearer-token client with the new key —
	// mTLS auth is keyed to the certificate, not the API key, so a key-roll check
	// always goes through the bearer path regardless of what the config says.
	c := client.New(cfg.CertForgeURL, newKey, "")
	if _, err := c.GetConfig(); err != nil {
		fmt.Println("failed.")
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("ok.")

	cfg.APIKey = newKey
	if err := config.Save(cfgPath, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Config updated at %s\n", cfgPath)
}

// ── scan ──────────────────────────────────────────────────────────────────────

func cmdScan(args []string) {
	opts := parseScanFlags("scan", args)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	certs, err := runScan(ctx, opts)
	if err != nil {
		log.Fatalf("scan: %v", err)
	}
	writeOutput(opts, certs)
}

// ── agent ─────────────────────────────────────────────────────────────────────

func cmdAgent(args []string) {
	opts := parseScanFlags("agent", args)

	if opts.cfg == nil {
		log.Fatalf("agent mode requires a config file — run 'certforge-discovery setup' first")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Printf("[agent] starting %s — polling %s every %s", Version, opts.cfg.CertForgeURL, opts.cfg.PollInterval)

	if certs, err := runScan(ctx, opts); err != nil {
		log.Printf("[agent] scan error: %v", err)
	} else {
		writeOutput(opts, certs)
	}

	ticker := time.NewTicker(opts.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("[agent] shutting down")
			return
		case <-ticker.C:
			if certs, err := runScan(ctx, opts); err != nil {
				log.Printf("[agent] scan error: %v", err)
			} else {
				writeOutput(opts, certs)
			}
		}
	}
}

// ── flags ─────────────────────────────────────────────────────────────────────

type scanOpts struct {
	cfg           *config.Config // nil when running without an account
	outFile       string
	domains       []string
	targets       []string
	ports         string
	scanLocal     bool
	scanK8s       bool
	k8sNamespaces []string // empty = all namespaces
	dryRun        bool
}

type multiFlag []string

func (m *multiFlag) String() string  { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func parseScanFlags(cmd string, args []string) scanOpts {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath(), "config file path")
	outFile  := fs.String("out", "", "output file (.csv or .json); stdout table if omitted")
	ports    := fs.String("ports", "443,8443", "ports for TLS scan")
	local    := fs.Bool("local", false, "scan local filesystem")
	k8s      := fs.Bool("k8s", false, "scan Kubernetes TLS secrets")
	dryRun   := fs.Bool("dry-run", false, "print JSON that would be sent to CertForge; do not post")

	var domains, targets, k8sNamespaces multiFlag
	fs.Var(&domains, "domain", "domain to scan via CT log (repeatable)")
	fs.Var(&targets, "target", "host/IP/CIDR to TLS scan (repeatable)")
	fs.Var(&k8sNamespaces, "k8s-namespace", "limit K8s scan to this namespace (repeatable; default: all namespaces)")

	_ = fs.Parse(args)

	opts := scanOpts{
		outFile:       *outFile,
		domains:       []string(domains),
		targets:       []string(targets),
		ports:         *ports,
		scanLocal:     *local,
		scanK8s:       *k8s,
		k8sNamespaces: []string(k8sNamespaces),
		dryRun:        *dryRun,
	}

	// Config is optional — only needed to talk to CertForge.
	cfg, err := config.Load(*cfgPath)
	if err == nil {
		opts.cfg = cfg
	} else if len(opts.domains) == 0 && len(opts.targets) == 0 && !*local && !*k8s {
		// No config and no explicit scan targets — nothing to do.
		log.Fatalf("no config found and no scan targets specified\n\nRun 'certforge-discovery setup' to connect to CertForge,\nor use -domain / -target flags to scan without an account.")
	}

	return opts
}

// ── CertForge client factory ───────────────────────────────────────────────────

// newClient returns a CertForge API client for the given config.
// When ClientCertFile is set the client uses mTLS; otherwise it falls back to
// the legacy bearer-token path.  Errors are returned so callers can decide
// whether to fatal or log-and-continue.
func newClient(cfg *config.Config) (*client.Client, error) {
	if cfg.ClientCertFile != "" {
		return client.NewMTLS(
			cfg.CertForgeURL,
			cfg.MTLSEndpoint(),
			cfg.ClientCertFile,
			cfg.ClientKeyFile,
			cfg.ServerCAFile,
			Version,
		)
	}
	return client.New(cfg.CertForgeURL, cfg.APIKey, Version), nil
}

// ── core scan logic ───────────────────────────────────────────────────────────

const ingestBatchSize = 200

func runScan(ctx context.Context, opts scanOpts) ([]client.Cert, error) {
	hc := &http.Client{Timeout: 30 * time.Second}
	var all []client.Cert

	// Load known internal CAs from config for issuer classification.
	var knownCAPaths []string
	if opts.cfg != nil {
		for _, ca := range opts.cfg.KnownInternalCAs {
			knownCAPaths = append(knownCAPaths, ca.Cert)
		}
	}
	knownCAs := scan.LoadKnownCAs(knownCAPaths)

	// Build the CertForge client once per scan run (not once per batch).
	// mTLS clients hold a tls.Config — safe to reuse across requests.
	var cfClient *client.Client
	if opts.cfg != nil {
		var clientErr error
		cfClient, clientErr = newClient(opts.cfg)
		if clientErr != nil {
			log.Printf("[scan] CertForge client setup failed: %v — results will not be posted", clientErr)
		}
	}

	// Work list: start from CLI flags, then merge CertForge config if available.
	domains := opts.domains
	type tgt struct{ target, ports string }
	var targets []tgt
	for _, t := range opts.targets {
		targets = append(targets, tgt{t, opts.ports})
	}
	scanLocal := opts.scanLocal
	scanK8s   := opts.scanK8s
	var storagePaths []string

	if cfClient != nil {
		scanCfg, err := cfClient.GetConfig()
		if err != nil {
			log.Printf("[scan] could not fetch CertForge config: %v", err)
		} else {
			for _, d := range scanCfg.Domains {
				domains = appendUniq(domains, d.Domain)
				if d.ScanLocal {
					scanLocal = true
				}
			}
			for _, t := range scanCfg.Targets {
				targets = append(targets, tgt{t.Target, t.Ports})
			}
		}
		if opts.cfg.ScanLocal {
			scanLocal = true
		}
		if opts.cfg.ScanK8s {
			scanK8s = true
		}
		storagePaths = opts.cfg.StoragePaths
	}

	log.Printf("[scan] %d domain(s), %d target(s), local=%v k8s=%v",
		len(domains), len(targets), scanLocal, scanK8s)

	// CT log per domain.
	for _, domain := range domains {
		if ctx.Err() != nil {
			break
		}
		log.Printf("[scan] ct_log %s", domain)
		certs, err := scan.ScanCTLog(ctx, hc, domain, knownCAs)
		if err != nil {
			log.Printf("[scan] ct_log %s: %v", domain, err)
			if cfClient != nil {
				_ = cfClient.MarkDomainScanned(domain, "error", err.Error())
			}
			continue
		}
		all = append(all, certs...)
		if cfClient != nil {
			_ = cfClient.MarkDomainScanned(domain, "ok", "")
		}
	}

	// TLS live scan.
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		log.Printf("[scan] tls %s ports=%s", t.target, t.ports)
		all = append(all, scan.ScanTLSTarget(ctx, t.target, t.ports, knownCAs)...)
	}

	// Local filesystem.
	if scanLocal {
		log.Printf("[scan] local filesystem")
		all = append(all, scan.ScanLocalFS(storagePaths, knownCAs)...)
	}

	// Kubernetes secrets.
	if scanK8s {
		// Merge namespaces from CLI flags and config; empty = scan all.
		var k8sNamespaces []string
		if opts.cfg != nil {
			k8sNamespaces = append(k8sNamespaces, opts.cfg.K8sNamespaces...)
		}
		k8sNamespaces = append(k8sNamespaces, opts.k8sNamespaces...)
		k8sNamespaces = dedupStrings(k8sNamespaces)

		if len(k8sNamespaces) > 0 {
			log.Printf("[scan] k8s secrets (namespaces: %v)", k8sNamespaces)
		} else {
			log.Printf("[scan] k8s secrets (all namespaces)")
		}

		kubeconfig := ""
		if opts.cfg != nil {
			kubeconfig = opts.cfg.KubeConfig
		}
		k8sCerts, err := scan.ScanK8sSecrets(ctx, kubeconfig, k8sNamespaces, knownCAs)
		if err != nil {
			log.Printf("[scan] k8s: %v", err)
		} else {
			all = append(all, k8sCerts...)
		}
	}

	// Post to CertForge if configured.
	if cfClient != nil && len(all) > 0 {
		if opts.dryRun {
			body, _ := json.MarshalIndent(map[string]any{"certs": all}, "", "  ")
			fmt.Printf("--- DRY RUN: %d cert(s) found, nothing posted to CertForge (%s) ---\n", len(all), opts.cfg.CertForgeURL)
			fmt.Println(string(body))
		} else {
			total, errs := 0, 0
			for i := 0; i < len(all); i += ingestBatchSize {
				end := i + ingestBatchSize
				if end > len(all) {
					end = len(all)
				}
				result, err := cfClient.Ingest(all[i:end])
				if err != nil {
					log.Printf("[scan] ingest batch: %v", err)
					errs++
					continue
				}
				total += result.Ingested
				errs += result.Errors
			}
			log.Printf("[scan] posted to CertForge — %d ingested, %d errors", total, errs)
		}
	}

	log.Printf("[scan] complete — %d certificate(s) found", len(all))
	return all, nil
}

func writeOutput(opts scanOpts, certs []client.Cert) {
	if opts.outFile != "" {
		if err := output.ToFile(opts.outFile, certs); err != nil {
			log.Printf("output: %v", err)
		} else {
			log.Printf("[out] wrote %d cert(s) to %s", len(certs), opts.outFile)
		}
		return
	}
	// No --out and no CertForge config → print table to stdout.
	// With CertForge config, results were already posted; skip the table.
	if opts.cfg == nil {
		_ = output.Table(certs)
	}
}

func appendUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func dedupStrings(s []string) []string {
	seen := make(map[string]struct{}, len(s))
	out := s[:0]
	for _, v := range s {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}

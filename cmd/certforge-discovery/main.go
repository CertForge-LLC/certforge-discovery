package main

import (
	"bufio"
	"context"
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
	case "scan":
		cmdScan(os.Args[2:])
	case "agent":
		cmdAgent(os.Args[2:])
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
  setup             Connect to a CertForge account (optional — enables reporting
                    results to CertForge, pulling domain lists centrally, and
                    scanning internal networks from this host)
  version           Print version

Scan flags:
  -domain <domain>    CT log scan for this domain (repeatable)
  -target <host>      TLS-scan this host, IP, or CIDR (repeatable)
  -ports <ports>      Ports for TLS scan (default: 443,8443)
  -local              Scan local filesystem for cert files
  -k8s                Scan Kubernetes TLS secrets
  -out <file>         Write to file (.csv or .json); prints table to stdout if omitted
  -config <path>      Config file (default: ~/.certforge-discovery/config.yaml)

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
	c := client.New(chosenURL, apiKey)
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

	log.Printf("[agent] starting — polling %s every %s", opts.cfg.CertForgeURL, opts.cfg.PollInterval)

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
	cfg        *config.Config // nil when running without an account
	outFile    string
	domains    []string
	targets    []string
	ports      string
	scanLocal  bool
	scanK8s    bool
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

	var domains, targets multiFlag
	fs.Var(&domains, "domain", "domain to scan via CT log (repeatable)")
	fs.Var(&targets, "target", "host/IP/CIDR to TLS scan (repeatable)")

	_ = fs.Parse(args)

	opts := scanOpts{
		outFile:   *outFile,
		domains:   []string(domains),
		targets:   []string(targets),
		ports:     *ports,
		scanLocal: *local,
		scanK8s:   *k8s,
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

// ── core scan logic ───────────────────────────────────────────────────────────

const ingestBatchSize = 200

func runScan(ctx context.Context, opts scanOpts) ([]client.Cert, error) {
	hc := &http.Client{Timeout: 30 * time.Second}
	var all []client.Cert

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

	if opts.cfg != nil {
		c := client.New(opts.cfg.CertForgeURL, opts.cfg.APIKey)
		scanCfg, err := c.GetConfig()
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
		certs, err := scan.ScanCTLog(ctx, hc, domain)
		if err != nil {
			log.Printf("[scan] ct_log %s: %v", domain, err)
			if opts.cfg != nil {
				c := client.New(opts.cfg.CertForgeURL, opts.cfg.APIKey)
				_ = c.MarkDomainScanned(domain, "error", err.Error())
			}
			continue
		}
		all = append(all, certs...)
		if opts.cfg != nil {
			c := client.New(opts.cfg.CertForgeURL, opts.cfg.APIKey)
			_ = c.MarkDomainScanned(domain, "ok", "")
		}
	}

	// TLS live scan.
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		log.Printf("[scan] tls %s ports=%s", t.target, t.ports)
		all = append(all, scan.ScanTLSTarget(ctx, t.target, t.ports)...)
	}

	// Local filesystem.
	if scanLocal {
		log.Printf("[scan] local filesystem")
		all = append(all, scan.ScanLocalFS(storagePaths)...)
	}

	// Kubernetes secrets.
	if scanK8s {
		log.Printf("[scan] k8s secrets")
		kubeconfig := ""
		if opts.cfg != nil {
			kubeconfig = opts.cfg.KubeConfig
		}
		k8sCerts, err := scan.ScanK8sSecrets(ctx, kubeconfig)
		if err != nil {
			log.Printf("[scan] k8s: %v", err)
		} else {
			all = append(all, k8sCerts...)
		}
	}

	// Post to CertForge if configured.
	if opts.cfg != nil && len(all) > 0 {
		c := client.New(opts.cfg.CertForgeURL, opts.cfg.APIKey)
		total, errs := 0, 0
		for i := 0; i < len(all); i += ingestBatchSize {
			end := i + ingestBatchSize
			if end > len(all) {
				end = len(all)
			}
			result, err := c.Ingest(all[i:end])
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

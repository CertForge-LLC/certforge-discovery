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
	"github.com/certforge-llc/certforge-discovery/internal/scan"
)

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
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `certforge-discovery — CertForge certificate discovery agent

Usage:
  certforge-discovery setup          Interactive first-time setup
  certforge-discovery scan           Run a single discovery scan and exit
  certforge-discovery agent          Run continuously on the configured poll interval

Flags (scan / agent):
  -config <path>   Config file path (default: ~/.certforge-discovery/config.yaml)

`)
}

// ── setup ─────────────────────────────────────────────────────────────────────

func cmdSetup() {
	cfgPath := config.DefaultPath()
	stdin := bufio.NewReader(os.Stdin)

	fmt.Println("CertForge Discovery — Setup")
	fmt.Println()

	// Step 1: pick a CertForge URL / region.
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

	// Step 2: get API key.
	fmt.Println()
	fmt.Printf("Open %s/settings/api-keys in your browser to create an API key.\n", chosenURL)
	fmt.Println("(If you don't have an account yet, sign up first at that URL.)")
	fmt.Println()
	fmt.Print("Paste your API key here: ")
	apiKey, _ := stdin.ReadString('\n')
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "Error: API key is required.")
		os.Exit(1)
	}

	// Step 3: verify the key works.
	fmt.Print("Verifying API key... ")
	c := client.New(chosenURL, apiKey)
	if _, err := c.GetConfig(); err != nil {
		fmt.Println("failed.")
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("ok.")

	// Step 4: write config.
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
	fmt.Println("  1. Add domains and scan targets in CertForge → Discovery")
	fmt.Println("  2. Run:  certforge-discovery scan")
	fmt.Println("  3. Or:   certforge-discovery agent  (runs continuously)")
}

// ── scan ──────────────────────────────────────────────────────────────────────

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath(), "config file path")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := runScan(ctx, cfg); err != nil {
		log.Fatalf("scan: %v", err)
	}
}

// ── agent ─────────────────────────────────────────────────────────────────────

func cmdAgent(args []string) {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath(), "config file path")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Printf("[agent] starting — polling %s every %s", cfg.CertForgeURL, cfg.PollInterval)

	// Run immediately on start, then on the interval.
	if err := runScan(ctx, cfg); err != nil {
		log.Printf("[agent] scan error: %v", err)
	}

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("[agent] shutting down")
			return
		case <-ticker.C:
			if err := runScan(ctx, cfg); err != nil {
				log.Printf("[agent] scan error: %v", err)
			}
		}
	}
}

// ── core scan logic ───────────────────────────────────────────────────────────

const ingestBatchSize = 200

func runScan(ctx context.Context, cfg *config.Config) error {
	c := client.New(cfg.CertForgeURL, cfg.APIKey)

	scanCfg, err := c.GetConfig()
	if err != nil {
		return fmt.Errorf("fetch config: %w", err)
	}

	log.Printf("[scan] %d domain(s), %d target(s)", len(scanCfg.Domains), len(scanCfg.Targets))

	hc := &http.Client{Timeout: 30 * time.Second}
	var all []client.Cert

	// CT log + local filesystem per domain.
	for _, d := range scanCfg.Domains {
		if ctx.Err() != nil {
			break
		}
		log.Printf("[scan] ct_log %s", d.Domain)
		certs, err := scan.ScanCTLog(ctx, hc, d.Domain)
		if err != nil {
			log.Printf("[scan] ct_log %s: %v", d.Domain, err)
			_ = c.MarkDomainScanned(d.Domain, "error", err.Error())
			continue
		}
		all = append(all, certs...)

		if d.ScanLocal || cfg.ScanLocal {
			all = append(all, scan.ScanLocalFS(cfg.StoragePaths)...)
		}

		_ = c.MarkDomainScanned(d.Domain, "ok", "")
	}

	// TLS live scan per target.
	for _, t := range scanCfg.Targets {
		if ctx.Err() != nil {
			break
		}
		log.Printf("[scan] tls %s ports=%s", t.Target, t.Ports)
		all = append(all, scan.ScanTLSTarget(ctx, t.Target, t.Ports)...)
	}

	// Kubernetes TLS secrets.
	if cfg.ScanK8s {
		log.Printf("[scan] k8s secrets")
		k8sCerts, err := scan.ScanK8sSecrets(ctx, cfg.KubeConfig)
		if err != nil {
			log.Printf("[scan] k8s: %v", err)
		} else {
			all = append(all, k8sCerts...)
		}
	}

	if len(all) == 0 {
		log.Printf("[scan] no certs found")
		return nil
	}

	// Post in batches.
	total, errs := 0, 0
	for i := 0; i < len(all); i += ingestBatchSize {
		end := i + ingestBatchSize
		if end > len(all) {
			end = len(all)
		}
		result, err := c.Ingest(all[i:end])
		if err != nil {
			log.Printf("[scan] ingest batch %d-%d: %v", i, end, err)
			errs++
			continue
		}
		total += result.Ingested
		errs += result.Errors
	}

	log.Printf("[scan] complete — %d cert(s) ingested, %d error(s)", total, errs)
	return nil
}

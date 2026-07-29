package scan

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"strings"
	"time"

	"github.com/certforge-llc/certforge-discovery/internal/client"
)

const (
	crtshSubdomainURL = "https://crt.sh/?q=%%25.%s&output=json&exclude=expired"
	crtshApexURL      = "https://crt.sh/?q=%s&output=json&exclude=expired"
	crtshCertURL      = "https://crt.sh/?d=%s"

	crtshTimeout    = 90 * time.Second
	ekuConcurrency  = 5
)

type crtshEntry struct {
	ID         int64  `json:"id"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
	IssuerName string `json:"issuer_name"`
	Serial     string `json:"serial_number"`
}

// ScanCTLog queries crt.sh for all known certs for domain and returns discovered certs.
func ScanCTLog(ctx context.Context, _ *http.Client, domain string) ([]client.Cert, error) {
	// Use a dedicated client with a longer timeout — crt.sh can be slow.
	hc := &http.Client{Timeout: crtshTimeout}

	log.Printf("[ctlog] %s: querying crt.sh (subdomain)...", domain)
	subEntries, err := fetchCRTSH(ctx, hc, fmt.Sprintf(crtshSubdomainURL, domain))
	if err != nil {
		return nil, fmt.Errorf("crt.sh subdomain: %w", err)
	}

	log.Printf("[ctlog] %s: querying crt.sh (apex)...", domain)
	apexEntries, _ := fetchCRTSH(ctx, hc, fmt.Sprintf(crtshApexURL, domain))

	entries := append(subEntries, apexEntries...)
	log.Printf("[ctlog] %s: %d entries from crt.sh", domain, len(entries))

	seen := map[string]bool{}
	type pending struct {
		entry crtshEntry
		cert  client.Cert
	}
	var pendings []pending

	for _, e := range entries {
		key := e.Serial + "|" + e.IssuerName
		if seen[key] {
			continue
		}
		seen[key] = true

		notAfter := parseCRTTime(e.NotAfter)
		notBefore := parseCRTTime(e.NotBefore)
		if notAfter != nil && notAfter.Before(time.Now()) {
			continue
		}

		fp := fingerprintFromMeta(e.Serial, e.IssuerName)
		sans := strings.ReplaceAll(e.NameValue, "\n", ", ")

		pendings = append(pendings, pending{
			entry: e,
			cert: client.Cert{
				Fingerprint:  fp,
				Serial:       e.Serial,
				Issuer:       e.IssuerName,
				Subject:      e.CommonName,
				SANs:         sans,
				Domain:       domain,
				NotBefore:    notBefore,
				NotAfter:     notAfter,
				Source:       "ct_log",
				SourceDetail: fmt.Sprintf("crt.sh #%d", e.ID),
			},
		})
	}

	if len(pendings) == 0 {
		return nil, nil
	}

	// Enrich EKU concurrently with a bounded worker pool.
	log.Printf("[ctlog] %s: enriching EKU for %d cert(s)...", domain, len(pendings))
	certs := make([]client.Cert, len(pendings))
	sem := make(chan struct{}, ekuConcurrency)
	var wg sync.WaitGroup
	done := 0
	var mu sync.Mutex

	for i, p := range pendings {
		wg.Add(1)
		go func(idx int, pp pending) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			c := pp.cert
			c.EKU = enrichEKU(ctx, hc, fmt.Sprintf("%d", pp.entry.ID))
			certs[idx] = c

			mu.Lock()
			done++
			if done%10 == 0 || done == len(pendings) {
				log.Printf("[ctlog] %s: EKU enrichment %d/%d", domain, done, len(pendings))
			}
			mu.Unlock()
		}(i, p)
	}
	wg.Wait()

	return certs, nil
}

func fetchCRTSH(ctx context.Context, hc *http.Client, url string) ([]crtshEntry, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "CertForge-Discovery/1.0")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned %d", resp.StatusCode)
	}
	var entries []crtshEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return entries, nil
}

// enrichEKU fetches the raw cert PEM from crt.sh and extracts EKU values.
// Returns nil on any error — EKU enrichment is best-effort.
func enrichEKU(ctx context.Context, hc *http.Client, id string) []string {
	url := fmt.Sprintf(crtshCertURL, id)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "CertForge-Discovery/1.0")
	resp, err := hc.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	block, _ := pem.Decode(buf)
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return ekuStrings(cert)
}

func fingerprintFromMeta(serial, issuer string) string {
	h := sha256.Sum256([]byte(serial + "|" + issuer))
	return fmt.Sprintf("%x", h)
}

func parseCRTTime(s string) *time.Time {
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

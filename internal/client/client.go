package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Client talks to the CertForge discovery API.
// It supports two auth modes:
//   - Bearer token (legacy): set apiKey; uses the dashboard endpoint (dashURL).
//   - mTLS (preferred): set clientCert + serverCA; uses the mTLS endpoint (mtlsURL).
//     When mTLS is active, apiKey is ignored and requests go to the mTLS port.
type Client struct {
	dashURL string // dashboard base URL (bearer token path)
	mtlsURL string // mTLS server base URL (e.g. https://host:8443)
	apiKey  string // bearer token (empty when using mTLS)
	version string // binary version reported via X-Agent-Version header
	http    *http.Client
	useMTLS bool
}

// New returns a bearer-token client (legacy mode).
func New(baseURL, apiKey, version string) *Client {
	return &Client{
		dashURL: baseURL,
		apiKey:  apiKey,
		version: version,
		http:    &http.Client{Timeout: 30 * time.Second},
		useMTLS: false,
	}
}

// NewMTLS returns a client that authenticates with a client certificate.
// certFile and keyFile are paths to the PEM client cert and key written by the enroll command.
// caFile is the path to the CertForge client CA PEM (for server cert pinning on the mTLS port).
// dashURL is the dashboard base URL (for endpoints not yet on the mTLS server).
// mtlsURL is the base URL of the mTLS server (e.g. https://host:8443).
func NewMTLS(dashURL, mtlsURL, certFile, keyFile, caFile, version string) (*Client, error) {
	clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS12,
		// RootCAs is set only when a custom server CA is provided (self-hosted deployments
		// with a self-signed mTLS server cert). When empty, the system trust store is used
		// — this is the right default for SaaS deployments where the mTLS server presents
		// an ACME/Let's Encrypt cert that is already trusted by the OS.
	}
	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read server CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("server CA: no valid certs in %s", caFile)
		}
		tlsCfg.RootCAs = pool
	}

	transport := &http.Transport{TLSClientConfig: tlsCfg}
	return &Client{
		dashURL: dashURL,
		mtlsURL: mtlsURL,
		version: version,
		http:    &http.Client{Timeout: 30 * time.Second, Transport: transport},
		useMTLS: true,
	}, nil
}

// baseURL returns the appropriate base URL for the given path.
// Discovery API paths (/api/v1/discovery/...) go to the mTLS endpoint when active.
func (c *Client) baseURL(path string) string {
	if c.useMTLS && c.mtlsURL != "" {
		return c.mtlsURL
	}
	return c.dashURL
}

// Region is one entry from GET /api/v1/regions.
type Region struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	URL        string `json:"url"`
	ComingSoon bool   `json:"coming_soon"`
}

// ListRegions fetches available CertForge regions. No auth required.
func ListRegions(baseURL string) ([]Region, error) {
	hc := &http.Client{Timeout: 10 * time.Second}
	resp, err := hc.Get(baseURL + "/api/v1/regions")
	if err != nil {
		return nil, fmt.Errorf("fetch regions: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("regions: %s %s", resp.Status, b)
	}
	var out struct {
		Regions []Region `json:"regions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode regions: %w", err)
	}
	return out.Regions, nil
}

// ScanConfig is the work list returned by GET /api/v1/discovery/config.
type ScanConfig struct {
	Domains []DomainConfig `json:"domains"`
	Targets []TargetConfig `json:"targets"`
}

type DomainConfig struct {
	Domain    string `json:"domain"`
	ScanLocal bool   `json:"scan_local"`
}

type TargetConfig struct {
	Target string `json:"target"`
	Ports  string `json:"ports"`
}

// GetConfig fetches the scan work list for this org.
func (c *Client) GetConfig() (*ScanConfig, error) {
	var cfg ScanConfig
	if err := c.get("/api/v1/discovery/config", &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Cert is one discovered certificate sent to the ingest endpoint.
type Cert struct {
	Fingerprint  string     `json:"fingerprint"`
	Serial       string     `json:"serial"`
	Issuer       string     `json:"issuer"`
	Subject      string     `json:"subject"`
	SANs         string     `json:"sans"`
	Domain       string     `json:"domain"`
	NotBefore    *time.Time `json:"not_before"`
	NotAfter     *time.Time `json:"not_after"`
	Source       string     `json:"source"`        // ct_log | tls_scan | local | k8s
	SourceDetail string     `json:"source_detail"` // e.g. "10.0.0.1:443" or "default/my-tls-secret"
	SeenDeployed bool       `json:"seen_deployed"`
	ScanHosts    string     `json:"scan_hosts"`
	EKU          []string   `json:"eku"`
	IssuerType   string     `json:"issuer_type,omitempty"` // "internal_ca" when signed by a known internal CA
}

// IngestResult is the response from POST /api/v1/discovery/ingest.
type IngestResult struct {
	Ingested int `json:"ingested"`
	Errors   int `json:"errors"`
}

// Ingest posts a batch of discovered certs to CertForge.
func (c *Client) Ingest(certs []Cert) (*IngestResult, error) {
	body, err := json.Marshal(map[string]any{"certs": certs})
	if err != nil {
		return nil, err
	}
	var result IngestResult
	if err := c.post("/api/v1/discovery/ingest", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// StatsResult is the response from GET /api/v1/discovery/stats.
type StatsResult struct {
	DiscoveredCerts int    `json:"discovered_certs"`
	OrgID           string `json:"org_id"`
}

// GetStats returns the count of discovered certs stored for this org.
func (c *Client) GetStats() (*StatsResult, error) {
	var r StatsResult
	if err := c.get("/api/v1/discovery/stats", &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ClearCerts deletes all discovered certs stored for this org on CertForge.
func (c *Client) ClearCerts() error {
	return c.delete("/api/v1/discovery/certs")
}

// MarkDomainScanned reports scan completion for a domain so CertForge UI timestamps update.
func (c *Client) MarkDomainScanned(domain, status, scanErr string) error {
	body, _ := json.Marshal(map[string]string{
		"domain": domain,
		"status": status,
		"error":  scanErr,
	})
	return c.post("/api/v1/discovery/domains/scanned", body, nil)
}

func (c *Client) addAuth(req *http.Request) {
	if !c.useMTLS && c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	// mTLS: auth is the client cert presented at TLS layer — no header needed.
	if c.version != "" {
		req.Header.Set("X-Agent-Version", c.version)
	}
}

func (c *Client) delete(path string) error {
	req, err := http.NewRequest(http.MethodDelete, c.baseURL(path)+path, nil)
	if err != nil {
		return err
	}
	c.addAuth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("DELETE %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("DELETE %s: %s %s", path, resp.Status, b)
	}
	return nil
}

func (c *Client) get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL(path)+path, nil)
	if err != nil {
		return err
	}
	c.addAuth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GET %s: %s %s", path, resp.Status, b)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) post(path string, body []byte, out any) error {
	req, err := http.NewRequest(http.MethodPost, c.baseURL(path)+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.addAuth(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST %s: %s %s", path, resp.Status, b)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

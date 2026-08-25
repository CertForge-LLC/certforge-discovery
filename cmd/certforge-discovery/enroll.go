package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/certforge-llc/certforge-discovery/internal/config"
)

// cmdEnroll exchanges a one-time enrollment token for an mTLS client certificate.
// Usage: certforge-discovery enroll -token <otp> [-url <certforge-url>] [-config <path>] [-label <name>]
func cmdEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	token := fs.String("token", "", "one-time enrollment token from CertForge Settings (required)")
	certforgeURL := fs.String("url", defaultBaseURL, "CertForge URL")
	mtlsPort := fs.Int("mtls-port", 8443, "CertForge mTLS port")
	cfgPath := fs.String("config", config.DefaultPath(), "config file path to update after enrollment")
	label := fs.String("label", "discovery", "label for this agent in CertForge")
	_ = fs.Parse(args)

	if *token == "" {
		fmt.Fprintln(os.Stderr, "error: -token is required")
		fmt.Fprintln(os.Stderr, "  Generate one in CertForge → Settings → Agent Tokens")
		fmt.Fprintln(os.Stderr, "  then run: certforge-discovery enroll -token <otp>")
		os.Exit(1)
	}

	// Storage directory alongside the config file.
	storageDir := filepath.Dir(*cfgPath)
	if err := os.MkdirAll(storageDir, 0700); err != nil {
		log.Fatalf("create storage dir: %v", err)
	}

	certPath := filepath.Join(storageDir, "client.crt")
	keyPath := filepath.Join(storageDir, "client.key")
	caPath := filepath.Join(storageDir, "certforge-ca.crt")

	// 1. Generate a fresh ECDSA P-384 key pair.
	fmt.Println("Generating ECDSA P-384 key pair...")
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	// 2. Build a CSR.
	csrTmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("discovery:%s", *label),
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, privateKey)
	if err != nil {
		log.Fatalf("create CSR: %v", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	// 3. POST to /v1/agent/enroll on the mTLS port.
	// The endpoint is accessible without a client cert (it's the bootstrap point).
	// We use InsecureSkipVerify here only for the enrollment call because we don't
	// have the CA cert yet; the returned CA cert is saved and used for all future calls.
	enrollURL := buildMTLSURL(*certforgeURL, *mtlsPort) + "/v1/agent/enroll"
	fmt.Printf("Enrolling with CertForge at %s...\n", enrollURL)

	payload, _ := json.Marshal(map[string]string{
		"token":   *token,
		"csr_pem": csrPEM,
	})
	hc := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec — bootstrap only, CA pinned after
		},
	}
	resp, err := hc.Post(enrollURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Fatalf("enroll request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		log.Fatalf("enroll failed (%s): %s", resp.Status, b)
	}

	var result struct {
		CertPEM string `json:"cert_pem"`
		CAPEM   string `json:"ca_pem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Fatalf("decode response: %v", err)
	}
	if result.CertPEM == "" || result.CAPEM == "" {
		log.Fatalf("enrollment response missing cert_pem or ca_pem")
	}

	// 4. Persist key, cert, and CA cert.
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		log.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		log.Fatalf("write client key: %v", err)
	}
	if err := os.WriteFile(certPath, []byte(result.CertPEM), 0600); err != nil {
		log.Fatalf("write client cert: %v", err)
	}
	if err := os.WriteFile(caPath, []byte(result.CAPEM), 0600); err != nil {
		log.Fatalf("write CA cert: %v", err)
	}

	// Parse and show cert details.
	certBlock, _ := pem.Decode([]byte(result.CertPEM))
	cert, _ := x509.ParseCertificate(certBlock.Bytes)

	fmt.Println("\n✅ Enrollment successful!")
	fmt.Printf("   Client cert: %s\n", certPath)
	fmt.Printf("   Client key:  %s\n", keyPath)
	fmt.Printf("   CA cert:     %s\n", caPath)
	if cert != nil {
		fmt.Printf("   Valid until: %s\n", cert.NotAfter.Format("2006-01-02"))
		fmt.Printf("   CN:          %s\n", cert.Subject.CommonName)
	}

	// 5. Update the config file if it exists.
	cfg, loadErr := config.Load(*cfgPath)
	if loadErr != nil {
		// Config doesn't exist yet — create a minimal one.
		cfg = &config.Config{
			CertForgeURL: *certforgeURL,
			MTLSPort:     *mtlsPort,
		}
	}
	cfg.ClientCertFile = certPath
	cfg.ClientKeyFile = keyPath
	cfg.ServerCAFile = caPath
	cfg.MTLSPort = *mtlsPort
	// Keep api_key if it was set — it's used as a fallback until all endpoints migrate.
	if err := config.Save(*cfgPath, cfg); err != nil {
		fmt.Printf("   Warning: could not update config: %v\n", err)
		fmt.Println("   Add these lines to your config manually:")
		fmt.Printf("     client_cert: %s\n", certPath)
		fmt.Printf("     client_key:  %s\n", keyPath)
		fmt.Printf("     server_ca:   %s\n", caPath)
	} else {
		fmt.Printf("   Config updated: %s\n", *cfgPath)
	}
	fmt.Println("\nThe agent will now use mTLS for all CertForge communication.")
	fmt.Println("Your api_key is no longer required and can be removed from the config.")
}

func buildMTLSURL(baseURL string, port int) string {
	// Strip existing port if present, add mTLS port.
	for _, pfx := range []string{"https://", "http://"} {
		if len(baseURL) > len(pfx) && baseURL[:len(pfx)] == pfx {
			host := baseURL[len(pfx):]
			// Remove any existing port.
			for i := len(host) - 1; i >= 0; i-- {
				if host[i] == ':' {
					host = host[:i]
					break
				}
			}
			return fmt.Sprintf("https://%s:%d", host, port)
		}
	}
	return fmt.Sprintf("https://%s:%d", baseURL, port)
}

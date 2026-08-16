package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// InternalCAConfig identifies a private CA cert so discovered certs can be
// classified as internal vs external.
type InternalCAConfig struct {
	Cert  string `yaml:"cert"`  // path to PEM CA certificate
	Label string `yaml:"label"` // optional friendly name shown in CertForge
}

// Config is loaded from the config file (default: ~/.certforge-discovery/config.yaml).
type Config struct {
	CertForgeURL     string             `yaml:"certforge_url"`     // e.g. https://app.certgovernance.app
	APIKey           string             `yaml:"api_key"`           // bearer token from CertForge Settings → API Keys
	PollInterval     time.Duration      `yaml:"poll_interval"`     // how often agent re-scans; default 6h
	ScanLocal        bool               `yaml:"scan_local"`        // scan local filesystem for cert files
	StoragePaths     []string           `yaml:"storage_paths"`     // additional filesystem paths to scan
	ScanK8s          bool               `yaml:"scan_k8s"`           // scan Kubernetes TLS secrets
	KubeConfig       string             `yaml:"kubeconfig"`         // path to kubeconfig; empty = in-cluster
	K8sNamespaces    []string           `yaml:"k8s_namespaces"`     // namespaces to scan; empty = all (requires cluster-wide Secret list)
	KnownInternalCAs []InternalCAConfig `yaml:"known_internal_cas"` // optional: classify certs signed by these CAs
}

// DefaultPath returns the default config file path.
func DefaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".certforge-discovery", "config.yaml")
}

// Load reads and parses a config file, expanding environment variables.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	data = []byte(os.ExpandEnv(string(data)))

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.CertForgeURL == "" {
		return nil, fmt.Errorf("certforge_url is required")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("api_key is required")
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 6 * time.Hour
	}
	return &cfg, nil
}

// Save writes cfg to path, creating the directory if needed.
func Save(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

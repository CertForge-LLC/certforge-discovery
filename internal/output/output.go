package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/certforge-llc/certforge-discovery/internal/client"
)

// Write writes certs to w in the format determined by filename extension.
// ".csv" → CSV, ".json" → JSON, anything else → table.
func Write(w io.Writer, filename string, certs []client.Cert) error {
	switch strings.ToLower(filepath.Ext(filename)) {
	case ".csv":
		return writeCSV(w, certs)
	case ".json":
		return writeJSON(w, certs)
	default:
		return writeTable(w, certs)
	}
}

// ToFile writes certs to the named file, creating it if needed.
// Format is inferred from the file extension.
func ToFile(filename string, certs []client.Cert) error {
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("create %s: %w", filename, err)
	}
	defer f.Close()
	return Write(f, filename, certs)
}

// Table writes a formatted table to stdout.
func Table(certs []client.Cert) error {
	return writeTable(os.Stdout, certs)
}

func writeTable(w io.Writer, certs []client.Cert) error {
	if len(certs) == 0 {
		fmt.Fprintln(w, "No certificates found.")
		return nil
	}

	// Column widths.
	const (
		wSubject = 40
		wIssuer  = 28
		wExpiry  = 12
		wSource  = 10
		wStatus  = 10
	)

	header := fmt.Sprintf("%-*s  %-*s  %-*s  %-*s  %-*s",
		wSubject, "SUBJECT",
		wIssuer, "ISSUER",
		wExpiry, "EXPIRES",
		wSource, "SOURCE",
		wStatus, "STATUS",
	)
	fmt.Fprintln(w, header)
	fmt.Fprintln(w, strings.Repeat("─", len(header)))

	now := time.Now()
	for _, c := range certs {
		expiry := "unknown"
		status := "ok"
		if c.NotAfter != nil {
			expiry = c.NotAfter.Format("2006-01-02")
			days := int(time.Until(*c.NotAfter).Hours() / 24)
			switch {
			case days < 0:
				status = "EXPIRED"
			case days < 14:
				status = fmt.Sprintf("exp %dd", days)
			case days < 30:
				status = fmt.Sprintf("exp %dd", days)
			}
			_ = now
		}

		subject := truncate(c.Subject, wSubject)
		issuer := truncate(shortIssuer(c.Issuer), wIssuer)

		fmt.Fprintf(w, "%-*s  %-*s  %-*s  %-*s  %-*s\n",
			wSubject, subject,
			wIssuer, issuer,
			wExpiry, expiry,
			wSource, c.Source,
			wStatus, status,
		)
	}

	// Summary line.
	expired, expiring14, expiring30 := 0, 0, 0
	for _, c := range certs {
		if c.NotAfter == nil {
			continue
		}
		days := int(time.Until(*c.NotAfter).Hours() / 24)
		switch {
		case days < 0:
			expired++
		case days < 14:
			expiring14++
		case days < 30:
			expiring30++
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%d certificate(s) found", len(certs))
	if expired > 0 {
		fmt.Fprintf(w, "  •  %d expired", expired)
	}
	if expiring14 > 0 {
		fmt.Fprintf(w, "  •  %d expiring within 14 days", expiring14)
	} else if expiring30 > 0 {
		fmt.Fprintf(w, "  •  %d expiring within 30 days", expiring30)
	}
	fmt.Fprintln(w)
	return nil
}

func writeCSV(w io.Writer, certs []client.Cert) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"Subject", "SANs", "Issuer", "Serial",
		"Not Before", "Not After", "Days Until Expiry",
		"Source", "Source Detail", "Seen Deployed", "EKU", "Fingerprint",
	})
	now := time.Now()
	for _, c := range certs {
		notBefore, notAfter, daysLeft := "", "", ""
		if c.NotBefore != nil {
			notBefore = c.NotBefore.Format(time.RFC3339)
		}
		if c.NotAfter != nil {
			notAfter = c.NotAfter.Format(time.RFC3339)
			daysLeft = fmt.Sprintf("%d", int(c.NotAfter.Sub(now).Hours()/24))
		}
		deployed := "false"
		if c.SeenDeployed {
			deployed = "true"
		}
		_ = cw.Write([]string{
			c.Subject, c.SANs, c.Issuer, c.Serial,
			notBefore, notAfter, daysLeft,
			c.Source, c.SourceDetail, deployed,
			strings.Join(c.EKU, ";"), c.Fingerprint,
		})
	}
	cw.Flush()
	return cw.Error()
}

func writeJSON(w io.Writer, certs []client.Cert) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{
		"generated_at":  time.Now().UTC().Format(time.RFC3339),
		"count":         len(certs),
		"certificates":  certs,
	})
}

func shortIssuer(issuer string) string {
	// Strip common verbose prefixes so the table stays readable.
	for _, prefix := range []string{
		"Let's Encrypt ", "DigiCert ", "Sectigo ", "GlobalSign ",
		"Amazon ", "Google Trust Services ", "ZeroSSL ",
	} {
		if strings.HasPrefix(issuer, prefix) {
			return issuer
		}
	}
	return issuer
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

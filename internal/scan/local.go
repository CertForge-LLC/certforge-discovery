package scan

import (
	"crypto/x509"
	"encoding/pem"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/certforge-llc/certforge-discovery/internal/client"
)

var defaultPaths = []string{
	"/etc/ssl/certs",
	"/etc/ssl/private",
	"/etc/nginx/ssl",
	"/etc/nginx/certs",
	"/etc/apache2/ssl",
	"/etc/httpd/ssl",
	"/etc/letsencrypt/live",
	"/etc/letsencrypt/archive",
	"/etc/pki/tls/certs",
}

// ScanLocalFS walks well-known certificate directories (plus any extra paths)
// and returns all non-expired leaf certificates found.
// knownCAs is optional: when non-empty, certs signed by those CAs are tagged IssuerType="internal_ca".
func ScanLocalFS(extraPaths []string, knownCAs []*x509.Certificate) []client.Cert {
	paths := append(defaultPaths, extraPaths...)
	var certs []client.Cert
	for _, root := range paths {
		_ = filepath.WalkDir(root, func(path string, info fs.DirEntry, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".crt" && ext != ".pem" && ext != ".cer" {
				return nil
			}
			certs = append(certs, parseLocalCerts(path, knownCAs)...)
			return nil
		})
	}
	return certs
}

func parseLocalCerts(path string, knownCAs []*x509.Certificate) []client.Cert {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var certs []client.Cert
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || cert.IsCA || cert.NotAfter.Before(time.Now()) {
			continue
		}
		nb := cert.NotBefore
		na := cert.NotAfter
		certs = append(certs, client.Cert{
			Fingerprint:  certFingerprint(cert),
			Serial:       cert.SerialNumber.String(),
			Issuer:       certIssuerName(cert),
			Subject:      cert.Subject.CommonName,
			SANs:         sanList(cert),
			NotBefore:    &nb,
			NotAfter:     &na,
			Source:       "local",
			SourceDetail: path,
			EKU:          ekuStrings(cert),
			IssuerType:   issuerTypeFor(cert, knownCAs),
		})
	}
	if len(certs) > 0 {
		log.Printf("[local] %s: found %d cert(s)", path, len(certs))
	}
	return certs
}

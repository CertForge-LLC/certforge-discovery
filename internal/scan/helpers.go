package scan

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"
)

// LoadKnownCAs reads CA certificates from disk. Non-CA or unreadable files are
// logged and skipped so a bad path doesn't abort the scan.
func LoadKnownCAs(certFiles []string) []*x509.Certificate {
	var cas []*x509.Certificate
	for _, path := range certFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[discovery] known_ca: read %s: %v", path, err)
			continue
		}
		block, _ := pem.Decode(data)
		if block == nil {
			log.Printf("[discovery] known_ca: no PEM block in %s", path)
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Printf("[discovery] known_ca: parse %s: %v", path, err)
			continue
		}
		if !cert.IsCA {
			log.Printf("[discovery] known_ca: %s is not a CA cert — skipping", path)
			continue
		}
		cas = append(cas, cert)
		log.Printf("[discovery] known_ca: loaded %s (subject: %s)", path, cert.Subject.CommonName)
	}
	return cas
}

// issuerTypeFor returns "internal_ca" when cert was signed by one of the known CAs,
// using cryptographic verification for full x509.Certificate objects or subject-string
// matching for CT log entries where we have the issuer name but not the raw cert.
func issuerTypeFor(cert *x509.Certificate, knownCAs []*x509.Certificate) string {
	if len(knownCAs) == 0 {
		return ""
	}
	for _, ca := range knownCAs {
		if cert.CheckSignatureFrom(ca) == nil {
			return "internal_ca"
		}
	}
	return ""
}

// issuerTypeFromName returns "internal_ca" when the issuer name string matches
// any known CA's subject. Used for CT log entries where we don't have the raw cert.
func issuerTypeFromName(issuerName string, knownCAs []*x509.Certificate) string {
	if len(knownCAs) == 0 {
		return ""
	}
	for _, ca := range knownCAs {
		if ca.Subject.CommonName != "" && strings.Contains(issuerName, ca.Subject.CommonName) {
			return "internal_ca"
		}
	}
	return ""
}

func certFingerprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", h)
}

func certIssuerName(cert *x509.Certificate) string {
	cn := cert.Issuer.CommonName
	if len(cert.Issuer.Organization) > 0 {
		org := cert.Issuer.Organization[0]
		if org != "" && org != cn {
			return org + " " + cn
		}
	}
	return cn
}

func sanList(cert *x509.Certificate) string {
	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	return strings.Join(sans, ", ")
}

func ekuStrings(cert *x509.Certificate) []string {
	var out []string
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			out = append(out, "serverAuth")
		case x509.ExtKeyUsageClientAuth:
			out = append(out, "clientAuth")
		case x509.ExtKeyUsageCodeSigning:
			out = append(out, "codeSigning")
		case x509.ExtKeyUsageEmailProtection:
			out = append(out, "emailProtection")
		case x509.ExtKeyUsageTimeStamping:
			out = append(out, "timeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			out = append(out, "OCSPSigning")
		}
	}
	return out
}

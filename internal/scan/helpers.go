package scan

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"
)

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

package scan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"strings"
	"time"

	"github.com/certforge-llc/certforge-discovery/internal/client"
)

// ScanTLSTarget connects to each host:port derived from target and returns
// the leaf certificates presented. Handles single hostnames, IPs, and CIDR ranges.
// knownCAs is optional: when non-empty, certs signed by those CAs are tagged IssuerType="internal_ca".
func ScanTLSTarget(ctx context.Context, target, ports string, knownCAs []*x509.Certificate) []client.Cert {
	portList := parsePorts(ports)
	if len(portList) == 0 {
		portList = []string{"443"}
	}

	hosts, err := expandTarget(target)
	if err != nil {
		log.Printf("[tls] expand %q: %v", target, err)
		return nil
	}

	total := len(hosts)
	if total > 1 {
		log.Printf("[tls] %s: probing %d host(s) on port(s) %s", target, total, ports)
	}

	var certs []client.Cert
	for i, host := range hosts {
		if ctx.Err() != nil {
			return certs
		}
		for _, port := range portList {
			c := probeTLS(ctx, host, port, knownCAs)
			certs = append(certs, c...)
		}
		// Print progress every 16 hosts so a /24 gets ~16 updates without flooding.
		if total > 16 && (i+1)%16 == 0 {
			log.Printf("[tls] %s: %d/%d hosts probed, %d cert(s) found so far", target, i+1, total, len(certs))
		}
	}

	if total > 1 {
		log.Printf("[tls] %s: done — %d cert(s) found", target, len(certs))
	}
	return certs
}

func probeTLS(ctx context.Context, host, port string, knownCAs []*x509.Certificate) []client.Cert {
	timeout := 2 * time.Second
	if net.ParseIP(host) == nil {
		timeout = 10 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(host, port)
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{ //nolint:gosec
			InsecureSkipVerify: true, // intentional — discovering unknown/self-signed certs
			ServerName:         host,
		},
	}
	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		if net.ParseIP(host) == nil {
			log.Printf("[tls] %s: %v", addr, err)
		}
		return nil
	}
	defer conn.Close()

	var certs []client.Cert
	for _, cert := range conn.(*tls.Conn).ConnectionState().PeerCertificates {
		if cert.IsCA || cert.NotAfter.Before(time.Now()) {
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
			Domain:       host,
			NotBefore:    &nb,
			NotAfter:     &na,
			Source:       "tls_scan",
			SourceDetail: addr,
			SeenDeployed: true,
			ScanHosts:    addr,
			EKU:          ekuStrings(cert),
			IssuerType:   issuerTypeFor(cert, knownCAs),
		})
	}
	return certs
}

func expandTarget(target string) ([]string, error) {
	if strings.Contains(target, "/") {
		return expandCIDR(target)
	}
	return []string{target}, nil
}

func expandCIDR(cidr string) ([]string, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ones, bits := network.Mask.Size()
	if bits-ones > 16 {
		return nil, nil // too large — skip silently
	}
	var hosts []string
	for ip = ip.Mask(network.Mask); network.Contains(ip); incrementIP(ip) {
		if ip[len(ip)-1] == 0 || ip[len(ip)-1] == 255 {
			continue
		}
		hosts = append(hosts, ip.String())
	}
	return hosts, nil
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func parsePorts(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

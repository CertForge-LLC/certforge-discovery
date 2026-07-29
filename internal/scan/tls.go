package scan

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"strings"
	"time"

	"github.com/certforge-llc/certforge-discovery/internal/client"
)

// ScanTLSTarget connects to each host:port derived from target and returns
// the leaf certificates presented. Handles single hostnames, IPs, and CIDR ranges.
func ScanTLSTarget(ctx context.Context, target, ports string) []client.Cert {
	portList := parsePorts(ports)
	if len(portList) == 0 {
		portList = []string{"443"}
	}

	hosts, err := expandTarget(target)
	if err != nil {
		log.Printf("[tls] expand %q: %v", target, err)
		return nil
	}

	var certs []client.Cert
	for _, host := range hosts {
		for _, port := range portList {
			if ctx.Err() != nil {
				return certs
			}
			c := probeTLS(ctx, host, port, target)
			certs = append(certs, c...)
		}
	}
	return certs
}

func probeTLS(ctx context.Context, host, port, domain string) []client.Cert {
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
			Domain:       domain,
			NotBefore:    &nb,
			NotAfter:     &na,
			Source:       "tls_scan",
			SourceDetail: addr,
			SeenDeployed: true,
			ScanHosts:    addr,
			EKU:          ekuStrings(cert),
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

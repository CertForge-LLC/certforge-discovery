package scan

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"log"
	"time"

	"github.com/certforge-llc/certforge-discovery/internal/client"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ScanK8sSecrets finds kubernetes.io/tls secrets and returns the leaf
// certificates stored in them.
//
// kubeconfig may be empty to use in-cluster config.
// namespaces restricts the scan to the listed namespaces; pass nil or an empty
// slice to scan all namespaces (requires cluster-wide Secret list permission).
// knownCAs is optional: when non-empty, certs signed by those CAs are tagged IssuerType="internal_ca".
func ScanK8sSecrets(ctx context.Context, kubeconfig string, namespaces []string, knownCAs []*x509.Certificate) ([]client.Cert, error) {
	var restCfg *rest.Config
	var err error
	if kubeconfig != "" {
		restCfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		restCfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}

	cs, err := k8sclient.NewForConfig(restCfg)
	if err != nil {
		return nil, err
	}

	listOpts := metav1.ListOptions{FieldSelector: "type=kubernetes.io/tls"}

	var secretItems []secretItem
	if len(namespaces) == 0 {
		// No filter — list across all namespaces.
		list, err := cs.CoreV1().Secrets("").List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for _, s := range list.Items {
			secretItems = append(secretItems, secretItem{ns: s.Namespace, name: s.Name, data: s.Data})
		}
	} else {
		// Namespace-filtered — list each namespace independently.
		for _, ns := range namespaces {
			list, err := cs.CoreV1().Secrets(ns).List(ctx, listOpts)
			if err != nil {
				log.Printf("[k8s] namespace %s: %v", ns, err)
				continue
			}
			for _, s := range list.Items {
				secretItems = append(secretItems, secretItem{ns: s.Namespace, name: s.Name, data: s.Data})
			}
		}
	}

	log.Printf("[k8s] found %d TLS secrets", len(secretItems))

	var certs []client.Cert
	for _, s := range secretItems {
		certPEM, ok := s.data["tls.crt"]
		if !ok {
			continue
		}
		ref := s.ns + "/" + s.name
		certs = append(certs, parseK8sCert(certPEM, ref, knownCAs)...)
	}
	return certs, nil
}

// secretItem is a minimal representation of a TLS secret to avoid holding
// the full Kubernetes API object after the list call.
type secretItem struct {
	ns, name string
	data     map[string][]byte
}

func parseK8sCert(certPEM []byte, ref string, knownCAs []*x509.Certificate) []client.Cert {
	var certs []client.Cert
	for {
		block, rest := pem.Decode(certPEM)
		if block == nil {
			break
		}
		certPEM = rest
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
			Source:       "k8s",
			SourceDetail: ref,
			EKU:          ekuStrings(cert),
			IssuerType:   issuerTypeFor(cert, knownCAs),
		})
	}
	return certs
}

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

// ScanK8sSecrets finds all kubernetes.io/tls secrets across all namespaces
// and returns the leaf certificates stored in them.
// kubeconfig may be empty to use in-cluster config.
func ScanK8sSecrets(ctx context.Context, kubeconfig string) ([]client.Cert, error) {
	var cfg *rest.Config
	var err error
	if kubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}

	cs, err := k8sclient.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	secrets, err := cs.CoreV1().Secrets("").List(ctx, metav1.ListOptions{
		FieldSelector: "type=kubernetes.io/tls",
	})
	if err != nil {
		return nil, err
	}

	log.Printf("[k8s] found %d TLS secrets", len(secrets.Items))

	var certs []client.Cert
	for _, secret := range secrets.Items {
		certPEM, ok := secret.Data["tls.crt"]
		if !ok {
			continue
		}
		ref := secret.Namespace + "/" + secret.Name
		certs = append(certs, parseK8sCert(certPEM, ref)...)
	}
	return certs, nil
}

func parseK8sCert(certPEM []byte, ref string) []client.Cert {
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
		})
	}
	return certs
}

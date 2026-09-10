package scan

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"log"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/certforge-llc/certforge-discovery/internal/client"
)

// ScanWindowsLocal discovers certificates on a Windows host by querying:
//   - Windows Certificate Store (LocalMachine\My)
//   - IIS HTTPS bindings (via WebAdministration PowerShell module)
//   - RDP listener certificate (via WMI)
//   - netsh http SSL certificate bindings
//
// Returns nil on non-Windows platforms.
//
// The -local flag activates this scan. On Windows it runs instead of (and in
// addition to) the Linux filesystem walk, which will find nothing on Windows
// since the standard Linux cert paths do not exist.
func ScanWindowsLocal(knownCAs []*x509.Certificate) []client.Cert {
	if runtime.GOOS != "windows" {
		return nil
	}
	log.Printf("[windows] starting local certificate scan")

	// Step 1 — enumerate LocalMachine\My cert store (raw DER → parsed x509)
	storeCerts := enumCertStore()
	log.Printf("[windows] cert store: %d certificate(s) found", len(storeCerts))

	// Step 2 — IIS HTTPS bindings: thumbprint (upper) → ["Site :port", ...]
	iisBindings := enumIISBindings()
	log.Printf("[windows] IIS: %d binding(s)", len(iisBindings))

	// Step 3 — RDP listener cert thumbprint (empty or all-zeros when no custom cert configured)
	rdpThumb := strings.ToUpper(strings.TrimSpace(enumRDPCert()))
	// All-zeros thumbprint means Windows is using its auto-generated self-signed cert
	// for RDP — not a real custom cert, so ignore it.
	if rdpThumb == "0000000000000000000000000000000000000000" {
		rdpThumb = ""
	}
	if rdpThumb != "" {
		log.Printf("[windows] RDP: cert thumbprint %s", rdpThumb)
	} else {
		log.Printf("[windows] RDP: no custom cert (default self-signed)")
	}

	// Step 4 — netsh http SSL bindings: thumbprint (upper) → ["ip:port", ...]
	netshBindings := enumNetshBindings()
	log.Printf("[windows] netsh: %d binding(s)", len(netshBindings))

	// Step 5 — build Cert records, annotating with binding metadata
	var certs []client.Cert
	for _, sc := range storeCerts {
		// Skip CA certs and expired certs.
		if sc.cert.IsCA || sc.cert.NotAfter.Before(time.Now()) {
			continue
		}

		thumb := strings.ToUpper(sc.thumbprint)
		var bindings []string
		deployed := false

		if sites, ok := iisBindings[thumb]; ok {
			bindings = append(bindings, "IIS: "+strings.Join(sites, ", "))
			deployed = true
		}
		if rdpThumb != "" && thumb == rdpThumb {
			bindings = append(bindings, "RDP listener")
			deployed = true
		}
		if ports, ok := netshBindings[thumb]; ok {
			bindings = append(bindings, "netsh: "+strings.Join(ports, ", "))
			deployed = true
		}

		sourceDetail := `Windows Cert Store (LocalMachine\My)`
		if len(bindings) > 0 {
			sourceDetail = strings.Join(bindings, "; ")
		}

		fp := certFingerprint(sc.cert)
		nb := sc.cert.NotBefore
		na := sc.cert.NotAfter

		certs = append(certs, client.Cert{
			Fingerprint:  fp,
			Serial:       sc.cert.SerialNumber.String(),
			Issuer:       certIssuerName(sc.cert),
			Subject:      sc.cert.Subject.CommonName,
			SANs:         sanList(sc.cert),
			Domain:       sc.cert.Subject.CommonName,
			NotBefore:    &nb,
			NotAfter:     &na,
			Source:       "windows_local",
			SourceDetail: sourceDetail,
			SeenDeployed: deployed,
			EKU:          ekuStrings(sc.cert),
			IssuerType:   issuerTypeFor(sc.cert, knownCAs),
		})
	}

	log.Printf("[windows] scan complete — %d certificate(s) returned", len(certs))
	return certs
}

// ── cert store ────────────────────────────────────────────────────────────────

// storeCert pairs a Windows thumbprint with its parsed x509 certificate.
type storeCert struct {
	thumbprint string
	cert       *x509.Certificate
}

// enumCertStore enumerates the LocalMachine\My store via PowerShell, returning
// the raw DER so we can parse SANs and other extensions that PowerShell omits.
func enumCertStore() []storeCert {
	ps := `Get-ChildItem Cert:\LocalMachine\My |` +
		` ForEach-Object {` +
		`   [PSCustomObject]@{` +
		`     Thumbprint = [string]$_.Thumbprint;` +
		`     RawData    = [Convert]::ToBase64String($_.RawData)` +
		`   }` +
		` } | ConvertTo-Json -Compress -Depth 2`

	out, err := runPS(ps)
	if err != nil || strings.TrimSpace(out) == "" {
		if err != nil {
			log.Printf("[windows] cert store enum: %v", err)
		}
		return nil
	}

	// PowerShell emits a bare object (not an array) when exactly one cert exists.
	out = strings.TrimSpace(out)
	if !strings.HasPrefix(out, "[") {
		out = "[" + out + "]"
	}

	var rows []struct {
		Thumbprint string `json:"Thumbprint"`
		RawData    string `json:"RawData"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		log.Printf("[windows] cert store parse error: %v (output: %.200s)", err, out)
		return nil
	}

	var result []storeCert
	for _, r := range rows {
		der, err := base64.StdEncoding.DecodeString(r.RawData)
		if err != nil {
			log.Printf("[windows] cert store: base64 decode error for %s: %v", r.Thumbprint, err)
			continue
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			// "negative serial number" is common for legacy Microsoft root/intermediate CAs
			// that predate strict ASN.1 encoding — skip them silently, they are CA certs.
			if strings.Contains(err.Error(), "negative serial") {
				log.Printf("[windows] cert store: skipping %s (legacy CA cert with non-standard serial)", r.Thumbprint)
			} else {
				log.Printf("[windows] cert store: parse error for %s: %v", r.Thumbprint, err)
			}
			continue
		}
		result = append(result, storeCert{thumbprint: r.Thumbprint, cert: cert})
	}
	return result
}

// ── IIS bindings ──────────────────────────────────────────────────────────────

// enumIISBindings returns a map of thumbprint (uppercase) → []"SiteName :port".
// Returns nil when the WebAdministration module is unavailable (IIS not installed).
func enumIISBindings() map[string][]string {
	ps := `$ErrorActionPreference = 'SilentlyContinue';` +
		` Import-Module WebAdministration;` +
		` Get-WebBinding |` +
		` Where-Object { $_.protocol -eq 'https' -and $_.certificateHash -ne '' } |` +
		` ForEach-Object {` +
		`   $site = ($_.ItemXPath -replace ".*@name='([^']+)'.*", '$1');` +
		`   $port = ($_.bindingInformation -split ':')[1];` +
		`   [PSCustomObject]@{ Hash=$_.certificateHash.ToUpper(); Site=$site; Port=$port }` +
		` } | ConvertTo-Json -Compress -Depth 2`

	out, err := runPS(ps)
	if err != nil || strings.TrimSpace(out) == "" {
		return nil
	}
	out = strings.TrimSpace(out)
	if !strings.HasPrefix(out, "[") {
		out = "[" + out + "]"
	}

	var rows []struct {
		Hash string `json:"Hash"`
		Site string `json:"Site"`
		Port string `json:"Port"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		log.Printf("[windows] IIS bindings parse error: %v", err)
		return nil
	}

	result := make(map[string][]string)
	for _, r := range rows {
		if r.Hash == "" {
			continue
		}
		label := r.Site
		if r.Port != "" {
			label += " :" + r.Port
		}
		result[r.Hash] = append(result[r.Hash], label)
	}
	return result
}

// ── RDP listener ──────────────────────────────────────────────────────────────

// enumRDPCert returns the SHA1 thumbprint of the RDP listener certificate,
// or an empty string when the default self-signed cert is in use or WMI is unavailable.
func enumRDPCert() string {
	ps := `$ts = Get-WmiObject -Namespace root\cimv2\TerminalServices` +
		` -Class Win32_TSGeneralSetting -ErrorAction SilentlyContinue;` +
		` if ($ts) { $ts.SSLCertificateSHA1Hash }`
	out, err := runPS(ps)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// ── netsh SSL bindings ────────────────────────────────────────────────────────

// enumNetshBindings returns a map of thumbprint (uppercase) → []"ip:port".
// Parses the text output of `netsh http show sslcert`.
func enumNetshBindings() map[string][]string {
	out, err := runCmd("netsh", "http", "show", "sslcert")
	if err != nil || strings.TrimSpace(out) == "" {
		return nil
	}

	// netsh output format (relevant lines):
	//
	//   IP:port                      : 0.0.0.0:443
	//   Certificate Hash             : aabbccdd...
	//
	//   Hostname:port                : server.example.com:8443
	//   Certificate Hash             : eeff1122...
	//
	// Key: split on " : " (with surrounding spaces) to separate label from value.

	result := make(map[string][]string)
	var currentEndpoint string

	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		// Find " : " separator — value follows.
		sep := strings.Index(line, " : ")
		if sep < 0 {
			continue
		}
		key := strings.TrimSpace(line[:sep])
		val := strings.TrimSpace(line[sep+3:])

		switch {
		case key == "IP:port" || key == "Hostname:port":
			currentEndpoint = val
		case key == "Certificate Hash" && currentEndpoint != "":
			thumb := strings.ToUpper(strings.ReplaceAll(val, " ", ""))
			if thumb != "" {
				result[thumb] = append(result[thumb], currentEndpoint)
			}
			// Don't reset currentEndpoint — multiple hashes per endpoint is
			// not standard but harmless to handle correctly.
		}
	}
	return result
}

// ── helpers ───────────────────────────────────────────────────────────────────

// runPS executes a PowerShell command and returns stdout.
// Uses -NoProfile and -NonInteractive to avoid startup overhead and prompts.
func runPS(command string) (string, error) {
	out, err := exec.Command(
		"powershell.exe",
		"-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", command,
	).Output()
	return string(out), err
}

// runCmd executes an arbitrary command and returns stdout.
func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return string(out), err
}

package analyze

import (
	"fmt"
	"strings"
	"time"
)

func (a *analyzer) tls() {
	if a.result.TLS == nil {
		a.add(Finding{
			ID: "no-tls", Title: "Served over plaintext HTTP",
			Severity: Critical, Category: CategoryTLS, Points: 30,
			Expected: "HTTPS",
			Detail: "Everything on the connection, including cookies and credentials, is readable " +
				"and modifiable in transit. No header can compensate for this.",
			Fix:       "Terminate TLS and redirect http:// to https://",
			Reference: "https://letsencrypt.org/getting-started/",
		})
		return
	}

	t := a.result.TLS

	// --- negotiated version ---
	switch t.Version {
	case "TLS 1.3":
		a.add(Finding{
			ID: "tls-version", Title: "Negotiated TLS 1.3",
			Severity: Info, Category: CategoryTLS, Points: -2, Observed: t.Version,
		})
	case "TLS 1.2":
		a.add(Finding{
			ID: "tls-version", Title: "Negotiated TLS 1.2",
			Severity: Info, Category: CategoryTLS, Points: 0, Observed: t.Version,
			Detail: "Acceptable. TLS 1.3 is faster and removes the legacy constructions that most " +
				"TLS attacks target.",
		})
	default:
		a.add(Finding{
			ID: "tls-version-obsolete", Title: "Negotiated an obsolete TLS version",
			Severity: Critical, Category: CategoryTLS, Points: 25,
			Observed: t.Version, Expected: "TLS 1.2 or 1.3",
			Detail: "TLS 1.0 and 1.1 are deprecated and unsupported by current browsers; they rely " +
				"on constructions with known weaknesses.",
			Fix: "Set the minimum protocol version to TLS 1.2",
		})
	}

	// --- lowest version the server will still accept ---
	switch t.MinVersionOffered {
	case "TLS 1.0", "TLS 1.1":
		a.add(Finding{
			ID: "tls-legacy-enabled", Title: "Server still accepts " + t.MinVersionOffered,
			Severity: High, Category: CategoryTLS, Points: 12,
			Observed: "lowest accepted: " + t.MinVersionOffered, Expected: "TLS 1.2 minimum",
			Detail: "A modern browser negotiates " + t.Version + ", but an attacker who can influence " +
				"the handshake can still reach the deprecated version. Disabling it is the fix.",
			Fix: "ssl_protocols TLSv1.2 TLSv1.3;  # nginx",
		})
	case "TLS 1.2", "TLS 1.3":
		a.add(Finding{
			ID: "tls-legacy-disabled", Title: "Obsolete TLS versions are disabled",
			Severity: Info, Category: CategoryTLS, Points: 0,
			Observed: "lowest accepted: " + t.MinVersionOffered,
		})
	}

	// --- certificate expiry ---
	left := t.ExpiresIn(a.now)
	switch {
	case left <= 0:
		a.add(Finding{
			ID: "cert-expired", Title: "Certificate has expired",
			Severity: Critical, Category: CategoryTLS, Points: 30,
			Observed: "expired " + t.NotAfter.UTC().Format(time.RFC3339),
			Detail:   "Browsers show a full-page interstitial; the site is effectively down.",
			Fix:      "Renew the certificate and fix whatever automation was supposed to",
		})
	case left < 7*24*time.Hour:
		a.add(Finding{
			ID: "cert-expiring", Title: "Certificate expires within a week",
			Severity: High, Category: CategoryTLS, Points: 12,
			Observed: fmt.Sprintf("%.1f days left (%s)", left.Hours()/24, t.NotAfter.UTC().Format("2006-01-02")),
			Detail:   "Renewal automation has either failed or is not configured.",
			Fix:      "Renew now and add an expiry alert",
		})
	case left < 21*24*time.Hour:
		a.add(Finding{
			ID: "cert-expiring-soon", Title: "Certificate expires within three weeks",
			Severity: Low, Category: CategoryTLS, Points: 3,
			Observed: fmt.Sprintf("%.0f days left", left.Hours()/24),
			Detail:   "Fine if renewal is automated; worth checking that it is.",
		})
	default:
		a.add(Finding{
			ID: "cert-validity", Title: "Certificate is valid",
			Severity: Info, Category: CategoryTLS, Points: 0,
			Observed: fmt.Sprintf("%.0f days left, issued by %s", left.Hours()/24, t.Issuer),
		})
	}

	// --- signature algorithm ---
	if algo := strings.ToUpper(t.SignatureAlgo); strings.Contains(algo, "SHA1") || strings.Contains(algo, "MD5") {
		a.add(Finding{
			ID: "cert-weak-signature", Title: "Certificate uses a broken signature algorithm",
			Severity: Critical, Category: CategoryTLS, Points: 20,
			Observed: t.SignatureAlgo, Expected: "SHA-256 or better",
			Detail: "SHA-1 and MD5 are collision-vulnerable, so a forged certificate is feasible. " +
				"Browsers reject these outright.",
			Fix: "Reissue the certificate with a SHA-256 signature",
		})
	}

	// --- cipher suite ---
	if cs := strings.ToUpper(t.CipherSuite); strings.Contains(cs, "RC4") ||
		strings.Contains(cs, "3DES") || strings.Contains(cs, "_CBC_") || strings.Contains(cs, "NULL") {
		sev, points := Medium, 6
		if strings.Contains(cs, "RC4") || strings.Contains(cs, "NULL") {
			sev, points = High, 12
		}
		a.add(Finding{
			ID: "tls-weak-cipher", Title: "Negotiated a weak cipher suite",
			Severity: sev, Category: CategoryTLS, Points: points,
			Observed: t.CipherSuite, Expected: "an AEAD suite (GCM or ChaCha20-Poly1305)",
			Detail: "RC4 is broken, 3DES is weak, and CBC suites have a long history of padding-oracle " +
				"attacks. AEAD suites avoid the whole class.",
			Fix: "Prefer TLS_AES_128_GCM_SHA256 / ECDHE-RSA-AES128-GCM-SHA256",
		})
	}

	// --- chain ---
	if t.ChainLength == 1 {
		a.add(Finding{
			ID: "cert-no-chain", Title: "Server sent no intermediate certificates",
			Severity: Medium, Category: CategoryTLS, Points: 5,
			Observed: "chain length 1",
			Detail: "Without the intermediate, clients that have not cached it cannot build a path to " +
				"a trusted root. It commonly works in a browser and fails in curl or a mobile app, " +
				"which makes it a miserable bug to diagnose.",
			Fix: "Serve the full chain (fullchain.pem, not cert.pem)",
		})
	}

	// --- HTTP to HTTPS redirect ---
	if a.result.HTTPRedirectsToHTTPS != nil {
		if *a.result.HTTPRedirectsToHTTPS {
			a.add(Finding{
				ID: "http-redirect", Title: "Plaintext HTTP redirects to HTTPS",
				Severity: Info, Category: CategoryTransport, Points: 0,
			})
		} else {
			a.add(Finding{
				ID: "no-http-redirect", Title: "Plaintext HTTP does not redirect to HTTPS",
				Severity: Medium, Category: CategoryTransport, Points: 8,
				Expected: "301 to the https:// equivalent",
				Detail: "A user typing the bare hostname lands on plaintext HTTP, where the response " +
					"can be modified before any HSTS policy applies.",
				Fix: "return 301 https://$host$request_uri;  # nginx",
			})
		}
	}
}

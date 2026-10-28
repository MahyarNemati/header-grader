package analyze

import (
	"time"

	"github.com/MahyarNemati/header-grader/internal/scan"
)

// analyzer carries the state shared by the individual checks.
type analyzer struct {
	result   *scan.Result
	findings Findings
	now      time.Time
}

func (a *analyzer) add(f Finding) { a.findings = append(a.findings, f) }

// Run produces the findings for a scan result. now is injectable so
// certificate-expiry grading is deterministic in tests.
func Run(result *scan.Result, now time.Time) Findings {
	if result == nil {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}

	a := &analyzer{result: result, now: now}

	// TLS first: a plaintext site gets a different interpretation of several
	// header checks, and HSTS grading depends on it.
	a.tls()
	a.csp()
	a.frameOptions()
	a.contentTypeOptions()
	a.hsts()
	a.referrerPolicy()
	a.permissionsPolicy()
	a.crossOriginIsolation()
	a.legacyXSSProtection()
	a.duplicateSecurityHeaders()
	a.informationDisclosure()
	a.cacheOnSensitive()
	a.cookies()

	a.findings.Sort()
	return a.findings
}

package analyze_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MahyarNemati/header-grader/internal/analyze"
	"github.com/MahyarNemati/header-grader/internal/scan"
)

var now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// goodTLS is a healthy TLS state, so header tests are not dominated by TLS
// findings.
func goodTLS() *scan.TLSInfo {
	return &scan.TLSInfo{
		Version:           "TLS 1.3",
		CipherSuite:       "TLS_AES_128_GCM_SHA256",
		Subject:           "example.com",
		Issuer:            "Example CA",
		NotBefore:         now.AddDate(0, -1, 0),
		NotAfter:          now.AddDate(0, 3, 0),
		SignatureAlgo:     "SHA256-RSA",
		ChainLength:       2,
		MinVersionOffered: "TLS 1.2",
	}
}

// res builds a scan result with the given headers over healthy TLS.
func res(headers map[string]string, cookies ...*http.Cookie) *scan.Result {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	yes := true
	return &scan.Result{
		Requested: "https://example.com/", Final: "https://example.com/", Status: 200,
		Header: h, Cookies: cookies, TLS: goodTLS(), HTTPRedirectsToHTTPS: &yes,
	}
}

func find(t *testing.T, fs analyze.Findings, id string) analyze.Finding {
	t.Helper()
	for _, f := range fs {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("no finding with id %q; got %v", id, ids(fs))
	return analyze.Finding{}
}

func ids(fs analyze.Findings) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func mustNotHave(t *testing.T, fs analyze.Findings, id string) {
	t.Helper()
	if fs.Has(id) {
		t.Errorf("unexpected finding %q", id)
	}
}

// ---------- CSP ----------

func TestCSPMissingIsHigh(t *testing.T) {
	fs := analyze.Run(res(nil), now)
	f := find(t, fs, "csp")
	if f.Severity != analyze.High {
		t.Errorf("severity = %s, want high", f.Severity)
	}
	if f.Points <= 0 {
		t.Errorf("points = %d, want a deduction", f.Points)
	}
}

func TestCSPReportOnlyIsNotEnforcement(t *testing.T) {
	fs := analyze.Run(res(map[string]string{
		"Content-Security-Policy-Report-Only": "default-src 'self'",
	}), now)
	f := find(t, fs, "csp-report-only")
	if f.Severity != analyze.High {
		t.Errorf("severity = %s, want high: report-only blocks nothing", f.Severity)
	}
}

func TestCSPUnsafeInlineIsCritical(t *testing.T) {
	fs := analyze.Run(res(map[string]string{
		"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
	}), now)
	f := find(t, fs, "csp-unsafe-inline")
	if f.Severity != analyze.Critical {
		t.Errorf("severity = %s, want critical", f.Severity)
	}
}

func TestCSPUnsafeInlineWithNonceIsAcceptable(t *testing.T) {
	fs := analyze.Run(res(map[string]string{
		"Content-Security-Policy": "script-src 'self' 'unsafe-inline' 'nonce-abc123'",
	}), now)
	// Browsers that understand nonces ignore unsafe-inline, so this is a
	// deliberate old-browser fallback, not a hole.
	mustNotHave(t, fs, "csp-unsafe-inline")
	f := find(t, fs, "csp-unsafe-inline-with-nonce")
	if f.Severity != analyze.Low {
		t.Errorf("severity = %s, want low", f.Severity)
	}
}

func TestCSPBaseURIAndFormActionDoNotInheritFromDefaultSrc(t *testing.T) {
	// This is the most common CSP mistake: default-src looks like it covers
	// everything, and base-uri / form-action are not among the directives
	// that fall back to it.
	fs := analyze.Run(res(map[string]string{
		"Content-Security-Policy": "default-src 'self'",
	}), now)
	for _, id := range []string{"csp-no-base-uri", "csp-no-form-action"} {
		f := find(t, fs, id)
		if f.Points <= 0 {
			t.Errorf("%s: points = %d, want a deduction", id, f.Points)
		}
	}
	// script-src does inherit, so it must not be reported as missing.
	mustNotHave(t, fs, "csp-no-script-src")
}

func TestCSPExplicitBaseURISatisfiesTheCheck(t *testing.T) {
	fs := analyze.Run(res(map[string]string{
		"Content-Security-Policy": "default-src 'self'; base-uri 'none'; form-action 'self'; object-src 'none'",
	}), now)
	mustNotHave(t, fs, "csp-no-base-uri")
	mustNotHave(t, fs, "csp-no-form-action")
	mustNotHave(t, fs, "csp-no-object-src")
}

func TestCSPWildcardScriptSrcIsFlagged(t *testing.T) {
	for _, src := range []string{"*", "https:", "data:"} {
		fs := analyze.Run(res(map[string]string{
			"Content-Security-Policy": "script-src 'self' " + src,
		}), now)
		f := find(t, fs, "csp-wildcard-script-src")
		if f.Points <= 0 {
			t.Errorf("script-src %q: want a deduction", src)
		}
	}
}

func TestCSPStrictDynamicIsACredit(t *testing.T) {
	fs := analyze.Run(res(map[string]string{
		"Content-Security-Policy": "script-src 'nonce-abc' 'strict-dynamic'; base-uri 'none'; form-action 'self'; object-src 'none'",
	}), now)
	f := find(t, fs, "csp-strict-dynamic")
	if f.Points >= 0 {
		t.Errorf("points = %d, want a credit (negative)", f.Points)
	}
}

func TestCSPUnknownDirectiveIsFlagged(t *testing.T) {
	// A misspelling silently removes the protection, so it has to be caught.
	fs := analyze.Run(res(map[string]string{
		"Content-Security-Policy": "default-src 'self'; script-source 'self'",
	}), now)
	f := find(t, fs, "csp-unknown-directive")
	if !strings.Contains(f.Observed, "script-source") {
		t.Errorf("observed = %q, want it to name script-source", f.Observed)
	}
}

func TestCSPRepeatedDirectiveKeepsTheFirst(t *testing.T) {
	// Browsers ignore a repeated directive, so the parser must too.
	p := analyze.ParseCSP("script-src 'self'; script-src 'unsafe-inline'")
	got, _ := p.Get("script-src")
	if len(got) != 1 || got[0] != "'self'" {
		t.Errorf("script-src = %v, want ['self'] (first occurrence wins)", got)
	}
}

// ---------- HSTS ----------

func TestHSTS(t *testing.T) {
	for _, tc := range []struct {
		name, value, wantID string
		wantSeverity        analyze.Severity
	}{
		{"missing", "", "hsts", analyze.High},
		{"no max-age", "includeSubDomains", "hsts-no-max-age", analyze.High},
		{"disabled", "max-age=0", "hsts-disabled", analyze.High},
		{"short", "max-age=86400", "hsts-short", analyze.Medium},
		{"no subdomains", "max-age=31536000", "hsts-subdomains", analyze.Low},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := map[string]string{}
			if tc.value != "" {
				h["Strict-Transport-Security"] = tc.value
			}
			fs := analyze.Run(res(h), now)
			f := find(t, fs, tc.wantID)
			if f.Severity != tc.wantSeverity {
				t.Errorf("severity = %s, want %s", f.Severity, tc.wantSeverity)
			}
		})
	}
}

func TestHSTSGoodValueScoresNothing(t *testing.T) {
	fs := analyze.Run(res(map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
	}), now)
	f := find(t, fs, "hsts")
	if f.Points != 0 {
		t.Errorf("points = %d, want 0", f.Points)
	}
	mustNotHave(t, fs, "hsts-subdomains")
}

func TestHSTSIsNotGradedOverPlaintext(t *testing.T) {
	r := res(nil)
	r.TLS = nil
	r.Requested, r.Final = "http://example.com/", "http://example.com/"
	fs := analyze.Run(r, now)
	f := find(t, fs, "hsts")
	if f.Points != 0 {
		t.Errorf("points = %d, want 0: HSTS is meaningless over HTTP", f.Points)
	}
}

// ---------- framing ----------

func TestFrameAncestorsSupersedesXFrameOptions(t *testing.T) {
	fs := analyze.Run(res(map[string]string{
		"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
	}), now)
	// XFO must not be reported as missing when CSP already restricts framing.
	mustNotHave(t, fs, "x-frame-options")
	f := find(t, fs, "frame-ancestors")
	if f.Points != 0 {
		t.Errorf("points = %d, want 0", f.Points)
	}
}

func TestXFrameOptionsAllowFromIsUseless(t *testing.T) {
	fs := analyze.Run(res(map[string]string{
		"X-Frame-Options": "ALLOW-FROM https://trusted.example",
	}), now)
	f := find(t, fs, "x-frame-options-allow-from")
	if f.Points <= 0 {
		t.Error("ALLOW-FROM is unsupported everywhere and should be a deduction")
	}
}

func TestXFrameOptionsInvalidValue(t *testing.T) {
	fs := analyze.Run(res(map[string]string{"X-Frame-Options": "yes please"}), now)
	find(t, fs, "x-frame-options-invalid")
}

// ---------- cookies ----------

func TestCookieMissingSecureOnSessionIsHigh(t *testing.T) {
	fs := analyze.Run(res(nil, &http.Cookie{
		Name: "sessionid", Value: "x", HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}), now)
	f := find(t, fs, "cookie-insecure-sessionid")
	if f.Severity != analyze.High {
		t.Errorf("severity = %s, want high for a session cookie", f.Severity)
	}
}

func TestCookieMissingSecureOnNonSessionIsLower(t *testing.T) {
	fs := analyze.Run(res(nil, &http.Cookie{
		Name: "locale", Value: "en", HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}), now)
	f := find(t, fs, "cookie-insecure-locale")
	if f.Severity != analyze.Medium {
		t.Errorf("severity = %s, want medium for a non-session cookie", f.Severity)
	}

	// The same omission on a session cookie must be graded higher.
	sessionFs := analyze.Run(res(nil, &http.Cookie{
		Name: "sessionid", Value: "x", HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}), now)
	s := find(t, sessionFs, "cookie-insecure-sessionid")
	if s.Points <= f.Points {
		t.Errorf("session cookie deduction (%d) should exceed a preference cookie's (%d)", s.Points, f.Points)
	}
}

func TestCookieSeverityDependsOnWhetherItLooksLikeASession(t *testing.T) {
	sessionFs := analyze.Run(res(nil, &http.Cookie{Name: "auth_token", Value: "x", Secure: true}), now)
	prefFs := analyze.Run(res(nil, &http.Cookie{Name: "theme", Value: "dark", Secure: true}), now)

	s := find(t, sessionFs, "cookie-no-httponly-auth_token")
	p := find(t, prefFs, "cookie-no-httponly-theme")
	if s.Points <= p.Points {
		t.Errorf("session cookie deduction (%d) should exceed a preference cookie's (%d)", s.Points, p.Points)
	}
}

func TestCSRFCookieIsExemptFromHttpOnly(t *testing.T) {
	// A double-submit CSRF token has to be readable by script by design.
	fs := analyze.Run(res(nil, &http.Cookie{
		Name: "csrf_token", Value: "x", Secure: true, SameSite: http.SameSiteLaxMode,
	}), now)
	f := find(t, fs, "cookie-no-httponly-csrf_token")
	if f.Points != 0 {
		t.Errorf("points = %d, want 0 for a CSRF cookie", f.Points)
	}
}

func TestSameSiteNoneWithoutSecureIsDropped(t *testing.T) {
	fs := analyze.Run(res(nil, &http.Cookie{
		Name: "sid", Value: "x", HttpOnly: true, SameSite: http.SameSiteNoneMode,
	}), now)
	f := find(t, fs, "cookie-samesite-none-insecure-sid")
	if f.Severity != analyze.High {
		t.Errorf("severity = %s, want high: the browser discards this cookie entirely", f.Severity)
	}
}

func TestHostPrefixSuggestedForSessionCookies(t *testing.T) {
	fs := analyze.Run(res(nil, &http.Cookie{
		Name: "sid", Value: "x", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}), now)
	find(t, fs, "cookie-no-prefix-sid")

	fs = analyze.Run(res(nil, &http.Cookie{
		Name: "__Host-sid", Value: "x", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Path: "/",
	}), now)
	mustNotHave(t, fs, "cookie-no-prefix-__Host-sid")
}

func TestCookieSummaryRedactsTheValue(t *testing.T) {
	secret := "super-secret-session-value"
	fs := analyze.Run(res(nil, &http.Cookie{Name: "sid", Value: secret}), now)
	for _, f := range fs {
		if strings.Contains(f.Observed, secret) {
			t.Fatalf("finding %s leaked the cookie value: %q", f.ID, f.Observed)
		}
	}
}

// ---------- TLS / transport ----------

func TestPlaintextIsCritical(t *testing.T) {
	r := res(nil)
	r.TLS = nil
	fs := analyze.Run(r, now)
	f := find(t, fs, "no-tls")
	if f.Severity != analyze.Critical {
		t.Errorf("severity = %s, want critical", f.Severity)
	}
}

func TestExpiredCertificateIsCritical(t *testing.T) {
	r := res(nil)
	r.TLS.NotAfter = now.AddDate(0, 0, -1)
	fs := analyze.Run(r, now)
	find(t, fs, "cert-expired")
}

func TestLegacyTLSStillAcceptedIsFlagged(t *testing.T) {
	r := res(nil)
	r.TLS.MinVersionOffered = "TLS 1.0"
	fs := analyze.Run(r, now)
	f := find(t, fs, "tls-legacy-enabled")
	if f.Severity != analyze.High {
		t.Errorf("severity = %s, want high", f.Severity)
	}
}

func TestMissingIntermediateIsFlagged(t *testing.T) {
	r := res(nil)
	r.TLS.ChainLength = 1
	fs := analyze.Run(r, now)
	find(t, fs, "cert-no-chain")
}

func TestNoHTTPRedirectIsFlagged(t *testing.T) {
	r := res(nil)
	no := false
	r.HTTPRedirectsToHTTPS = &no
	fs := analyze.Run(r, now)
	find(t, fs, "no-http-redirect")
}

// ---------- misc headers ----------

func TestDuplicateSecurityHeaderIsFlagged(t *testing.T) {
	h := http.Header{}
	h.Add("X-Frame-Options", "DENY")
	h.Add("X-Frame-Options", "SAMEORIGIN")
	r := res(nil)
	r.Header = h
	fs := analyze.Run(r, now)
	find(t, fs, "duplicate-x-frame-options")
}

func TestVersionBannerScoresWorseThanAProductName(t *testing.T) {
	withVersion := analyze.Run(res(map[string]string{"Server": "nginx/1.25.3"}), now)
	bare := analyze.Run(res(map[string]string{"Server": "nginx"}), now)

	a := find(t, withVersion, "disclosure-server")
	b := find(t, bare, "disclosure-server")
	if a.Points <= b.Points {
		t.Errorf("version banner (%d) should score worse than a bare name (%d)", a.Points, b.Points)
	}
}

func TestObsoleteXSSProtectionIsNoted(t *testing.T) {
	fs := analyze.Run(res(map[string]string{"X-XSS-Protection": "1; mode=block"}), now)
	find(t, fs, "x-xss-protection-obsolete")
}

func TestPubliclyCacheableResponseWithCookiesIsFlagged(t *testing.T) {
	fs := analyze.Run(res(
		map[string]string{"Cache-Control": "public, max-age=3600"},
		&http.Cookie{Name: "sid", Value: "x", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode},
	), now)
	find(t, fs, "cache-control-public")
}

func TestPublicPageCacheabilityIsNotAFinding(t *testing.T) {
	// No cookies means no credentials to leak via a shared cache.
	fs := analyze.Run(res(map[string]string{"Cache-Control": "public, max-age=3600"}), now)
	mustNotHave(t, fs, "cache-control-public")
}

// ---------- ordering ----------

func TestFindingsAreSortedBySeverity(t *testing.T) {
	fs := analyze.Run(res(map[string]string{
		"Content-Security-Policy": "script-src 'unsafe-inline'",
		"Server":                  "nginx/1.0.0",
	}), now)
	last := analyze.Critical + 1
	for _, f := range fs {
		if f.Severity > last {
			t.Fatalf("findings are not sorted descending by severity: %v", ids(fs))
		}
		last = f.Severity
	}
}

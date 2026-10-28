package analyze

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// hstsMinAge is six months, the floor for inclusion in browser preload lists
// and a reasonable bar generally: a short max-age leaves a long window in
// which a downgrade attack still works.
const hstsMinAge = 15768000

func (a *analyzer) hsts() {
	const id = "hsts"
	v := a.header("Strict-Transport-Security")

	if a.result.TLS == nil {
		a.add(Finding{
			ID: id, Title: "HSTS not applicable over plaintext HTTP",
			Severity: Info, Category: CategoryTransport, Points: 0,
			Detail: "Strict-Transport-Security is ignored when served over HTTP, so it is not graded here.",
		})
		return
	}

	if v == "" {
		a.add(Finding{
			ID: id, Title: "Strict-Transport-Security is missing",
			Severity: High, Category: CategoryTransport, Points: 20,
			Expected: "max-age >= 15768000; includeSubDomains",
			Detail: "Without HSTS, a user's first request over http:// can be intercepted and " +
				"downgraded before any redirect to https:// is seen.",
			Fix:       "Strict-Transport-Security: max-age=31536000; includeSubDomains",
			Reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
		})
		return
	}

	age, hasAge := hstsMaxAge(v)
	switch {
	case !hasAge:
		a.add(Finding{
			ID: id + "-no-max-age", Title: "HSTS has no max-age",
			Severity: High, Category: CategoryTransport, Points: 18,
			Observed: truncate(v, 120), Expected: "max-age >= 15768000",
			Detail: "A Strict-Transport-Security header without max-age is ignored entirely by browsers.",
			Fix:    "Strict-Transport-Security: max-age=31536000; includeSubDomains",
		})
	case age == 0:
		a.add(Finding{
			ID: id + "-disabled", Title: "HSTS is explicitly disabled",
			Severity: High, Category: CategoryTransport, Points: 18,
			Observed: truncate(v, 120),
			Detail: "max-age=0 tells browsers to forget the HSTS policy for this host, which is " +
				"how HSTS is switched off deliberately. If that was not the intent, it is a misconfiguration.",
			Fix: "Strict-Transport-Security: max-age=31536000; includeSubDomains",
		})
	case age < hstsMinAge:
		a.add(Finding{
			ID: id + "-short", Title: "HSTS max-age is short",
			Severity: Medium, Category: CategoryTransport, Points: 8,
			Observed: fmt.Sprintf("max-age=%d (%.0f days)", age, float64(age)/86400),
			Expected: fmt.Sprintf("max-age >= %d (180 days)", hstsMinAge),
			Detail: "A short max-age means the protection lapses quickly for visitors who do not " +
				"return, leaving a window for a downgrade attack.",
			Fix: "Strict-Transport-Security: max-age=31536000; includeSubDomains",
		})
	default:
		a.add(Finding{
			ID: id, Title: "HSTS is set with a long max-age",
			Severity: Info, Category: CategoryTransport, Points: 0,
			Observed: truncate(v, 120),
		})
	}

	if hasAge && age >= hstsMinAge && !strings.Contains(strings.ToLower(v), "includesubdomains") {
		a.add(Finding{
			ID: id + "-subdomains", Title: "HSTS does not cover subdomains",
			Severity: Low, Category: CategoryTransport, Points: 4,
			Observed: truncate(v, 120), Expected: "includeSubDomains",
			Detail: "Without includeSubDomains, a subdomain served over plaintext can be used to set " +
				"cookies for the parent domain.",
			Fix: "Strict-Transport-Security: max-age=31536000; includeSubDomains",
		})
	}
}

func hstsMaxAge(v string) (int, bool) {
	for _, part := range strings.Split(v, ";") {
		part = strings.TrimSpace(part)
		k, val, ok := strings.Cut(part, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "max-age") {
			continue
		}
		n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(val), `"`))
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

func (a *analyzer) frameOptions() {
	xfo := a.header("X-Frame-Options")
	csp := a.header("Content-Security-Policy")
	// frame-ancestors supersedes X-Frame-Options and is honoured where both
	// are present, so a modern CSP makes XFO redundant rather than missing.
	hasFrameAncestors := csp != "" && strings.Contains(strings.ToLower(csp), "frame-ancestors")

	switch {
	case hasFrameAncestors:
		a.add(Finding{
			ID: "frame-ancestors", Title: "Framing is restricted by CSP frame-ancestors",
			Severity: Info, Category: CategoryHeaders, Points: 0,
			Detail: "frame-ancestors supersedes X-Frame-Options, so X-Frame-Options is not required.",
		})
	case xfo == "":
		a.add(Finding{
			ID: "x-frame-options", Title: "No framing protection",
			Severity: Medium, Category: CategoryHeaders, Points: 10,
			Expected: "CSP frame-ancestors, or X-Frame-Options: DENY",
			Detail: "Without framing restrictions the page can be embedded in an attacker's site " +
				"and used for clickjacking.",
			Fix:       "Content-Security-Policy: frame-ancestors 'none'",
			Reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options",
		})
	case strings.EqualFold(strings.TrimSpace(xfo), "allow-from") ||
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(xfo)), "allow-from"):
		a.add(Finding{
			ID: "x-frame-options-allow-from", Title: "X-Frame-Options uses the obsolete ALLOW-FROM",
			Severity: Medium, Category: CategoryHeaders, Points: 8,
			Observed: truncate(xfo, 80), Expected: "CSP frame-ancestors",
			Detail: "ALLOW-FROM is not supported by any current browser, so this header provides " +
				"no protection at all.",
			Fix: "Content-Security-Policy: frame-ancestors https://trusted.example",
		})
	case strings.EqualFold(strings.TrimSpace(xfo), "deny"), strings.EqualFold(strings.TrimSpace(xfo), "sameorigin"):
		a.add(Finding{
			ID: "x-frame-options", Title: "X-Frame-Options is set",
			Severity: Info, Category: CategoryHeaders, Points: 0, Observed: xfo,
		})
	default:
		a.add(Finding{
			ID: "x-frame-options-invalid", Title: "X-Frame-Options value is not valid",
			Severity: Medium, Category: CategoryHeaders, Points: 8,
			Observed: truncate(xfo, 80), Expected: "DENY or SAMEORIGIN",
			Detail: "An unrecognised value is ignored, so the header provides no protection.",
			Fix:    "X-Frame-Options: DENY",
		})
	}
}

func (a *analyzer) contentTypeOptions() {
	v := strings.TrimSpace(a.header("X-Content-Type-Options"))
	if strings.EqualFold(v, "nosniff") {
		a.add(Finding{
			ID: "x-content-type-options", Title: "MIME sniffing is disabled",
			Severity: Info, Category: CategoryHeaders, Points: 0, Observed: v,
		})
		return
	}
	a.add(Finding{
		ID: "x-content-type-options", Title: "X-Content-Type-Options: nosniff is missing",
		Severity: Medium, Category: CategoryHeaders, Points: 6,
		Observed: truncate(v, 60), Expected: "nosniff",
		Detail: "Without nosniff, a browser may ignore the declared Content-Type and execute an " +
			"uploaded file as script.",
		Fix: "X-Content-Type-Options: nosniff",
	})
}

func (a *analyzer) referrerPolicy() {
	v := strings.ToLower(strings.TrimSpace(a.header("Referrer-Policy")))
	// Leaking a full URL cross-origin leaks whatever is in the path and query,
	// which on many sites includes tokens and identifiers.
	leaky := map[string]bool{
		"unsafe-url": true, "no-referrer-when-downgrade": true, "origin-when-cross-origin": true,
	}
	switch {
	case v == "":
		a.add(Finding{
			ID: "referrer-policy", Title: "Referrer-Policy is not set",
			Severity: Low, Category: CategoryHeaders, Points: 4,
			Expected: "strict-origin-when-cross-origin or no-referrer",
			Detail: "Browsers default to strict-origin-when-cross-origin, so this is a hardening " +
				"gap rather than a leak, but setting it explicitly removes the dependence on defaults.",
			Fix: "Referrer-Policy: strict-origin-when-cross-origin",
		})
	case leaky[v]:
		a.add(Finding{
			ID: "referrer-policy-leaky", Title: "Referrer-Policy leaks URLs cross-origin",
			Severity: Medium, Category: CategoryHeaders, Points: 7,
			Observed: v, Expected: "strict-origin-when-cross-origin or no-referrer",
			Detail: "This policy sends the full URL to third parties. Any token or identifier in a " +
				"path or query string is disclosed to every external resource the page loads.",
			Fix: "Referrer-Policy: strict-origin-when-cross-origin",
		})
	default:
		a.add(Finding{
			ID: "referrer-policy", Title: "Referrer-Policy is set",
			Severity: Info, Category: CategoryHeaders, Points: 0, Observed: v,
		})
	}
}

func (a *analyzer) permissionsPolicy() {
	if v := a.header("Permissions-Policy"); v != "" {
		a.add(Finding{
			ID: "permissions-policy", Title: "Permissions-Policy is set",
			Severity: Info, Category: CategoryHeaders, Points: 0, Observed: truncate(v, 140),
		})
		return
	}
	if v := a.header("Feature-Policy"); v != "" {
		a.add(Finding{
			ID: "feature-policy-obsolete", Title: "Using obsolete Feature-Policy",
			Severity: Low, Category: CategoryHeaders, Points: 3,
			Observed: truncate(v, 120), Expected: "Permissions-Policy",
			Detail: "Feature-Policy was renamed to Permissions-Policy and is no longer honoured by " +
				"current browsers.",
			Fix: "Permissions-Policy: geolocation=(), camera=(), microphone=()",
		})
		return
	}
	a.add(Finding{
		ID: "permissions-policy", Title: "Permissions-Policy is not set",
		Severity: Low, Category: CategoryHeaders, Points: 3,
		Expected: "an explicit allow-list for powerful features",
		Detail: "Without it, embedded content inherits access to features such as geolocation, " +
			"camera and microphone.",
		Fix: "Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()",
	})
}

func (a *analyzer) crossOriginIsolation() {
	for _, h := range []struct {
		name, id, want, fix, why string
	}{
		{
			"Cross-Origin-Opener-Policy", "coop", "same-origin",
			"Cross-Origin-Opener-Policy: same-origin",
			"Without COOP, a window this page opens (or that opened it) keeps a reference to it, which enables cross-window attacks such as XS-Leaks.",
		},
		{
			"Cross-Origin-Resource-Policy", "corp", "same-origin",
			"Cross-Origin-Resource-Policy: same-origin",
			"Without CORP, other origins can embed this response as a subresource, which is the basis of Spectre-style cross-origin reads.",
		},
	} {
		if v := a.header(h.name); v != "" {
			a.add(Finding{
				ID: h.id, Title: h.name + " is set",
				Severity: Info, Category: CategoryHeaders, Points: 0, Observed: truncate(v, 80),
			})
			continue
		}
		a.add(Finding{
			ID: h.id, Title: h.name + " is not set",
			Severity: Low, Category: CategoryHeaders, Points: 2,
			Expected: h.want, Detail: h.why, Fix: h.fix,
		})
	}
}

func (a *analyzer) legacyXSSProtection() {
	v := strings.TrimSpace(a.header("X-XSS-Protection"))
	if v == "" {
		return
	}
	// Worth calling out because it is still widely recommended by old blog
	// posts, and the filter it enabled introduced vulnerabilities of its own.
	sev, points := Info, 0
	detail := "X-XSS-Protection is ignored by every current browser. It is harmless but misleading: " +
		"it suggests XSS protection that is not actually present."
	if strings.HasPrefix(v, "1") && strings.Contains(strings.ToLower(v), "mode=block") {
		sev, points = Low, 1
	}
	a.add(Finding{
		ID: "x-xss-protection-obsolete", Title: "X-XSS-Protection is obsolete",
		Severity: sev, Category: CategoryHeaders, Points: points,
		Observed: v, Expected: "a Content-Security-Policy instead",
		Detail: detail,
		Fix:    "Remove X-XSS-Protection and rely on CSP",
	})
}

func (a *analyzer) informationDisclosure() {
	for _, name := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "X-Drupal-Cache", "X-Runtime"} {
		v := a.header(name)
		if v == "" {
			continue
		}
		// A bare product name is mild; a version number tells an attacker
		// which exploits to try.
		sev, points := Low, 2
		if hasVersion(v) {
			sev, points = Medium, 5
		}
		a.add(Finding{
			ID: "disclosure-" + strings.ToLower(name), Title: name + " reveals software details",
			Severity: sev, Category: CategoryLeak, Points: points,
			Observed: truncate(v, 80), Expected: "header removed, or no version",
			Detail: "Version banners let an attacker skip reconnaissance and go straight to exploits " +
				"for the exact version you are running.",
			Fix: "Remove or blank the " + name + " header at the proxy",
		})
	}
}

// hasVersion reports whether a banner contains something version-shaped.
func hasVersion(v string) bool {
	digits, dots := 0, 0
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == '.':
			dots++
		}
	}
	return digits >= 2 && dots >= 1
}

func (a *analyzer) cacheOnSensitive() {
	cc := strings.ToLower(a.header("Cache-Control"))
	if cc == "" {
		return
	}
	// Only interesting when credentials are in play: a public page being
	// cacheable is correct, not a finding.
	if len(a.result.Cookies) == 0 {
		return
	}
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		a.add(Finding{
			ID: "cache-control", Title: "Cache-Control prevents shared caching of an authenticated response",
			Severity: Info, Category: CategoryHeaders, Points: 0, Observed: truncate(cc, 80),
		})
		return
	}
	if strings.Contains(cc, "public") {
		a.add(Finding{
			ID: "cache-control-public", Title: "A response that sets cookies is marked publicly cacheable",
			Severity: Medium, Category: CategoryHeaders, Points: 6,
			Observed: truncate(cc, 80), Expected: "no-store or private",
			Detail: "A shared cache may store this response and serve it, along with its Set-Cookie, " +
				"to a different user.",
			Fix: "Cache-Control: no-store",
		})
	}
}

// header returns the final response's value for name.
func (a *analyzer) header(name string) string {
	if a.result.Header == nil {
		return ""
	}
	return strings.TrimSpace(a.result.Header.Get(name))
}

// headerCount reports how many times a header was sent, which matters because
// duplicates are handled inconsistently and often mean two layers both set it.
func (a *analyzer) headerCount(name string) int {
	if a.result.Header == nil {
		return 0
	}
	return len(a.result.Header.Values(http.CanonicalHeaderKey(name)))
}

func (a *analyzer) duplicateSecurityHeaders() {
	for _, name := range []string{
		"Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
		"X-Content-Type-Options", "Referrer-Policy",
	} {
		if n := a.headerCount(name); n > 1 {
			a.add(Finding{
				ID: "duplicate-" + strings.ToLower(name), Title: name + " is sent more than once",
				Severity: Medium, Category: CategoryHeaders, Points: 5,
				Observed: fmt.Sprintf("%d occurrences", n), Expected: "exactly one",
				Detail: "Browsers combine duplicate security headers by taking the most restrictive " +
					"result, which is rarely what either layer intended. Usually the application and a " +
					"proxy are both setting it.",
				Fix: "Set " + name + " in exactly one place",
			})
		}
	}
}

package analyze

import (
	"fmt"
	"sort"
	"strings"
)

// Policy is a parsed Content-Security-Policy.
type Policy struct {
	// Directives maps a directive name to its source list, in order.
	Directives map[string][]string
	// Order preserves the order directives appeared in.
	Order []string
	// ReportOnly is true when parsed from Content-Security-Policy-Report-Only.
	ReportOnly bool
}

// ParseCSP parses a policy string. It is intentionally lenient in the same way
// browsers are: unknown directives are kept, and a repeated directive keeps
// the first occurrence, because that is what browsers do.
func ParseCSP(raw string) *Policy {
	p := &Policy{Directives: map[string][]string{}}
	for _, segment := range strings.Split(raw, ";") {
		fields := strings.Fields(segment)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		if _, dup := p.Directives[name]; dup {
			// Browsers ignore a repeated directive, so so do we.
			continue
		}
		p.Directives[name] = fields[1:]
		p.Order = append(p.Order, name)
	}
	return p
}

// Get returns a directive's sources, falling back to default-src for the
// directives that inherit from it.
func (p *Policy) Get(name string) ([]string, bool) {
	if v, ok := p.Directives[name]; ok {
		return v, true
	}
	if fallsBackToDefault[name] {
		if v, ok := p.Directives["default-src"]; ok {
			return v, true
		}
	}
	return nil, false
}

// fallsBackToDefault lists directives that inherit from default-src. Notably
// absent: frame-ancestors, base-uri and form-action, which do NOT inherit --
// a policy with only default-src leaves all three unrestricted, and that is
// the single most common CSP mistake.
var fallsBackToDefault = map[string]bool{
	"script-src": true, "style-src": true, "img-src": true, "connect-src": true,
	"font-src": true, "media-src": true, "object-src": true, "frame-src": true,
	"worker-src": true, "manifest-src": true, "child-src": true, "script-src-elem": true,
	"script-src-attr": true, "style-src-elem": true, "style-src-attr": true,
}

// Has reports whether a source list contains a keyword or source, case
// insensitively.
func hasSource(sources []string, want string) bool {
	for _, s := range sources {
		if strings.EqualFold(strings.Trim(s, "'"), strings.Trim(want, "'")) {
			return true
		}
	}
	return false
}

func hasNonceOrHash(sources []string) bool {
	for _, s := range sources {
		l := strings.ToLower(strings.Trim(s, "'"))
		if strings.HasPrefix(l, "nonce-") || strings.HasPrefix(l, "sha256-") ||
			strings.HasPrefix(l, "sha384-") || strings.HasPrefix(l, "sha512-") {
			return true
		}
	}
	return false
}

func (a *analyzer) csp() {
	raw := a.header("Content-Security-Policy")
	reportOnly := a.header("Content-Security-Policy-Report-Only")

	if raw == "" {
		if reportOnly != "" {
			a.add(Finding{
				ID: "csp-report-only", Title: "CSP is report-only and therefore not enforced",
				Severity: High, Category: CategoryCSP, Points: 22,
				Observed: truncate(reportOnly, 160), Expected: "Content-Security-Policy (enforcing)",
				Detail: "Content-Security-Policy-Report-Only collects violations but blocks nothing. " +
					"It is the correct way to roll a policy out, and no protection once you are done.",
				Fix: "Move the policy to the Content-Security-Policy header",
			})
			return
		}
		a.add(Finding{
			ID: "csp", Title: "No Content-Security-Policy",
			Severity: High, Category: CategoryCSP, Points: 25,
			Expected: "a policy with default-src, object-src 'none', base-uri 'none'",
			Detail: "CSP is the main defence-in-depth control against cross-site scripting. Without " +
				"it, any injected markup executes with the page's full privileges.",
			Fix:       "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
			Reference: "https://developer.mozilla.org/docs/Web/HTTP/CSP",
		})
		return
	}

	p := ParseCSP(raw)
	a.add(Finding{
		ID: "csp", Title: "Content-Security-Policy is present",
		Severity: Info, Category: CategoryCSP, Points: 0, Observed: truncate(raw, 200),
	})

	a.cspScriptSrc(p)
	a.cspMissingNonInheriting(p)
	a.cspObjectSrc(p)
	a.cspWildcards(p)
	a.cspUnknownDirectives(p)
}

// cspScriptSrc grades the directive that actually stops XSS.
func (a *analyzer) cspScriptSrc(p *Policy) {
	sources, ok := p.Get("script-src")
	if !ok {
		a.add(Finding{
			ID: "csp-no-script-src", Title: "CSP does not restrict script sources",
			Severity: High, Category: CategoryCSP, Points: 18,
			Expected: "script-src or default-src",
			Detail: "With neither script-src nor default-src, scripts from anywhere are allowed and " +
				"the policy does nothing about XSS.",
			Fix: "Add: script-src 'self'",
		})
		return
	}

	switch {
	case hasSource(sources, "'unsafe-inline'") && !hasNonceOrHash(sources):
		// This is the finding that matters most. A CSP with unsafe-inline and
		// no nonce does not prevent the attack CSP exists to prevent.
		a.add(Finding{
			ID: "csp-unsafe-inline", Title: "script-src allows 'unsafe-inline'",
			Severity: Critical, Category: CategoryCSP, Points: 20,
			Observed: "script-src " + truncate(strings.Join(sources, " "), 120),
			Expected: "a nonce or hash instead of 'unsafe-inline'",
			Detail: "'unsafe-inline' permits any inline <script>, which is exactly what an XSS " +
				"payload is. The policy provides essentially no XSS protection.",
			Fix:       "script-src 'self' 'nonce-<random-per-response>'",
			Reference: "https://developer.mozilla.org/docs/Web/HTTP/CSP#unsafe_inline_script",
		})
	case hasSource(sources, "'unsafe-inline'") && hasNonceOrHash(sources):
		a.add(Finding{
			ID: "csp-unsafe-inline-with-nonce", Title: "script-src has 'unsafe-inline' alongside a nonce",
			Severity: Low, Category: CategoryCSP, Points: 2,
			Observed: "script-src " + truncate(strings.Join(sources, " "), 120),
			Detail: "Browsers that support nonces ignore 'unsafe-inline' when one is present, so this " +
				"is a deliberate and correct fallback for very old browsers rather than a hole.",
		})
	default:
		a.add(Finding{
			ID: "csp-script-src", Title: "script-src does not allow inline script",
			Severity: Info, Category: CategoryCSP, Points: 0,
			Observed: "script-src " + truncate(strings.Join(sources, " "), 120),
		})
	}

	if hasSource(sources, "'unsafe-eval'") {
		a.add(Finding{
			ID: "csp-unsafe-eval", Title: "script-src allows 'unsafe-eval'",
			Severity: Medium, Category: CategoryCSP, Points: 8,
			Observed: "script-src " + truncate(strings.Join(sources, " "), 120),
			Detail: "'unsafe-eval' re-enables eval() and friends, which turns any injected string that " +
				"reaches them into code execution.",
			Fix: "Remove 'unsafe-eval' and avoid eval/new Function",
		})
	}

	// 'strict-dynamic' is a credit: it neutralises host allow-lists, which are
	// the other common way a CSP ends up bypassable.
	if hasSource(sources, "'strict-dynamic'") {
		a.add(Finding{
			ID: "csp-strict-dynamic", Title: "script-src uses 'strict-dynamic'",
			Severity: Info, Category: CategoryCSP, Points: -3,
			Observed: "script-src " + truncate(strings.Join(sources, " "), 120),
			Detail: "'strict-dynamic' makes host allow-lists irrelevant and is the recommended basis " +
				"for a strict CSP.",
		})
	}
}

// cspMissingNonInheriting flags the directives that do not fall back to
// default-src, which is where most otherwise-good policies are incomplete.
func (a *analyzer) cspMissingNonInheriting(p *Policy) {
	for _, d := range []struct {
		name, want, why string
		points          int
		severity        Severity
	}{
		{
			"base-uri", "'none'",
			"Without base-uri, injected markup can add a <base> tag and redirect every relative URL on the page, including script sources, to an attacker's host. default-src does not cover this.",
			8, Medium,
		},
		{
			"form-action", "'self'",
			"Without form-action, injected markup can repoint a form at an attacker's server and collect whatever the user submits. default-src does not cover this.",
			6, Medium,
		},
		{
			"frame-ancestors", "'none'",
			"Without frame-ancestors (and without X-Frame-Options) the page can be framed for clickjacking. default-src does not cover this.",
			0, Low, // graded under framing instead, to avoid double-counting
		},
	} {
		if _, ok := p.Directives[d.name]; ok {
			continue
		}
		if d.points == 0 {
			continue
		}
		a.add(Finding{
			ID: "csp-no-" + d.name, Title: "CSP is missing " + d.name,
			Severity: d.severity, Category: CategoryCSP, Points: d.points,
			Expected: d.name + " " + d.want, Detail: d.why,
			Fix: d.name + " " + d.want,
		})
	}
}

func (a *analyzer) cspObjectSrc(p *Policy) {
	sources, ok := p.Get("object-src")
	if !ok {
		a.add(Finding{
			ID: "csp-no-object-src", Title: "CSP does not restrict object-src",
			Severity: Medium, Category: CategoryCSP, Points: 5,
			Expected: "object-src 'none'",
			Detail: "Plugin content via <object> and <embed> can execute script in some browsers. " +
				"'none' is safe for essentially every modern site.",
			Fix: "object-src 'none'",
		})
		return
	}
	if !hasSource(sources, "'none'") {
		a.add(Finding{
			ID: "csp-object-src-permissive", Title: "object-src is not 'none'",
			Severity: Low, Category: CategoryCSP, Points: 3,
			Observed: "object-src " + truncate(strings.Join(sources, " "), 80),
			Expected: "object-src 'none'", Fix: "object-src 'none'",
			Detail: "Allowing plugin content is rarely necessary and widens the attack surface.",
		})
	}
}

// cspWildcards flags source lists that are effectively unrestricted.
func (a *analyzer) cspWildcards(p *Policy) {
	// Fetch directives where a wildcard genuinely matters for script execution
	// or exfiltration.
	important := map[string]Severity{
		"script-src": High, "script-src-elem": High, "default-src": Medium,
		"connect-src": Medium, "frame-src": Low, "style-src": Low,
	}

	names := make([]string, 0, len(p.Directives))
	for name := range p.Directives {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		sev, care := important[name]
		if !care {
			continue
		}
		sources := p.Directives[name]
		for _, s := range sources {
			trimmed := strings.Trim(s, "'")
			if trimmed != "*" && trimmed != "http:" && trimmed != "https:" && trimmed != "data:" {
				continue
			}
			points := 10
			if sev == Medium {
				points = 6
			} else if sev == Low {
				points = 3
			}
			detail := fmt.Sprintf("A %q source in %s allows content from anywhere, which defeats the point of the directive.", trimmed, name)
			if trimmed == "data:" {
				detail = fmt.Sprintf("A data: source in %s lets an attacker inline a payload as a data URI, bypassing host restrictions entirely.", name)
			}
			a.add(Finding{
				ID: "csp-wildcard-" + name, Title: fmt.Sprintf("%s allows %q", name, trimmed),
				Severity: sev, Category: CategoryCSP, Points: points,
				Observed: name + " " + truncate(strings.Join(sources, " "), 100),
				Expected: "an explicit list of origins", Detail: detail,
				Fix: name + " 'self' https://cdn.example.com",
			})
			break // one finding per directive is enough
		}
	}
}

// knownDirectives is used only to spot typos; an unknown directive is ignored
// by browsers, so a misspelling silently removes the protection.
var knownDirectives = map[string]bool{
	"default-src": true, "script-src": true, "script-src-elem": true, "script-src-attr": true,
	"style-src": true, "style-src-elem": true, "style-src-attr": true, "img-src": true,
	"connect-src": true, "font-src": true, "object-src": true, "media-src": true,
	"frame-src": true, "child-src": true, "worker-src": true, "manifest-src": true,
	"prefetch-src": true, "base-uri": true, "form-action": true, "frame-ancestors": true,
	"sandbox": true, "report-uri": true, "report-to": true, "upgrade-insecure-requests": true,
	"block-all-mixed-content": true, "require-trusted-types-for": true, "trusted-types": true,
	"navigate-to": true, "fenced-frame-src": true,
}

func (a *analyzer) cspUnknownDirectives(p *Policy) {
	var unknown []string
	for _, name := range p.Order {
		if !knownDirectives[name] {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) == 0 {
		return
	}
	a.add(Finding{
		ID: "csp-unknown-directive", Title: "CSP contains unrecognised directives",
		Severity: Medium, Category: CategoryCSP, Points: 5,
		Observed: strings.Join(unknown, ", "),
		Expected: "only directives browsers implement",
		Detail: "Browsers ignore directives they do not recognise, so a misspelling such as " +
			"'script-source' silently provides no protection while looking like it does.",
		Fix: "Correct the directive name",
	})
}

package analyze

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// sessionNameHints are substrings that suggest a cookie carries authentication.
// Used only to raise severity: a missing Secure flag on a session cookie is
// worse than on a locale preference.
var sessionNameHints = []string{
	"sess", "sid", "auth", "token", "jwt", "login", "remember", "csrf", "xsrf", "_ga_session",
}

func looksLikeSession(name string) bool {
	l := strings.ToLower(name)
	for _, hint := range sessionNameHints {
		if strings.Contains(l, hint) {
			return true
		}
	}
	return false
}

func (a *analyzer) cookies() {
	if len(a.result.Cookies) == 0 {
		a.add(Finding{
			ID: "cookies-none", Title: "No cookies set",
			Severity: Info, Category: CategoryCookies, Points: 0,
			Detail: "Nothing to grade; a page that sets no cookies cannot get cookie flags wrong.",
		})
		return
	}

	overHTTPS := a.result.TLS != nil

	for _, c := range a.result.Cookies {
		sensitive := looksLikeSession(c.Name)
		label := fmt.Sprintf("cookie %q", c.Name)

		// --- Secure ---
		if !c.Secure && overHTTPS {
			sev, points := Medium, 5
			if sensitive {
				sev, points = High, 12
			}
			a.add(Finding{
				ID: "cookie-insecure-" + c.Name, Title: label + " is missing Secure",
				Severity: sev, Category: CategoryCookies, Points: points,
				Observed: cookieSummary(c), Expected: "Secure",
				Detail: "Without Secure, the browser will send this cookie over plaintext HTTP, where " +
					"it can be read in transit. For a session cookie that is account takeover.",
				Fix: fmt.Sprintf("Set-Cookie: %s=...; Secure; HttpOnly; SameSite=Lax", c.Name),
			})
		}

		// --- HttpOnly ---
		if !c.HttpOnly {
			sev, points := Low, 2
			if sensitive {
				sev, points = High, 10
			}
			detail := "Without HttpOnly the cookie is readable by JavaScript, so any XSS on the site " +
				"can exfiltrate it."
			if strings.Contains(strings.ToLower(c.Name), "csrf") || strings.Contains(strings.ToLower(c.Name), "xsrf") {
				// A double-submit CSRF cookie is read by script by design.
				sev, points = Info, 0
				detail = "This looks like a double-submit CSRF token, which has to be readable by " +
					"JavaScript by design, so HttpOnly is correctly omitted."
			}
			a.add(Finding{
				ID: "cookie-no-httponly-" + c.Name, Title: label + " is missing HttpOnly",
				Severity: sev, Category: CategoryCookies, Points: points,
				Observed: cookieSummary(c), Expected: "HttpOnly",
				Detail: detail,
				Fix:    fmt.Sprintf("Set-Cookie: %s=...; Secure; HttpOnly; SameSite=Lax", c.Name),
			})
		}

		// --- SameSite ---
		switch c.SameSite {
		case http.SameSiteNoneMode:
			if !c.Secure {
				// SameSite=None without Secure is rejected outright by
				// browsers, so the cookie is simply dropped.
				a.add(Finding{
					ID:       "cookie-samesite-none-insecure-" + c.Name,
					Title:    label + " uses SameSite=None without Secure",
					Severity: High, Category: CategoryCookies, Points: 10,
					Observed: cookieSummary(c), Expected: "SameSite=None; Secure",
					Detail: "Browsers reject SameSite=None unless Secure is also set, so this cookie " +
						"is discarded entirely. Whatever depends on it is silently broken.",
					Fix: fmt.Sprintf("Set-Cookie: %s=...; SameSite=None; Secure", c.Name),
				})
			} else {
				sev, points := Low, 2
				if sensitive {
					sev, points = Medium, 6
				}
				a.add(Finding{
					ID: "cookie-samesite-none-" + c.Name, Title: label + " uses SameSite=None",
					Severity: sev, Category: CategoryCookies, Points: points,
					Observed: cookieSummary(c), Expected: "SameSite=Lax or Strict",
					Detail: "SameSite=None sends the cookie on cross-site requests, which removes the " +
						"browser's built-in CSRF mitigation. Only correct for cookies genuinely needed " +
						"in a third-party context.",
					Fix: fmt.Sprintf("Set-Cookie: %s=...; SameSite=Lax", c.Name),
				})
			}
		case http.SameSiteDefaultMode:
			// Go reports an absent attribute as DefaultMode. Modern browsers
			// treat absent as Lax, so this is a hardening gap, not a hole.
			sev, points := Low, 2
			if sensitive {
				sev, points = Medium, 4
			}
			a.add(Finding{
				ID: "cookie-no-samesite-" + c.Name, Title: label + " has no SameSite attribute",
				Severity: sev, Category: CategoryCookies, Points: points,
				Observed: cookieSummary(c), Expected: "SameSite=Lax or Strict",
				Detail: "Current browsers default an absent SameSite to Lax, so set it explicitly " +
					"rather than depending on a default that older clients do not share.",
				Fix: fmt.Sprintf("Set-Cookie: %s=...; SameSite=Lax", c.Name),
			})
		}

		// --- __Host- / __Secure- prefixes ---
		if sensitive && !strings.HasPrefix(c.Name, "__Host-") && !strings.HasPrefix(c.Name, "__Secure-") {
			a.add(Finding{
				ID: "cookie-no-prefix-" + c.Name, Title: label + " does not use a __Host- or __Secure- prefix",
				Severity: Low, Category: CategoryCookies, Points: 2,
				Observed: cookieSummary(c), Expected: "__Host-" + c.Name,
				Detail: "The __Host- prefix makes the browser enforce Secure, Path=/ and no Domain, " +
					"which blocks a subdomain from overwriting the cookie (session fixation).",
				Fix: fmt.Sprintf("Set-Cookie: __Host-%s=...; Secure; HttpOnly; SameSite=Lax; Path=/", c.Name),
			})
		}

		// --- lifetime ---
		if sensitive && !c.Expires.IsZero() {
			if life := c.Expires.Sub(a.now); life > 365*24*time.Hour {
				a.add(Finding{
					ID: "cookie-long-lived-" + c.Name, Title: label + " is very long lived",
					Severity: Low, Category: CategoryCookies, Points: 2,
					Observed: fmt.Sprintf("expires in %.0f days", life.Hours()/24),
					Expected: "a session cookie, or a bounded lifetime",
					Detail: "A session identifier valid for over a year stays useful to anyone who " +
						"captures it for just as long.",
					Fix: "Shorten the expiry, or omit it so the cookie expires with the session",
				})
			}
		}
	}

	// A positive finding when every cookie is correctly flagged.
	if !a.findings.Deductions().hasCategory(CategoryCookies) {
		a.add(Finding{
			ID: "cookies-well-configured", Title: "All cookies carry appropriate flags",
			Severity: Info, Category: CategoryCookies, Points: 0,
			Observed: fmt.Sprintf("%d cookie(s)", len(a.result.Cookies)),
		})
	}
}

func (fs Findings) hasCategory(c Category) bool {
	for _, f := range fs {
		if f.Category == c {
			return true
		}
	}
	return false
}

// cookieSummary renders a cookie's attributes without its value, so a report
// can be pasted into a ticket without leaking a live session.
func cookieSummary(c *http.Cookie) string {
	parts := []string{c.Name + "=<redacted>"}
	if c.Secure {
		parts = append(parts, "Secure")
	}
	if c.HttpOnly {
		parts = append(parts, "HttpOnly")
	}
	switch c.SameSite {
	case http.SameSiteStrictMode:
		parts = append(parts, "SameSite=Strict")
	case http.SameSiteLaxMode:
		parts = append(parts, "SameSite=Lax")
	case http.SameSiteNoneMode:
		parts = append(parts, "SameSite=None")
	}
	if c.Domain != "" {
		parts = append(parts, "Domain="+c.Domain)
	}
	if c.Path != "" {
		parts = append(parts, "Path="+c.Path)
	}
	return strings.Join(parts, "; ")
}

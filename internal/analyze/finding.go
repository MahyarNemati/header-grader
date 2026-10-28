// Package analyze turns an observed HTTP response into graded findings.
//
// The design goal is that every point deducted can be explained. A scanner
// that says "C+" without saying why is a scoreboard, not a tool, so each
// finding carries the observed value, what was expected, and the remediation.
package analyze

import (
	"fmt"
	"sort"
	"strings"
)

// Severity orders findings by how much they matter.
type Severity int

// Severities, ascending.
const (
	// Info is an observation that costs nothing.
	Info Severity = iota
	// Low is a hardening opportunity.
	Low
	// Medium is a missing control that a real attack would use.
	Medium
	// High is a missing or broken control with a direct exploit path.
	High
	// Critical is actively dangerous, not merely absent.
	Critical
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "critical"
	case High:
		return "high"
	case Medium:
		return "medium"
	case Low:
		return "low"
	default:
		return "info"
	}
}

// MarshalText renders the severity as its name in JSON.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Category groups findings in the report.
type Category string

// Finding categories.
const (
	CategoryHeaders   Category = "headers"
	CategoryCSP       Category = "csp"
	CategoryCookies   Category = "cookies"
	CategoryTLS       Category = "tls"
	CategoryTransport Category = "transport"
	CategoryLeak      Category = "information-disclosure"
)

// Finding is one graded observation.
type Finding struct {
	// ID is a stable identifier, safe to allowlist in CI.
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	Category Category `json:"category"`
	// Points is deducted from 100. Positive findings use a negative value.
	Points int `json:"points"`
	// Observed is what the site actually sent, verbatim where that is useful.
	Observed string `json:"observed,omitempty"`
	// Expected describes what good looks like.
	Expected string `json:"expected,omitempty"`
	// Detail explains why it matters, in one or two sentences.
	Detail string `json:"detail"`
	// Fix is a copy-pasteable remediation where one exists.
	Fix string `json:"fix,omitempty"`
	// Reference is a URL for further reading.
	Reference string `json:"reference,omitempty"`
}

// Passed reports whether this finding is a credit rather than a deduction.
func (f Finding) Passed() bool { return f.Points <= 0 }

// Findings is a sortable collection.
type Findings []Finding

// Sort orders findings by severity descending, then by points descending, then
// by ID, so a report is stable across runs.
func (fs Findings) Sort() {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		if fs[i].Points != fs[j].Points {
			return fs[i].Points > fs[j].Points
		}
		return fs[i].ID < fs[j].ID
	})
}

// Deductions returns only the findings that cost points.
func (fs Findings) Deductions() Findings {
	var out Findings
	for _, f := range fs {
		if !f.Passed() {
			out = append(out, f)
		}
	}
	return out
}

// Passes returns only the findings that are credits or neutral observations.
func (fs Findings) Passes() Findings {
	var out Findings
	for _, f := range fs {
		if f.Passed() {
			out = append(out, f)
		}
	}
	return out
}

// Worst returns the highest severity among deductions, and false when there
// are none.
func (fs Findings) Worst() (Severity, bool) {
	worst, found := Info, false
	for _, f := range fs {
		if f.Passed() {
			continue
		}
		if !found || f.Severity > worst {
			worst, found = f.Severity, true
		}
	}
	return worst, found
}

// ByCategory groups findings for display.
func (fs Findings) ByCategory() map[Category]Findings {
	out := map[Category]Findings{}
	for _, f := range fs {
		out[f.Category] = append(out[f.Category], f)
	}
	return out
}

// Has reports whether a finding with the given ID is present.
func (fs Findings) Has(id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}

// truncate shortens an observed value for display without hiding that it was
// cut, so a 40 KB CSP does not fill the terminal.
func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + fmt.Sprintf("… (%d more chars)", len(s)-n)
}

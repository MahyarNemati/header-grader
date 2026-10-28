// Package grade turns findings into a score and a letter.
//
// The scoring is deliberately simple and published: start at 100, subtract
// each finding's points, clamp to [0,100]. A grader whose arithmetic you
// cannot reproduce by hand is a black box, and nobody acts on a black box.
package grade

import (
	"time"

	"github.com/MahyarNemati/header-grader/internal/analyze"
	"github.com/MahyarNemati/header-grader/internal/scan"
)

// Report is a complete graded scan.
type Report struct {
	Target    string           `json:"target"`
	Final     string           `json:"final_url"`
	Status    int              `json:"status"`
	ScannedAt time.Time        `json:"scanned_at"`
	Score     int              `json:"score"`
	Grade     string           `json:"grade"`
	Findings  analyze.Findings `json:"findings"`
	Scan      *scan.Result     `json:"scan,omitempty"`
	Counts    map[string]int   `json:"counts"`
}

// Thresholds maps the minimum score for each letter, highest first. Exported
// so the README and the tests cannot drift from the implementation.
var Thresholds = []struct {
	Min   int
	Grade string
}{
	{95, "A+"},
	{85, "A"},
	{75, "B"},
	{65, "C"},
	{50, "D"},
	{35, "E"},
	{0, "F"},
}

// Letter returns the grade for a score.
func Letter(score int) string {
	for _, t := range Thresholds {
		if score >= t.Min {
			return t.Grade
		}
	}
	return "F"
}

// Score sums the deductions. Credits (negative points) can lift a score, but
// never above 100.
func Score(fs analyze.Findings) int {
	score := 100
	for _, f := range fs {
		score -= f.Points
	}
	switch {
	case score < 0:
		return 0
	case score > 100:
		return 100
	default:
		return score
	}
}

// Build assembles a Report.
func Build(result *scan.Result, fs analyze.Findings, now time.Time) *Report {
	score := Score(fs)

	counts := map[string]int{}
	for _, f := range fs {
		if f.Passed() {
			counts["pass"]++
			continue
		}
		counts[f.Severity.String()]++
		counts["issues"]++
	}

	r := &Report{
		ScannedAt: now,
		Score:     score,
		Grade:     Letter(score),
		Findings:  fs,
		Scan:      result,
		Counts:    counts,
	}
	if result != nil {
		r.Target, r.Final, r.Status = result.Requested, result.Final, result.Status
	}
	return r
}

// Capped reports whether a finding's severity should cap the grade regardless
// of the arithmetic. A site served over plaintext HTTP cannot be an A because
// it happens to set a lot of headers.
func Capped(fs analyze.Findings) (string, bool) {
	for _, f := range fs {
		if f.Passed() {
			continue
		}
		// These two are categorically disqualifying: no amount of header
		// hygiene compensates for an unencrypted or untrusted transport.
		switch f.ID {
		case "no-tls", "cert-expired", "tls-version-obsolete", "cert-weak-signature":
			return "F", true
		}
	}
	return "", false
}

// BuildCapped is Build with the disqualifying cap applied.
func BuildCapped(result *scan.Result, fs analyze.Findings, now time.Time) *Report {
	r := Build(result, fs, now)
	if letter, capped := Capped(fs); capped {
		r.Grade = letter
	}
	return r
}

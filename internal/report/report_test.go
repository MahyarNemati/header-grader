package report_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/MahyarNemati/header-grader/internal/analyze"
	"github.com/MahyarNemati/header-grader/internal/grade"
	"github.com/MahyarNemati/header-grader/internal/report"
	"github.com/MahyarNemati/header-grader/internal/scan"
)

var now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func sample() *grade.Report {
	fs := analyze.Findings{
		{
			ID: "csp", Title: "No Content-Security-Policy", Severity: analyze.High,
			Category: analyze.CategoryCSP, Points: 25,
			Detail: "CSP is the main defence against XSS.", Fix: "Add a policy",
			Reference: "https://example.com/csp",
		},
		{
			ID: "hsts-short", Title: "HSTS max-age is short", Severity: analyze.Medium,
			Category: analyze.CategoryTransport, Points: 8, Observed: "max-age=600",
		},
		{
			ID: "tls-version", Title: "Negotiated TLS 1.3", Severity: analyze.Info,
			Category: analyze.CategoryTLS, Points: 0,
		},
	}
	fs.Sort()
	res := &scan.Result{
		Requested: "https://example.com/", Final: "https://example.com/", Status: 200,
		TLS: &scan.TLSInfo{Version: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256"},
	}
	return grade.BuildCapped(res, fs, now)
}

func TestTextIncludesScoreGradeAndFixes(t *testing.T) {
	var b strings.Builder
	if err := report.Text(&b, sample(), false); err != nil {
		t.Fatalf("Text: %v", err)
	}
	out := b.String()
	for _, want := range []string{"67/100", "grade", "No Content-Security-Policy", "fix:", "Negotiated TLS 1.3"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
}

func TestTextWithoutColorHasNoEscapes(t *testing.T) {
	var b strings.Builder
	_ = report.Text(&b, sample(), false)
	if strings.Contains(b.String(), "\033[") {
		t.Error("colour was disabled but the output contains ANSI escapes")
	}
}

func TestTextWithColorHasEscapes(t *testing.T) {
	var b strings.Builder
	_ = report.Text(&b, sample(), true)
	if !strings.Contains(b.String(), "\033[") {
		t.Error("colour was enabled but the output contains no ANSI escapes")
	}
}

func TestJSONRoundTrips(t *testing.T) {
	var b strings.Builder
	if err := report.JSON(&b, sample()); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var out struct {
		Score    int    `json:"score"`
		Grade    string `json:"grade"`
		Findings []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Points   int    `json:"points"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(b.String()), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Score != 67 {
		t.Errorf("score = %d, want 67", out.Score)
	}
	if len(out.Findings) != 3 {
		t.Fatalf("findings = %d, want 3", len(out.Findings))
	}
	// Severity must serialise as a name, not an integer, or the JSON is
	// unreadable to anything but this program.
	if out.Findings[0].Severity != "high" {
		t.Errorf("severity = %q, want \"high\"", out.Findings[0].Severity)
	}
}

func TestSARIFIsWellFormedAndOnlyContainsIssues(t *testing.T) {
	var b strings.Builder
	if err := report.SARIF(&b, sample()); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID      string `json:"id"`
						HelpURI string `json:"helpUri"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(b.String()), &doc); err != nil {
		t.Fatalf("decode SARIF: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "header-grader" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}
	// Only deductions belong in SARIF; a passing check is not an annotation.
	if len(run.Results) != 2 {
		t.Errorf("results = %d, want 2 (passes excluded)", len(run.Results))
	}
	for _, r := range run.Results {
		if r.RuleID == "tls-version" {
			t.Error("a passing finding leaked into the SARIF results")
		}
		if len(r.Locations) == 0 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Errorf("result %s has no location", r.RuleID)
		}
	}
	// High severity must map to error so code scanning surfaces it.
	for _, r := range run.Results {
		if r.RuleID == "csp" && r.Level != "error" {
			t.Errorf("csp level = %q, want error", r.Level)
		}
	}
}

func TestSARIFDeduplicatesRules(t *testing.T) {
	fs := analyze.Findings{
		{ID: "dup", Title: "x", Severity: analyze.Medium, Points: 5},
		{ID: "dup", Title: "x", Severity: analyze.Medium, Points: 5},
	}
	var b strings.Builder
	if err := report.SARIF(&b, grade.Build(nil, fs, now)); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []json.RawMessage `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	_ = json.Unmarshal([]byte(b.String()), &doc)
	if n := len(doc.Runs[0].Tool.Driver.Rules); n != 1 {
		t.Errorf("rules = %d, want 1 (deduplicated)", n)
	}
	if n := len(doc.Runs[0].Results); n != 2 {
		t.Errorf("results = %d, want 2 (both occurrences reported)", n)
	}
}

func TestTextHandlesACleanSite(t *testing.T) {
	fs := analyze.Findings{{ID: "ok", Title: "All good", Severity: analyze.Info, Points: 0}}
	var b strings.Builder
	if err := report.Text(&b, grade.Build(&scan.Result{Final: "https://x/"}, fs, now), false); err != nil {
		t.Fatalf("Text: %v", err)
	}
	if !strings.Contains(b.String(), "No issues found") {
		t.Errorf("expected a clean-site message:\n%s", b.String())
	}
}

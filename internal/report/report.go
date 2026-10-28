// Package report renders a graded scan as text, JSON, SARIF or HTML.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/MahyarNemati/header-grader/internal/analyze"
	"github.com/MahyarNemati/header-grader/internal/grade"
)

// Text writes a terminal report. color controls ANSI escapes.
func Text(w io.Writer, r *grade.Report, color bool) error {
	c := palette(color)

	fmt.Fprintf(w, "\n%s%s%s  score %d/100\n", c.bold, r.Final, c.reset, r.Score)
	fmt.Fprintf(w, "%sgrade %s%s%s\n", c.dim, gradeColor(c, r.Grade), r.Grade, c.reset)

	if r.Scan != nil && r.Scan.TLS != nil {
		fmt.Fprintf(w, "%s%s · %s%s\n", c.dim, r.Scan.TLS.Version, r.Scan.TLS.CipherSuite, c.reset)
	}
	if len(r.Scan.Redirects) > 0 {
		fmt.Fprintf(w, "%s%d redirect(s) followed%s\n", c.dim, len(r.Scan.Redirects), c.reset)
	}

	deductions := r.Findings.Deductions()
	if len(deductions) == 0 {
		fmt.Fprintf(w, "\n%sNo issues found.%s\n\n", c.green, c.reset)
		return nil
	}

	fmt.Fprintf(w, "\n%sIssues%s\n", c.bold, c.reset)

	byCat := deductions.ByCategory()
	cats := make([]string, 0, len(byCat))
	for k := range byCat {
		cats = append(cats, string(k))
	}
	sort.Strings(cats)

	for _, cat := range cats {
		fs := byCat[analyze.Category(cat)]
		fmt.Fprintf(w, "\n  %s%s%s\n", c.dim, cat, c.reset)
		for _, f := range fs {
			fmt.Fprintf(w, "    %s%-8s%s −%-3d %s\n",
				sevColor(c, f.Severity), f.Severity, c.reset, f.Points, f.Title)
			if f.Observed != "" {
				fmt.Fprintf(w, "             %sgot:    %s%s\n", c.dim, f.Observed, c.reset)
			}
			if f.Expected != "" {
				fmt.Fprintf(w, "             %swant:   %s%s\n", c.dim, f.Expected, c.reset)
			}
			if f.Detail != "" {
				fmt.Fprintf(w, "             %s%s%s\n", c.dim, wrap(f.Detail, 68, "             "), c.reset)
			}
			if f.Fix != "" {
				fmt.Fprintf(w, "             %sfix:    %s%s\n", c.cyan, f.Fix, c.reset)
			}
		}
	}

	passes := r.Findings.Passes()
	if len(passes) > 0 {
		fmt.Fprintf(w, "\n%sPassed%s\n", c.bold, c.reset)
		for _, f := range passes {
			fmt.Fprintf(w, "    %s✓%s %s\n", c.green, c.reset, f.Title)
		}
	}

	fmt.Fprintf(w, "\n%s%d issue(s): %s%s\n", c.dim, r.Counts["issues"], severitySummary(r.Counts), c.reset)
	fmt.Fprintln(w)
	return nil
}

// JSON writes the machine-readable report.
func JSON(w io.Writer, r *grade.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// SARIF writes the report in SARIF 2.1.0, so GitHub code scanning can display
// the findings as annotations.
func SARIF(w io.Writer, r *grade.Report) error {
	type sarifMessage struct {
		Text string `json:"text"`
	}
	type sarifRule struct {
		ID               string       `json:"id"`
		Name             string       `json:"name"`
		ShortDescription sarifMessage `json:"shortDescription"`
		FullDescription  sarifMessage `json:"fullDescription"`
		HelpURI          string       `json:"helpUri,omitempty"`
		Properties       struct {
			Tags     []string `json:"tags,omitempty"`
			Severity string   `json:"problem.severity,omitempty"`
		} `json:"properties"`
	}
	type sarifResult struct {
		RuleID  string       `json:"ruleId"`
		Level   string       `json:"level"`
		Message sarifMessage `json:"message"`
		// The findings are properties of a URL, not a file, so the location
		// is expressed as the scanned target rather than a source line.
		Locations []map[string]any `json:"locations"`
	}

	var (
		rules   []sarifRule
		results []sarifResult
		seen    = map[string]bool{}
	)

	for _, f := range r.Findings.Deductions() {
		if !seen[f.ID] {
			seen[f.ID] = true
			rule := sarifRule{
				ID:               f.ID,
				Name:             f.ID,
				ShortDescription: sarifMessage{Text: f.Title},
				FullDescription:  sarifMessage{Text: strings.TrimSpace(f.Detail + " " + f.Fix)},
				HelpURI:          f.Reference,
			}
			rule.Properties.Tags = []string{"security", string(f.Category)}
			rule.Properties.Severity = sarifLevel(f.Severity)
			rules = append(rules, rule)
		}
		msg := f.Title
		if f.Observed != "" {
			msg += " (observed: " + f.Observed + ")"
		}
		if f.Fix != "" {
			msg += " Fix: " + f.Fix
		}
		results = append(results, sarifResult{
			RuleID:  f.ID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: msg},
			Locations: []map[string]any{{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{"uri": r.Final},
				},
			}},
		})
	}

	doc := map[string]any{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":           "header-grader",
					"informationUri": "https://github.com/MahyarNemati/header-grader",
					"rules":          rules,
				},
			},
			"results": results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifLevel(s analyze.Severity) string {
	switch s {
	case analyze.Critical, analyze.High:
		return "error"
	case analyze.Medium:
		return "warning"
	default:
		return "note"
	}
}

func severitySummary(counts map[string]int) string {
	var parts []string
	for _, k := range []string{"critical", "high", "medium", "low"} {
		if n := counts[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, k))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

type colors struct {
	reset, bold, dim, red, yellow, green, cyan, magenta string
}

func palette(on bool) colors {
	if !on {
		return colors{}
	}
	return colors{
		reset: "\033[0m", bold: "\033[1m", dim: "\033[2m",
		red: "\033[31m", yellow: "\033[33m", green: "\033[32m",
		cyan: "\033[36m", magenta: "\033[35m",
	}
}

func sevColor(c colors, s analyze.Severity) string {
	switch s {
	case analyze.Critical:
		return c.magenta
	case analyze.High:
		return c.red
	case analyze.Medium:
		return c.yellow
	case analyze.Low:
		return c.cyan
	default:
		return c.dim
	}
}

func gradeColor(c colors, g string) string {
	switch {
	case strings.HasPrefix(g, "A"):
		return c.green
	case g == "B", g == "C":
		return c.yellow
	default:
		return c.red
	}
}

// wrap hard-wraps text at n columns, indenting continuation lines.
func wrap(s string, n int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	line := 0
	for i, w := range words {
		if line > 0 && line+1+len(w) > n {
			b.WriteString("\n" + indent)
			line = 0
		} else if i > 0 {
			b.WriteString(" ")
			line++
		}
		b.WriteString(w)
		line += len(w)
	}
	return b.String()
}

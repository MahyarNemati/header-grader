package grade_test

import (
	"testing"
	"time"

	"github.com/MahyarNemati/header-grader/internal/analyze"
	"github.com/MahyarNemati/header-grader/internal/grade"
	"github.com/MahyarNemati/header-grader/internal/scan"
)

var now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func TestScoreIsPlainSubtraction(t *testing.T) {
	// The whole point of the model is that you can check it by hand.
	fs := analyze.Findings{
		{ID: "a", Points: 25},
		{ID: "b", Points: 10},
		{ID: "c", Points: 0},
	}
	if got := grade.Score(fs); got != 65 {
		t.Errorf("Score = %d, want 65", got)
	}
}

func TestScoreIsClampedToZero(t *testing.T) {
	fs := analyze.Findings{{ID: "a", Points: 200}}
	if got := grade.Score(fs); got != 0 {
		t.Errorf("Score = %d, want 0", got)
	}
}

func TestCreditsCannotExceedOneHundred(t *testing.T) {
	fs := analyze.Findings{{ID: "a", Points: -50}}
	if got := grade.Score(fs); got != 100 {
		t.Errorf("Score = %d, want 100", got)
	}
}

func TestLetterMatchesThresholds(t *testing.T) {
	// Drive this from the exported table so the README, the tests and the
	// implementation cannot drift apart.
	for _, th := range grade.Thresholds {
		if got := grade.Letter(th.Min); got != th.Grade {
			t.Errorf("Letter(%d) = %q, want %q", th.Min, got, th.Grade)
		}
	}
	if got := grade.Letter(100); got != "A+" {
		t.Errorf("Letter(100) = %q, want A+", got)
	}
	if got := grade.Letter(0); got != "F" {
		t.Errorf("Letter(0) = %q, want F", got)
	}
}

func TestLetterBoundariesAreInclusive(t *testing.T) {
	for _, tc := range []struct {
		score int
		want  string
	}{
		{95, "A+"}, {94, "A"}, {85, "A"}, {84, "B"},
		{75, "B"}, {74, "C"}, {65, "C"}, {64, "D"},
		{50, "D"}, {49, "E"}, {35, "E"}, {34, "F"},
	} {
		if got := grade.Letter(tc.score); got != tc.want {
			t.Errorf("Letter(%d) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

func TestPlaintextCapsTheGradeAtF(t *testing.T) {
	// A site with no TLS but otherwise perfect headers must not score an A.
	fs := analyze.Findings{{ID: "no-tls", Points: 30, Severity: analyze.Critical}}
	r := grade.BuildCapped(nil, fs, now)
	if r.Grade != "F" {
		t.Errorf("grade = %q, want F; score was %d", r.Grade, r.Score)
	}
}

func TestExpiredCertificateCapsTheGrade(t *testing.T) {
	for _, id := range []string{"cert-expired", "tls-version-obsolete", "cert-weak-signature"} {
		fs := analyze.Findings{{ID: id, Points: 1, Severity: analyze.Critical}}
		r := grade.BuildCapped(nil, fs, now)
		if r.Grade != "F" {
			t.Errorf("%s: grade = %q, want F (score %d)", id, r.Grade, r.Score)
		}
	}
}

func TestCapDoesNotApplyToAPassingFinding(t *testing.T) {
	// A positive finding with one of the capped IDs must not drag the grade.
	fs := analyze.Findings{{ID: "no-tls", Points: 0, Severity: analyze.Info}}
	r := grade.BuildCapped(nil, fs, now)
	if r.Grade == "F" {
		t.Error("a passing finding should not cap the grade")
	}
}

func TestCountsSummariseSeverities(t *testing.T) {
	fs := analyze.Findings{
		{ID: "a", Points: 10, Severity: analyze.High},
		{ID: "b", Points: 5, Severity: analyze.Medium},
		{ID: "c", Points: 5, Severity: analyze.Medium},
		{ID: "d", Points: 0, Severity: analyze.Info},
	}
	r := grade.Build(nil, fs, now)
	if r.Counts["high"] != 1 || r.Counts["medium"] != 2 || r.Counts["pass"] != 1 {
		t.Errorf("counts = %v", r.Counts)
	}
	if r.Counts["issues"] != 3 {
		t.Errorf("issues = %d, want 3", r.Counts["issues"])
	}
}

func TestBuildCarriesTargetDetails(t *testing.T) {
	res := &scan.Result{Requested: "https://a.example/", Final: "https://b.example/", Status: 200}
	r := grade.Build(res, nil, now)
	if r.Target != "https://a.example/" || r.Final != "https://b.example/" || r.Status != 200 {
		t.Errorf("report = %+v", r)
	}
}

func TestWorstIgnoresPassingFindings(t *testing.T) {
	fs := analyze.Findings{
		{ID: "pass", Points: 0, Severity: analyze.Critical},
		{ID: "real", Points: 5, Severity: analyze.Medium},
	}
	worst, found := fs.Worst()
	if !found {
		t.Fatal("expected a worst severity")
	}
	if worst != analyze.Medium {
		t.Errorf("worst = %s, want medium (the critical one is a pass)", worst)
	}
}

func TestWorstReportsNoneWhenEverythingPasses(t *testing.T) {
	fs := analyze.Findings{{ID: "a", Points: 0, Severity: analyze.Info}}
	if _, found := fs.Worst(); found {
		t.Error("expected no worst severity when there are no deductions")
	}
}

// Command header-grader scans a site's security headers, TLS, CSP and cookies
// and grades them.
//
//	header-grader https://example.com
//	header-grader -format json example.com
//	header-grader -format sarif -o results.sarif example.com
//	header-grader -fail-under 85 example.com      # exit 1 below the threshold
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/MahyarNemati/header-grader/internal/analyze"
	"github.com/MahyarNemati/header-grader/internal/grade"
	"github.com/MahyarNemati/header-grader/internal/report"
	"github.com/MahyarNemati/header-grader/internal/scan"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// Exit codes are distinct so this composes in a pipeline: a scan that could
// not run is a different problem from a scan that found issues.
const (
	exitOK       = 0
	exitFindings = 1
	exitUsage    = 2
	exitScan     = 3
)

func main() { os.Exit(run()) }

func run() int {
	var (
		format      = flag.String("format", "text", "text, json or sarif")
		out         = flag.String("o", "", "write to a file instead of stdout")
		failUnder   = flag.Int("fail-under", -1, "exit 1 when the score is below this (0-100)")
		failOn      = flag.String("fail-on", "", "exit 1 when a finding of this severity or worse is present: low, medium, high, critical")
		timeout     = flag.Duration("timeout", 15*time.Second, "overall request timeout")
		noColor     = flag.Bool("no-color", false, "disable ANSI colour")
		userAgent   = flag.String("user-agent", "", "override the User-Agent")
		skipTLSProb = flag.Bool("no-tls-probe", false, "skip probing for obsolete TLS versions (two fewer connections)")
		skipHTTP    = flag.Bool("no-http-probe", false, "skip checking whether http:// redirects to https://")
		showVersion = flag.Bool("version", false, "print the version and exit")
		ignore      = flag.String("ignore", "", "comma-separated finding IDs to exclude")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Println("header-grader", version)
		return exitOK
	}
	if flag.NArg() != 1 {
		usage()
		return exitUsage
	}

	minSeverity, err := parseSeverity(*failOn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsage
	}
	if *failUnder > 100 {
		fmt.Fprintln(os.Stderr, "-fail-under must be between 0 and 100")
		return exitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	scanner := scan.New(scan.Options{
		Timeout:          *timeout,
		UserAgent:        *userAgent,
		ProbeTLSVersions: !*skipTLSProb,
		ProbeHTTP:        !*skipHTTP,
	})

	result, err := scanner.Scan(ctx, flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		return exitScan
	}

	now := time.Now()
	findings := filter(analyze.Run(result, now), *ignore)
	rep := grade.BuildCapped(result, findings, now)

	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "create %s: %v\n", *out, err)
			return exitScan
		}
		defer f.Close()
		w = f
	}

	color := !*noColor && *out == "" && isTerminal()
	switch strings.ToLower(*format) {
	case "text":
		err = report.Text(w, rep, color)
	case "json":
		err = report.JSON(w, rep)
	case "sarif":
		err = report.SARIF(w, rep)
	default:
		fmt.Fprintf(os.Stderr, "unknown -format %q (want text, json or sarif)\n", *format)
		return exitUsage
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "write report: %v\n", err)
		return exitScan
	}

	// Gate on the score, the severity, or neither.
	if *failUnder >= 0 && rep.Score < *failUnder {
		fmt.Fprintf(os.Stderr, "score %d is below the threshold of %d\n", rep.Score, *failUnder)
		return exitFindings
	}
	if minSeverity != nil {
		if worst, found := findings.Worst(); found && worst >= *minSeverity {
			fmt.Fprintf(os.Stderr, "found a %s finding (threshold %s)\n", worst, *minSeverity)
			return exitFindings
		}
	}
	return exitOK
}

func usage() {
	fmt.Fprint(os.Stderr, `header-grader - grade a site's security headers, TLS, CSP and cookies

usage: header-grader [flags] <url>

  A bare hostname is assumed to be https://.

flags:
`)
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, `
exit codes:
  0  scanned, and any gate passed
  1  a gate failed (-fail-under or -fail-on)
  2  bad usage
  3  the scan itself failed

examples:
  header-grader example.com
  header-grader -format json -o report.json example.com
  header-grader -format sarif -o results.sarif example.com
  header-grader -fail-on high example.com
`)
}

func parseSeverity(s string) (*analyze.Severity, error) {
	if s == "" {
		return nil, nil
	}
	var sev analyze.Severity
	switch strings.ToLower(s) {
	case "low":
		sev = analyze.Low
	case "medium":
		sev = analyze.Medium
	case "high":
		sev = analyze.High
	case "critical":
		sev = analyze.Critical
	default:
		return nil, fmt.Errorf("unknown -fail-on %q (want low, medium, high or critical)", s)
	}
	return &sev, nil
}

// filter drops findings whose ID the caller has chosen to ignore, so a known
// and accepted deviation does not keep a pipeline red.
func filter(fs analyze.Findings, ignore string) analyze.Findings {
	if strings.TrimSpace(ignore) == "" {
		return fs
	}
	skip := map[string]bool{}
	for _, id := range strings.Split(ignore, ",") {
		if id = strings.TrimSpace(id); id != "" {
			skip[id] = true
		}
	}
	var out analyze.Findings
	for _, f := range fs {
		if !skip[f.ID] {
			out = append(out, f)
		}
	}
	return out
}

// isTerminal reports whether stdout is a character device, so piping the
// output does not fill it with escape codes.
func isTerminal() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

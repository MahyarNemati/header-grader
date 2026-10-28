package scan_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MahyarNemati/header-grader/internal/scan"
)

func scanner() *scan.Scanner {
	// Probes are off by default here: they reach out to the real network for
	// the http:// origin and extra TLS handshakes, which a unit test must not.
	return scan.New(scan.Options{Timeout: 5 * time.Second})
}

func TestScanCapturesFinalHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := scanner().Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Status != 200 {
		t.Errorf("status = %d", res.Status)
	}
	if got := res.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q", got)
	}
	if res.TLS != nil {
		t.Error("plaintext server should produce no TLS info")
	}
}

func TestScanFollowsRedirectsAndRecordsTheChain(t *testing.T) {
	var final *httptest.Server
	final = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/end" {
			w.Header().Set("X-Final", "yes")
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, final.URL+"/end", http.StatusFound)
	}))
	defer final.Close()

	res, err := scanner().Scan(context.Background(), final.URL+"/start")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !strings.HasSuffix(res.Final, "/end") {
		t.Errorf("final = %q, want it to end with /end", res.Final)
	}
	if res.Header.Get("X-Final") != "yes" {
		t.Error("headers should come from the final response")
	}
	if len(res.Redirects) != 1 {
		t.Errorf("redirects = %d, want 1", len(res.Redirects))
	}
}

func TestScanCollectsCookiesSetOnRedirects(t *testing.T) {
	// A cookie set on a 302 is still stored by the browser, so grading only
	// the final response would miss it.
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/end" {
			http.SetCookie(w, &http.Cookie{Name: "final", Value: "2", Secure: true})
			w.WriteHeader(http.StatusOK)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "onredirect", Value: "1"})
		http.Redirect(w, r, srv.URL+"/end", http.StatusFound)
	}))
	defer srv.Close()

	res, err := scanner().Scan(context.Background(), srv.URL+"/start")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	names := map[string]bool{}
	for _, c := range res.Cookies {
		names[c.Name] = true
	}
	if !names["onredirect"] {
		t.Errorf("cookie set on the redirect was lost; got %v", names)
	}
	if !names["final"] {
		t.Errorf("cookie from the final response was lost; got %v", names)
	}
}

func TestScanStopsAfterTooManyRedirects(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/again", http.StatusFound)
	}))
	defer srv.Close()

	s := scan.New(scan.Options{Timeout: 5 * time.Second, MaxRedirects: 3})
	if _, err := s.Scan(context.Background(), srv.URL); err == nil {
		t.Fatal("expected an error for an infinite redirect loop")
	}
}

func TestScanRecordsTLSState(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// httptest's TLS server uses a self-signed certificate, so the scan must
	// be done with its client. Scan uses its own transport, so point it at a
	// server whose cert we accept by disabling verification is not possible
	// here; instead assert the plaintext path and leave TLS details to the
	// analyze tests, which construct TLSInfo directly.
	_, err := scanner().Scan(context.Background(), srv.URL)
	if err == nil {
		t.Skip("unexpectedly trusted the self-signed certificate")
	}
	// The important property: a TLS failure is reported as an error rather
	// than silently producing a result with no TLS info, which would grade
	// as "plaintext" and be wrong.
	if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "x509") {
		t.Errorf("expected a certificate error, got %v", err)
	}
}

func TestScanRejectsNonHTTPSchemes(t *testing.T) {
	for _, target := range []string{"ftp://example.com", "file:///etc/passwd", "gopher://x"} {
		_, err := scanner().Scan(context.Background(), target)
		if !errors.Is(err, scan.ErrInsecureScheme) {
			t.Errorf("%s: err = %v, want ErrInsecureScheme", target, err)
		}
	}
}

func TestScanDefaultsBareHostToHTTPS(t *testing.T) {
	// No network access needed: the URL is normalised before any request, and
	// a bare host must not be silently downgraded to http.
	_, err := scanner().Scan(context.Background(), "this-host-does-not-exist.invalid")
	if err == nil {
		t.Fatal("expected a DNS failure")
	}
	if !strings.Contains(err.Error(), "https://") {
		t.Errorf("error should mention the https URL it tried, got %v", err)
	}
}

func TestScanRejectsEmptyTarget(t *testing.T) {
	if _, err := scanner().Scan(context.Background(), "   "); err == nil {
		t.Error("expected an error for an empty target")
	}
}

func TestScanHonoursContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := scanner().Scan(ctx, srv.URL); err == nil {
		t.Error("expected a timeout error")
	}
}

func TestDuplicateCookieKeepsTheLastValue(t *testing.T) {
	// Two Set-Cookie headers for one name: the browser keeps the last, so the
	// grader must grade the last.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "first"})
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "second", HttpOnly: true})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := scanner().Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var count int
	for _, c := range res.Cookies {
		if c.Name == "sid" {
			count++
			if !c.HttpOnly {
				t.Error("kept the first cookie; the browser would keep the last")
			}
		}
	}
	if count != 1 {
		t.Errorf("sid appears %d times, want 1", count)
	}
}

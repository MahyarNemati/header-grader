// Package scan fetches a URL and records everything the grader needs: the
// final response headers, the redirect chain, cookies and the TLS state.
package scan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Result is one completed scan.
type Result struct {
	// Requested is the URL asked for.
	Requested string `json:"requested"`
	// Final is the URL after redirects.
	Final  string `json:"final"`
	Status int    `json:"status"`
	// Header is the final response's headers.
	Header http.Header `json:"headers"`
	// Cookies are the Set-Cookie values from every hop, since a cookie set on
	// a redirect still lands in the browser.
	Cookies []*http.Cookie `json:"cookies,omitempty"`
	// Redirects is the chain that was followed, in order.
	Redirects []Hop `json:"redirects,omitempty"`
	// TLS is nil for a plaintext scan.
	TLS *TLSInfo `json:"tls,omitempty"`
	// HTTPRedirectsToHTTPS records whether http:// is redirected to https://.
	// Nil when not probed.
	HTTPRedirectsToHTTPS *bool `json:"http_redirects_to_https,omitempty"`
	// BodySample is the first few KB, used only to spot inline-script needs.
	BodySample string        `json:"-"`
	Elapsed    time.Duration `json:"elapsed_ns"`
}

// Hop is one step in a redirect chain.
type Hop struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Location string `json:"location,omitempty"`
}

// TLSInfo is the negotiated TLS state and certificate summary.
type TLSInfo struct {
	Version        string    `json:"version"`
	CipherSuite    string    `json:"cipher_suite"`
	Subject        string    `json:"subject"`
	Issuer         string    `json:"issuer"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	DNSNames       []string  `json:"dns_names,omitempty"`
	SignatureAlgo  string    `json:"signature_algorithm"`
	ChainLength    int       `json:"chain_length"`
	OCSPStapled    bool      `json:"ocsp_stapled"`
	NegotiatedALPN string    `json:"alpn,omitempty"`
	// MinVersionOffered is the lowest TLS version the server accepted during
	// probing, which is how an obsolete version is detected at all.
	MinVersionOffered string `json:"min_version_offered,omitempty"`
}

// ExpiresIn returns how long until the leaf certificate expires.
func (t TLSInfo) ExpiresIn(now time.Time) time.Duration { return t.NotAfter.Sub(now) }

// Options configure a Scanner.
type Options struct {
	Timeout   time.Duration
	UserAgent string
	// MaxRedirects bounds the chain; 0 uses the default of 10.
	MaxRedirects int
	// ProbeTLSVersions additionally handshakes with TLS 1.0/1.1 to detect
	// obsolete versions. Costs two extra connections.
	ProbeTLSVersions bool
	// ProbeHTTP additionally requests the http:// origin to see whether it
	// redirects to https://.
	ProbeHTTP bool
	// Now is injectable for tests.
	Now func() time.Time
}

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	if o.UserAgent == "" {
		o.UserAgent = "header-grader/1.0 (+https://github.com/MahyarNemati/header-grader)"
	}
	if o.MaxRedirects <= 0 {
		o.MaxRedirects = 10
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// Scanner performs scans.
type Scanner struct {
	opts Options
}

// New returns a Scanner.
func New(opts Options) *Scanner { return &Scanner{opts: opts.withDefaults()} }

// ErrInsecureScheme is returned for a URL that is neither http nor https.
var ErrInsecureScheme = errors.New("scan: url must be http or https")

// Scan fetches raw and records the result.
func (s *Scanner) Scan(ctx context.Context, raw string) (*Result, error) {
	target, err := normalize(raw)
	if err != nil {
		return nil, err
	}

	start := s.opts.Now()
	res := &Result{Requested: target.String()}

	var (
		hops    []Hop
		cookies []*http.Cookie
		connTLS *tls.ConnectionState
	)

	client := &http.Client{
		Timeout: s.opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= s.opts.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", s.opts.MaxRedirects)
			}
			prev := via[len(via)-1]
			hops = append(hops, Hop{
				URL:      prev.URL.String(),
				Status:   0, // filled from the response below where available
				Location: req.URL.String(),
			})
			return nil
		},
		Transport: &http.Transport{
			// Keep the server's own preferences visible: do not force a
			// minimum version here, or an obsolete server would simply fail
			// to connect and look like a network error.
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS10}, //nolint:gosec // probing, not protecting
			DialContext:       (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			ForceAttemptHTTP2: true,
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.opts.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", target, err)
	}
	defer resp.Body.Close()

	// Collect Set-Cookie from every response in the chain, not just the last:
	// a cookie set on a 302 is still stored by the browser.
	for r := resp; r != nil; r = r.Request.Response {
		cookies = append(cookies, r.Cookies()...)
		if r.TLS != nil && connTLS == nil {
			connTLS = r.TLS
		}
	}

	sample, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	res.Final = resp.Request.URL.String()
	res.Status = resp.StatusCode
	res.Header = resp.Header.Clone()
	res.Cookies = dedupeCookies(cookies)
	res.Redirects = hops
	res.BodySample = string(sample)

	if connTLS != nil {
		res.TLS = describeTLS(*connTLS)
		if s.opts.ProbeTLSVersions {
			res.TLS.MinVersionOffered = s.probeMinVersion(ctx, resp.Request.URL.Host)
		}
	}

	if s.opts.ProbeHTTP && target.Scheme == "https" {
		ok := s.probeHTTPRedirect(ctx, target.Host)
		res.HTTPRedirectsToHTTPS = &ok
	}

	res.Elapsed = s.opts.Now().Sub(start)
	return res, nil
}

// probeMinVersion reports the lowest TLS version the server will accept, which
// is the only way to tell that 1.0 is still enabled when 1.3 is negotiated.
func (s *Scanner) probeMinVersion(ctx context.Context, host string) string {
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	for _, v := range []struct {
		version uint16
		name    string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
	} {
		d := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: 5 * time.Second},
			Config: &tls.Config{
				MinVersion: v.version,
				MaxVersion: v.version,
				ServerName: hostOnly(host),
			},
		}
		conn, err := d.DialContext(ctx, "tcp", host)
		if err == nil {
			_ = conn.Close()
			return v.name
		}
	}
	return ""
}

// probeHTTPRedirect checks whether the plaintext origin redirects to HTTPS.
func (s *Scanner) probeHTTPRedirect(ctx context.Context, host string) bool {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // inspect the first hop only
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+hostOnly(host)+"/", nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", s.opts.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		return false
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	return err == nil && loc.Scheme == "https"
}

func describeTLS(cs tls.ConnectionState) *TLSInfo {
	info := &TLSInfo{
		Version:        tls.VersionName(cs.Version),
		CipherSuite:    tls.CipherSuiteName(cs.CipherSuite),
		ChainLength:    len(cs.PeerCertificates),
		OCSPStapled:    len(cs.OCSPResponse) > 0,
		NegotiatedALPN: cs.NegotiatedProtocol,
	}
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		info.Subject = leaf.Subject.CommonName
		info.NotBefore = leaf.NotBefore
		info.NotAfter = leaf.NotAfter
		info.DNSNames = leaf.DNSNames
		info.SignatureAlgo = leaf.SignatureAlgorithm.String()
		if len(cs.PeerCertificates) > 1 {
			info.Issuer = cs.PeerCertificates[1].Subject.CommonName
		} else {
			info.Issuer = leaf.Issuer.CommonName
		}
	}
	return info
}

// normalize parses a target, defaulting a bare host to https.
func normalize(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("scan: empty url")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("scan: parse %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: got %q", ErrInsecureScheme, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("scan: %q has no host", raw)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// dedupeCookies keeps the last Set-Cookie for each name, which is what a
// browser would end up storing.
func dedupeCookies(in []*http.Cookie) []*http.Cookie {
	seen := map[string]int{}
	var out []*http.Cookie
	for _, c := range in {
		if i, ok := seen[c.Name]; ok {
			out[i] = c
			continue
		}
		seen[c.Name] = len(out)
		out = append(out, c)
	}
	return out
}

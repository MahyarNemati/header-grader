# header-grader

[![CI](https://github.com/MahyarNemati/header-grader/actions/workflows/ci.yml/badge.svg)](https://github.com/MahyarNemati/header-grader/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/MahyarNemati/header-grader)](https://goreportcard.com/report/github.com/MahyarNemati/header-grader)

Grades a site's security headers, CSP, cookies and TLS, and tells you **why**
each point was deducted and exactly how to fix it. Outputs text, JSON or SARIF,
with exit codes designed for CI.

```bash
go install github.com/MahyarNemati/header-grader/cmd/header-grader@latest

header-grader github.com
header-grader -format sarif -o results.sarif example.com
header-grader -fail-on high example.com     # exit 1 if anything high or worse
```

```
https://example.com/  score 20/100
grade F

Issues

  csp
    high     −25  No Content-Security-Policy
             want:   a policy with default-src, object-src 'none', base-uri 'none'
             CSP is the main defence-in-depth control against cross-site
             scripting. Without it, any injected markup executes with the
             page's full privileges.
             fix:    Content-Security-Policy: default-src 'self'; object-src 'none'; …
```

## Why another header scanner

Because most of them check **presence, not value**, and presence is the easy
part. A site can have every recommended header and still be wide open:

```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
```

That is a CSP. A presence check gives it full marks. It also permits any inline
`<script>` — which is precisely what an XSS payload is — so it provides
essentially no XSS protection. This tool grades it **critical**.

The other half is explanation. A grader that says "C+" without saying why is a
scoreboard, so every finding carries the observed value, what was expected, why
it matters, and a copy-pasteable fix.

## What it actually checks

### Content-Security-Policy

The policy is parsed, not pattern-matched, which lets it catch the mistakes
that matter:

- **`'unsafe-inline'` in `script-src`** — critical, unless a nonce or hash is
  also present, in which case it is a correct old-browser fallback (browsers
  that understand nonces ignore `'unsafe-inline'`) and scores almost nothing.
- **`base-uri` and `form-action` missing.** These are the ones people get
  wrong, because **they do not inherit from `default-src`**. A policy of just
  `default-src 'self'` leaves both unrestricted: injected markup can add a
  `<base>` tag and repoint every relative script URL on the page, or repoint a
  form at an attacker's server.
- **Wildcards** (`*`, `https:`, `data:`) in directives where they defeat the
  point. `data:` in `script-src` is particularly bad — it lets a payload be
  inlined as a data URI, bypassing any host allow-list.
- **`'unsafe-eval'`**, and **`'strict-dynamic'`** as a *credit*, since it
  neutralises host allow-lists.
- **Unrecognised directives.** Browsers silently ignore a misspelling, so
  `script-source` looks like protection and provides none.
- **Report-only policies**, which collect violations and block nothing. The
  correct way to roll a policy out, and no protection once you are done.

### Cookies

Severity depends on what the cookie appears to be: a missing `Secure` flag on
`sessionid` is graded far harder than on `theme`. Checks `Secure`, `HttpOnly`,
`SameSite`, the `__Host-`/`__Secure-` prefixes, and session lifetime.

Two details worth knowing:

- **`SameSite=None` without `Secure` is graded high**, because browsers reject
  that combination outright — the cookie is discarded and whatever depended on
  it is silently broken.
- **A cookie named like a CSRF token is exempt from `HttpOnly`**, because a
  double-submit token has to be readable by JavaScript by design. Flagging it
  would be a false positive, and false positives are how a tool gets ignored.

Cookie values are **redacted** in all output, so a report can be pasted into a
ticket without leaking a live session.

### TLS

Negotiated version, cipher suite, certificate expiry, signature algorithm and
chain completeness — plus, with `-no-tls-probe` off, the **lowest version the
server still accepts**. That last one matters: a server can negotiate TLS 1.3
with your browser while still accepting TLS 1.0 from anyone who asks, and only
a separate handshake reveals it.

Missing intermediate certificates are flagged too. That one commonly works in
a browser (which caches intermediates) and fails in `curl` or a mobile app,
which makes it a miserable bug to diagnose from a bug report.

### Headers

HSTS (including `max-age=0`, which switches HSTS *off*, and a max-age below the
180-day preload floor), framing — where **CSP `frame-ancestors` correctly
satisfies the check and `X-Frame-Options` is not then required** —
`X-Content-Type-Options`, `Referrer-Policy` (flagging the policies that leak
full URLs cross-origin), `Permissions-Policy`, COOP/CORP, and the obsolete
`X-XSS-Protection` and `Feature-Policy`.

Also two things most scanners miss:

- **Duplicate security headers.** Browsers combine them by taking the most
  restrictive result, which is rarely what either layer intended — usually the
  application and a proxy are both setting it.
- **Version banners.** `Server: nginx/1.25.3` scores worse than
  `Server: nginx`, because a version number lets an attacker skip
  reconnaissance.

### Information disclosure and caching

`Server`, `X-Powered-By`, `X-AspNet-Version` and friends, and a response that
sets cookies while marked `Cache-Control: public` — where a shared cache may
serve one user's `Set-Cookie` to another. A public page being cacheable is
correct and is *not* flagged.

## Scoring

Start at 100, subtract each finding's points, clamp to 0–100. That is the whole
model, deliberately: a score you cannot reproduce by hand is a black box, and
nobody acts on a black box.

| Score | Grade |
|---|---|
| 95+ | A+ |
| 85+ | A |
| 75+ | B |
| 65+ | C |
| 50+ | D |
| 35+ | E |
| below 35 | F |

The thresholds are exported as `grade.Thresholds` and the tests iterate over
that table, so this README cannot drift from the implementation.

**Some findings cap the grade at F** regardless of arithmetic: no TLS, an
expired certificate, an obsolete TLS version, or a broken signature algorithm.
A site served over plaintext HTTP should not be able to reach an A by setting a
lot of headers.

## CI use

Exit codes are distinct, so a scan that *could not run* is a different problem
from a scan that *found something*:

| Code | Meaning |
|---|---|
| 0 | scanned, gates passed |
| 1 | a gate failed (`-fail-under` or `-fail-on`) |
| 2 | bad usage |
| 3 | the scan itself failed |

```yaml
- name: Grade security headers
  run: |
    go run github.com/MahyarNemati/header-grader/cmd/header-grader@latest \
      -format sarif -o results.sarif -fail-on high https://staging.example.com

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

SARIF means the findings appear as annotations in the GitHub Security tab
rather than buried in log output. `-ignore csp-no-form-action,coop` drops
findings you have assessed and accepted, so an accepted deviation does not keep
a pipeline red forever.

## Flags

```
-format text|json|sarif   output format (default text)
-o <file>                 write to a file instead of stdout
-fail-under <0-100>       exit 1 below this score
-fail-on <severity>       exit 1 at low|medium|high|critical or worse
-ignore <id,id>           exclude findings by ID
-timeout <duration>       overall request timeout (default 15s)
-no-tls-probe             skip the obsolete-TLS-version probe (2 fewer connections)
-no-http-probe            skip the http:// → https:// redirect check
-no-color                 disable ANSI colour
-user-agent <ua>          override the User-Agent
-version
```

Colour is disabled automatically when stdout is not a terminal, so piping the
output does not fill it with escape codes.

## Layout

```
cmd/header-grader/   CLI, exit codes
internal/scan/       fetch, redirect chain, cookies from every hop, TLS state
internal/analyze/    the checks: headers.go, csp.go, cookies.go, tls.go
internal/grade/      scoring and letter thresholds
internal/report/     text, JSON and SARIF renderers
```

The split matters: `scan` only observes, `analyze` only judges, `grade` only
counts. That is what makes the checks testable without a network — the tests
construct a `scan.Result` directly and assert on findings.

## Development

```bash
make test        # unit tests, no network required
make test-race   # with the race detector (needs working cgo)
make lint
make demo        # grade a couple of real sites
```

CI additionally scans a live site end to end and asserts the JSON and SARIF are
well formed — including that every SARIF result references a declared rule, and
that the exit-code gates actually gate. It deliberately does **not** assert a
particular score for someone else's site, which would make this build fail
whenever they deploy.

## Limitations

- **One URL per run.** No crawling, so a site is graded by whichever page you
  point at. Headers often differ between the landing page and an authenticated
  route.
- **No authenticated scans.** Cookie grading sees only what an anonymous
  request sets, which usually excludes the real session cookie.
- **Cipher suite grading reflects one negotiation**, not the server's full
  accepted list. For an exhaustive cipher and protocol audit, use
  [testssl.sh](https://testssl.sh) or SSL Labs.
- **CSP is graded statically.** It cannot tell whether a nonce is genuinely
  per-response and unpredictable, which is the difference between a strict CSP
  and a bypassable one.
- **The session-cookie heuristic is name-based**, so an unusually named session
  cookie is graded as a preference cookie.
- **No HTTP/3 or alt-svc analysis.**

## License

MIT — see [LICENSE](LICENSE).

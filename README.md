# Automated Web Scanner

A Python command-line tool that audits a website for common security misconfigurations: missing security headers, insecure cookies, information disclosure, HTTPS redirect problems and CORS flaws. It produces a console summary, a JSON file and a standalone HTML report, plus a 0-100 security score.

> **Legal notice:** Only scan websites you own or have explicit written permission to test. The tool asks for confirmation before every scan.

## Features

| Area | Checks |
|------|--------|
| Security headers | HSTS (presence and max-age), Content-Security-Policy (missing, `unsafe-inline`/`unsafe-eval`), X-Frame-Options / `frame-ancestors`, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| Cookies | Missing `Secure`, `HttpOnly`, `SameSite` flags |
| Information disclosure | Version numbers in `Server`, `X-Powered-By`, `X-AspNet-Version` |
| Transport | Target served over HTTP; HTTP not redirecting to HTTPS |
| CORS | Reflected arbitrary origin, reflected `null` origin, wildcard with credentials, wildcard policy, preflight allowing DELETE/PUT/PATCH |

Each finding has a severity (HIGH / MEDIUM / LOW / INFO), a description and a recommended fix.

## Installation

```bash
git clone <your-repo-url>
cd <repo-folder>
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Requires Python 3.8+.

## Usage

```bash
# Basic scan (asks for authorization confirmation)
python web_scanner.py https://example.com

# Skip the prompt, save JSON and HTML reports
python web_scanner.py https://example.com --yes --json results.json --html report.html
```

| Option | Description |
|--------|-------------|
| `url` | Target URL (https:// is assumed if omitted) |
| `--json FILE` | Save results as JSON |
| `--html FILE` | Save a colour-coded HTML report |
| `--timeout N` | Request timeout in seconds (default 10) |
| `--yes` | Confirm you are authorized to test the target |

## Example output

Scan of a local test server built with deliberate flaws (`sample_output.json`):

```
Target: http://127.0.0.1:8099
Score: 14/100  Findings: 11

[HIGH  ] CORS       Reflects arbitrary origin with credentials
[HIGH  ] CORS       Reflects null origin with credentials
[MEDIUM] Headers    Missing Content-Security-Policy
[MEDIUM] Headers    Clickjacking protection missing
[MEDIUM] Cookies    Cookie 'session' missing flags
...
```

## Scoring

The score starts at 100 and loses 15 points per HIGH, 8 per MEDIUM and 3 per LOW finding (INFO costs nothing). Deductions are capped per severity (60 / 40 / 12) so many minor issues cannot outweigh a serious one. Minimum score is 0.

## Performance and reliability

- A single pooled `requests.Session` reuses connections across checks.
- Automatic retries (with backoff) on connection errors and 502/503/504 responses.
- Independent checks (HTTPS redirect, CORS) run in parallel threads.
- Cookies are not stored between requests, so one check cannot affect another.

## Tests

```bash
python -m unittest test_scanner -v
```

## Limitations

- Passive checks only; it does not exploit anything or crawl the site.
- Only the given URL is analysed, not every page or subdomain.
- It reports misconfigurations, not application-logic vulnerabilities such as XSS or SQL injection.
- Results should be reviewed manually; some findings may be acceptable for a given site.

## Project structure

```
web_scanner.py      main script
test_scanner.py     unit tests
requirements.txt    dependencies
README.md           this file
```

## Possible improvements

Multi-URL and sitemap scanning, TLS certificate and cipher checks, `security.txt` detection, CI integration that fails builds below a score threshold.

## License

MIT

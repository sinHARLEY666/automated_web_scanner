#!/usr/bin/env python3
"""
Automated Web Scanner - audits a website for security header issues,
insecure cookies, information disclosure and CORS misconfigurations.

Passive checks only: it sends a handful of ordinary HTTP requests.
Only scan sites you own or have written permission to test.
"""
import argparse
import html
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from http.cookiejar import DefaultCookiePolicy
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
TIMEOUT = 10
UA = "WebSecScanner/1.1 (authorized security audit)"


def make_session():
    """One pooled session with retries; cookies are not stored between requests."""
    sess = requests.Session()
    retry = Retry(total=2, connect=1, backoff_factor=0.3,
                  status_forcelist=(502, 503, 504),
                  allowed_methods=("GET", "OPTIONS", "HEAD"))
    adapter = HTTPAdapter(max_retries=retry, pool_connections=8, pool_maxsize=8)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    sess.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))
    sess.headers["User-Agent"] = UA
    return sess


SESSION = make_session()


def finding(severity, category, title, detail, fix=""):
    return {"severity": severity, "category": category, "title": title,
            "detail": detail, "fix": fix}


# ---------------------------------------------------------------- headers
def check_headers(resp):
    out = []
    h = resp.headers
    is_https = resp.url.lower().startswith("https://")

    if is_https:
        hsts = h.get("Strict-Transport-Security")
        if not hsts:
            out.append(finding("MEDIUM", "Headers", "Missing HSTS",
                "Strict-Transport-Security header not set.",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"))
        elif "max-age" in hsts:
            try:
                age = int(hsts.split("max-age=")[1].split(";")[0].strip())
                if age < 15768000:
                    out.append(finding("LOW", "Headers", "Weak HSTS max-age",
                        f"max-age is {age}s (under 6 months).",
                        "Use max-age of at least 31536000."))
            except ValueError:
                pass

    csp = h.get("Content-Security-Policy")
    if not csp:
        out.append(finding("MEDIUM", "Headers", "Missing Content-Security-Policy",
            "No CSP header; XSS impact is not limited by the browser.",
            "Define a restrictive policy, e.g. default-src 'self'."))
    else:
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            out.append(finding("MEDIUM", "Headers", "CSP allows unsafe directives",
                "CSP contains 'unsafe-inline' or 'unsafe-eval'.",
                "Use nonces or hashes instead."))
        if "default-src" not in csp and "script-src" not in csp:
            out.append(finding("LOW", "Headers", "CSP lacks default-src/script-src",
                "Policy does not restrict script sources.",
                "Add default-src or script-src."))

    if not h.get("X-Frame-Options") and "frame-ancestors" not in (csp or ""):
        out.append(finding("MEDIUM", "Headers", "Clickjacking protection missing",
            "Neither X-Frame-Options nor CSP frame-ancestors is set.",
            "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'."))

    if h.get("X-Content-Type-Options", "").lower() != "nosniff":
        out.append(finding("LOW", "Headers", "Missing X-Content-Type-Options",
            "Browsers may MIME-sniff responses.",
            "Add: X-Content-Type-Options: nosniff"))

    if not h.get("Referrer-Policy"):
        out.append(finding("LOW", "Headers", "Missing Referrer-Policy",
            "Full URLs may leak to third parties via the Referer header.",
            "Add: Referrer-Policy: strict-origin-when-cross-origin"))

    if not h.get("Permissions-Policy"):
        out.append(finding("INFO", "Headers", "Missing Permissions-Policy",
            "Browser features (camera, geolocation...) are not restricted.",
            "Add a Permissions-Policy header."))

    for name in ("Server", "X-Powered-By", "X-AspNet-Version"):
        val = h.get(name)
        if val and any(c.isdigit() for c in val):
            out.append(finding("LOW", "Disclosure", f"{name} reveals version",
                f"{name}: {val}", f"Remove or genericize the {name} header."))
    return out


# ---------------------------------------------------------------- cookies
def check_cookies(resp):
    out = []
    try:
        raw = resp.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        sc = resp.headers.get("Set-Cookie")
        raw = [sc] if sc else []
    for c in raw:
        low = c.lower()
        name = c.split("=", 1)[0].strip()
        missing = []
        if "secure" not in low and resp.url.startswith("https"):
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            out.append(finding("MEDIUM" if "Secure" in missing or "HttpOnly" in missing else "LOW",
                "Cookies", f"Cookie '{name}' missing flags",
                "Missing: " + ", ".join(missing),
                "Set Secure; HttpOnly; SameSite=Lax (or Strict)."))
    return out


# ---------------------------------------------------------------- https
def check_https_redirect(url):
    out = []
    p = urlparse(url)
    if p.scheme != "https":
        out.append(finding("HIGH", "Transport", "Site scanned over HTTP",
            "Target URL is not HTTPS.", "Serve the site over HTTPS."))
        return out
    http_url = url.replace("https://", "http://", 1)
    try:
        r = SESSION.get(http_url, allow_redirects=False, timeout=TIMEOUT)
        loc = r.headers.get("Location", "")
        if not (300 <= r.status_code < 400 and loc.startswith("https://")):
            out.append(finding("MEDIUM", "Transport", "HTTP does not redirect to HTTPS",
                f"{http_url} returned {r.status_code}.",
                "Redirect all HTTP traffic to HTTPS."))
    except requests.RequestException:
        pass  # port 80 closed is fine
    return out


# ---------------------------------------------------------------- CORS
def check_cors(url):
    out = []
    tests = [
        ("arbitrary origin", "https://evil.example"),
        ("null origin", "null"),
    ]
    for label, origin in tests:
        try:
            r = SESSION.get(url, headers={"Origin": origin}, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if not acao:
            continue
        if acao == origin and acac:
            out.append(finding("HIGH", "CORS", f"Reflects {label} with credentials",
                f"ACAO: {acao}, ACAC: true. Any site can read authenticated responses.",
                "Validate Origin against a strict allow-list."))
        elif acao == origin:
            out.append(finding("MEDIUM", "CORS", f"Reflects {label}",
                f"ACAO echoes the supplied Origin ({origin}).",
                "Validate Origin against a strict allow-list."))
        elif acao == "*" and acac:
            out.append(finding("HIGH", "CORS", "Wildcard origin with credentials",
                "ACAO: * together with ACAC: true.",
                "Never combine wildcard with credentials."))
        elif acao == "*" and label == "arbitrary origin":
            out.append(finding("LOW", "CORS", "Wildcard CORS policy",
                "ACAO: * allows any site to read public responses.",
                "Restrict to known origins if the data is not public."))
    # preflight
    try:
        r = SESSION.options(url, headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "DELETE"}, timeout=TIMEOUT)
        methods = r.headers.get("Access-Control-Allow-Methods", "")
        if r.headers.get("Access-Control-Allow-Origin") and \
                any(m in methods.upper() for m in ("DELETE", "PUT", "PATCH")):
            out.append(finding("MEDIUM", "CORS", "Preflight allows state-changing methods",
                f"Allow-Methods: {methods}", "Limit allowed methods and origins."))
    except requests.RequestException:
        pass
    return out


# ---------------------------------------------------------------- reports
def score(findings):
    pts = {"HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
    cap = {"HIGH": 60, "MEDIUM": 40, "LOW": 12, "INFO": 0}
    total = 0
    for sev in pts:
        n = sum(1 for f in findings if f["severity"] == sev)
        total += min(n * pts[sev], cap[sev])
    return max(0, 100 - total)


def to_html(target, findings, sc):
    colors = {"HIGH": "#c0392b", "MEDIUM": "#e67e22", "LOW": "#f1c40f", "INFO": "#3498db"}
    rows = "".join(
        f"<tr><td style='background:{colors[f['severity']]};color:#fff;font-weight:bold'>"
        f"{f['severity']}</td><td>{html.escape(f['category'])}</td>"
        f"<td>{html.escape(f['title'])}</td><td>{html.escape(f['detail'])}</td>"
        f"<td>{html.escape(f['fix'])}</td></tr>" for f in findings)
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Scan Report</title>
<style>body{{font-family:Arial,sans-serif;margin:2em}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:6px;font-size:14px;vertical-align:top}}th{{background:#222;color:#fff}}</style>
</head><body><h1>Web Security Scan</h1><p><b>Target:</b> {html.escape(target)}<br>
<b>Date:</b> {datetime.now(timezone.utc).isoformat(timespec='seconds')}<br>
<b>Score:</b> {sc}/100 &nbsp; <b>Findings:</b> {len(findings)}</p>
<table><tr><th>Severity</th><th>Category</th><th>Issue</th><th>Detail</th><th>Fix</th></tr>{rows}</table>
</body></html>"""


def scan(url):
    findings = []
    try:
        resp = SESSION.get(url, timeout=TIMEOUT)
    except requests.RequestException as e:
        print(f"[!] Could not reach {url}: {e}", file=sys.stderr)
        sys.exit(2)
    with ThreadPoolExecutor(max_workers=4) as pool:
        jobs = [pool.submit(check_https_redirect, resp.url),
                pool.submit(check_cors, resp.url)]
        findings += check_headers(resp) + check_cookies(resp)
        for j in jobs:
            findings += j.result()
    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    return findings


def main():
    global TIMEOUT
    ap = argparse.ArgumentParser(description="Audit a site for security headers, cookies and CORS flaws.")
    ap.add_argument("url", help="Target URL, e.g. https://example.com")
    ap.add_argument("--json", metavar="FILE", help="Write JSON results to FILE")
    ap.add_argument("--html", metavar="FILE", help="Write HTML report to FILE")
    ap.add_argument("--timeout", type=int, default=TIMEOUT, help="Request timeout in seconds (default 10)")
    ap.add_argument("--yes", action="store_true",
                    help="Confirm you are authorized to test this target (skips prompt)")
    args = ap.parse_args()
    TIMEOUT = args.timeout

    url = args.url if "://" in args.url else "https://" + args.url
    if not args.yes:
        ans = input(f"Do you own or have permission to test {url}? [y/N] ")
        if ans.strip().lower() != "y":
            print("Aborted.")
            sys.exit(1)

    findings = scan(url)
    sc = score(findings)
    print(f"\nTarget: {url}\nScore: {sc}/100  Findings: {len(findings)}\n")
    for f in findings:
        print(f"[{f['severity']:<6}] {f['category']:<10} {f['title']}\n          {f['detail']}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"target": url, "score": sc, "findings": findings}, fh, indent=2)
        print(f"\nJSON saved to {args.json}")
    if args.html:
        with open(args.html, "w") as fh:
            fh.write(to_html(url, findings, sc))
        print(f"HTML report saved to {args.html}")


if __name__ == "__main__":
    main()

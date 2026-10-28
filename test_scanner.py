"""Run with:  python -m unittest test_scanner -v"""
import unittest
from types import SimpleNamespace

import web_scanner as ws


def fake_resp(headers, url="https://example.com/"):
    return SimpleNamespace(headers=headers, url=url,
                           raw=SimpleNamespace(headers=SimpleNamespace(
                               getlist=lambda n: [headers["Set-Cookie"]] if "Set-Cookie" in headers else [])))


def titles(findings):
    return {f["title"] for f in findings}


class HeaderTests(unittest.TestCase):
    def test_missing_headers_flagged(self):
        t = titles(ws.check_headers(fake_resp({})))
        self.assertIn("Missing HSTS", t)
        self.assertIn("Missing Content-Security-Policy", t)
        self.assertIn("Clickjacking protection missing", t)

    def test_good_headers_clean(self):
        good = {"Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=()"}
        self.assertEqual(ws.check_headers(fake_resp(good)), [])

    def test_unsafe_csp(self):
        r = fake_resp({"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"})
        self.assertIn("CSP allows unsafe directives", titles(ws.check_headers(r)))

    def test_version_disclosure(self):
        self.assertIn("Server reveals version",
                      titles(ws.check_headers(fake_resp({"Server": "Apache/2.4.1"}))))


class CookieTests(unittest.TestCase):
    def test_insecure_cookie(self):
        self.assertTrue(ws.check_cookies(fake_resp({"Set-Cookie": "id=1; Path=/"})))

    def test_secure_cookie(self):
        c = "id=1; Secure; HttpOnly; SameSite=Lax"
        self.assertEqual(ws.check_cookies(fake_resp({"Set-Cookie": c})), [])


class ScoreTests(unittest.TestCase):
    def test_perfect(self):
        self.assertEqual(ws.score([]), 100)

    def test_caps_and_floor(self):
        many_low = [{"severity": "LOW"}] * 50
        self.assertEqual(ws.score(many_low), 88)
        self.assertGreaterEqual(ws.score([{"severity": "HIGH"}] * 99 + [{"severity": "MEDIUM"}] * 99), 0)


if __name__ == "__main__":
    unittest.main()

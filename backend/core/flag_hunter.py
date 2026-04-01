"""
Flag Hunter v4 — Aggressive flag detection for all major CTF platforms.
"""
import re, base64

NAMED_PATTERNS = [
    r"picoCTF\{[^}]+\}", r"HTB\{[^}]+\}", r"THM\{[^}]+\}",
    r"IIITK\{[^}]+\}", r"TAJ\{[^}]+\}", r"csyclub\{[^}]+\}",
    r"flag\{[^}]+\}", r"FLAG\{[^}]+\}",
    r"(?<![A-Za-z0-9_])CTF\{[^}]+\}",
    r"pico[_\-]?ctf[_\-]?\{[^}]+\}",
    r"DUCTF\{[^}]+\}", r"UTCTF\{[^}]+\}", r"BCACTF\{[^}]+\}",
    r"UIUCTF\{[^}]+\}", r"NahamCTF\{[^}]+\}",
    r"INCTF\{[^}]+\}", r"darkCTF\{[^}]+\}",
    r"HackTheBox\{[^}]+\}", r"TryHackMe\{[^}]+\}",
    r"DEFCON\{[^}]+\}", r"GoogleCTF\{[^}]+\}",
    r"fbctf\{[^}]+\}", r"CSAW\{[^}]+\}",
    r"redpwnCTF\{[^}]+\}", r"angstromCTF\{[^}]+\}",
    r"InCTF\{[^}]+\}", r"TJCTF\{[^}]+\}",
    r"corCTF\{[^}]+\}", r"zh3r0\{[^}]+\}",
    r"zer0pts\{[^}]+\}", r"hxp\{[^}]+\}",
    r"b01lers\{[^}]+\}", r"m0leCon\{[^}]+\}",
    r"bi0sCTF\{[^}]+\}", r"VishwaCTF\{[^}]+\}",
    r"nullcon\{[^}]+\}", r"BITSCTF\{[^}]+\}",
    r"CTFSG\{[^}]+\}", r"imaginaryctf\{[^}]+\}",
    r"ImaginaryCTF\{[^}]+\}", r"pbctf\{[^}]+\}",
    r"ACSC\{[^}]+\}", r"PlaidCTF\{[^}]+\}",
    r"WPI\{[^}]+\}", r"RITSEC\{[^}]+\}",
    r"CakeCTF\{[^}]+\}", r"fword\{[^}]+\}",
    r"snyk\{[^}]+\}", r"0CTF\{[^}]+\}",
    r"TWCTF\{[^}]+\}", r"SECCON\{[^}]+\}",
    r"ACECTF\{[^}]+\}", r"BSides\{[^}]+\}",
]

GENERIC_PATTERN = r"[A-Za-z0-9_]{2,20}\{[A-Za-z0-9_\-!@#$%^&*()+=/\\:;,.?<>|\s]{3,200}\}"

HEX_PATTERNS = [
    r"\b[0-9a-f]{32}\b",
    r"\b[0-9a-f]{40}\b",
    r"\b[0-9a-f]{64}\b",
]

COMMENT_PATTERNS = [
    r"<!--\s*([^<]*(?:flag|FLAG|CTF|secret)[^<]*)\s*-->",
    r'data-flag=["\']([^"\']+)["\']',
    r'data-secret=["\']([^"\']+)["\']',
]

B64_FLAG_PATTERN = re.compile(r"(?:flag|FLAG|CTF|secret)[_\-=:\s]*([A-Za-z0-9+/]{20,}={0,2})", re.IGNORECASE)

EXCLUDE_EXACT = {"0" * 32, "f" * 32, "0" * 40, "f" * 40}


class FlagHunter:
    @staticmethod
    def hunt(text: str) -> list:
        if not text:
            return []
        found: set = set()

        for pat in NAMED_PATTERNS:
            for m in re.finditer(pat, text, re.IGNORECASE):
                found.add(m.group(0))

        snapshot = set(found)
        for m in re.finditer(GENERIC_PATTERN, text, re.IGNORECASE):
            candidate = m.group(0)
            if candidate in EXCLUDE_EXACT:
                continue
            if any(candidate in named for named in snapshot):
                continue
            inner = candidate.split("{", 1)[-1].rstrip("}")
            if len(inner) >= 3 and not inner.isspace():
                found.add(candidate)

        for pat in HEX_PATTERNS:
            for m in re.finditer(pat, text, re.IGNORECASE):
                candidate = m.group(0)
                if candidate not in EXCLUDE_EXACT:
                    found.add(candidate)

        for pat in COMMENT_PATTERNS:
            for m in re.finditer(pat, text, re.IGNORECASE | re.DOTALL):
                val = m.group(1).strip()
                if len(val) >= 5:
                    inner_flags = FlagHunter.hunt(val)
                    found.update(inner_flags)
                    if any(kw in val.lower() for kw in ("ctf{", "flag{", "htb{", "thm{")):
                        found.add(val[:200])

        for m in B64_FLAG_PATTERN.finditer(text):
            try:
                decoded = base64.b64decode(m.group(1) + "==").decode("utf-8", errors="ignore")
                found.update(FlagHunter.hunt(decoded))
            except Exception:
                pass

        return list(found)

    @staticmethod
    def hunt_response(response) -> list:
        if response is None:
            return []
        flags = FlagHunter.hunt(response.text)
        for hval in response.headers.values():
            flags.extend(FlagHunter.hunt(hval))
        for cval in response.cookies.values():
            flags.extend(FlagHunter.hunt(cval))
        return list(set(flags))

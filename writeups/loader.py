"""
TAJ-CTF-Engine · Writeup Loader (Future Use)
Parses CTF writeups from GitHub and extracts automation patterns.

Usage (future):
    loader = WriteupLoader("https://github.com/CSYClubIIITK/CTF-Writeups")
    patterns = loader.extract_patterns()
"""

import re
import json
from pathlib import Path


class WriteupLoader:
    """
    Loads CTF writeups from a local directory or GitHub URL and
    extracts exploitation patterns, payloads, and technique hints
    to feed into the automation modules.
    """

    TECHNIQUE_PATTERNS = {
        "sqli":  [r"union\s+select", r"sql\s+inject", r"sqlmap", r"--\s*$"],
        "xss":   [r"<script>", r"onerror=", r"xss", r"alert\("],
        "ssti":  [r"\{\{.*\}\}", r"template\s+inject", r"jinja2", r"twig"],
        "lfi":   [r"\.\.\/", r"php://filter", r"local\s+file", r"/etc/passwd"],
        "cmdi":  [r";\s*id\b", r";\s*whoami", r"command\s+inject", r"\|\s*cat"],
        "jwt":   [r"jwt", r"json\s+web\s+token", r"alg.*none", r"hs256"],
        "ssrf":  [r"ssrf", r"server.side\s+request", r"169\.254", r"metadata"],
        "idor":  [r"idor", r"insecure\s+direct", r"object\s+reference"],
        "xxe":   [r"xxe", r"xml\s+external", r"<!entity", r"<!doctype"],
        "nosql": [r"nosql", r"\$ne", r"\$gt", r"mongodb", r"operator"],
    }

    def __init__(self, source: str = None):
        self.source   = source
        self.writeups = []

    def load_directory(self, path: str) -> list:
        """Load all .md writeup files from a directory."""
        root = Path(path)
        self.writeups = []
        for md_file in root.rglob("*.md"):
            content = md_file.read_text(errors="replace")
            self.writeups.append({
                "file":    str(md_file),
                "content": content,
            })
        return self.writeups

    def extract_patterns(self) -> dict:
        """
        Analyze loaded writeups and return dict of
        technique -> list of extracted payloads/patterns.
        """
        extracted = {k: [] for k in self.TECHNIQUE_PATTERNS}
        for wu in self.writeups:
            text = wu["content"].lower()
            for technique, pats in self.TECHNIQUE_PATTERNS.items():
                for pat in pats:
                    if re.search(pat, text, re.IGNORECASE):
                        extracted[technique].append({
                            "source":  wu["file"],
                            "pattern": pat,
                        })
                        break
        return extracted

    def extract_payloads_from_code_blocks(self) -> list:
        """Pull payloads from markdown code blocks in writeups."""
        payloads = []
        code_re  = re.compile(r"```(?:\w+)?\n(.*?)```", re.DOTALL)
        for wu in self.writeups:
            for block in code_re.findall(wu["content"]):
                payloads.append({
                    "source":  wu["file"],
                    "payload": block.strip(),
                })
        return payloads

    def save_extracted(self, output_path: str):
        """Save extracted patterns to JSON for module use."""
        data = {
            "patterns": self.extract_patterns(),
            "payloads": self.extract_payloads_from_code_blocks(),
        }
        Path(output_path).write_text(json.dumps(data, indent=2))
        print(f"[WriteupLoader] Saved to {output_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    loader = WriteupLoader()
    loader.load_directory(path)
    patterns = loader.extract_patterns()
    print(json.dumps(patterns, indent=2))

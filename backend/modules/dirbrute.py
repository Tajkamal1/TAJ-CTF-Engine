"""
DirBrute Module — Aggressively brute-forces directories and files for CTF flags.
Focuses on CTF-specific paths, common web app paths, and source code leaks.
"""
from backend.core.base_module import BaseModule
from backend.core.flag_hunter import FlagHunter

CTF_PATHS = [
    # Direct flag files
    "/flag", "/flag.txt", "/flag.php", "/flag.html", "/flag.json",
    "/FLAG", "/FLAG.txt", "/flag/", "/flags",
    "/secret", "/secret.txt", "/secret.php", "/secret/",
    "/hidden", "/hidden.txt", "/hidden/",
    "/answer", "/answer.txt",
    # Common CTF endpoints
    "/api/flag", "/api/flags", "/api/secret", "/api/get_flag",
    "/api/v1/flag", "/api/v1/flags", "/api/v2/flag",
    "/get_flag", "/getflag", "/giveflag", "/show_flag", "/showflag",
    "/read_flag", "/readflag", "/capture", "/win", "/solved",
    # Admin / backend
    "/admin", "/admin/", "/admin/flag", "/admin/flags",
    "/admin/panel", "/admin/secret", "/admin/config",
    "/admin/users", "/admin/login", "/admin/debug",
    "/dashboard", "/panel", "/control",
    "/console", "/debug", "/debug/",
    # Debug / dev
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.php", "/config.py", "/config.json", "/config.yaml", "/config.yml",
    "/settings.py", "/settings.php", "/settings.json",
    "/app.py", "/app.php", "/app.js", "/server.py", "/server.js",
    "/index.php.bak", "/index.bak", "/backup.php",
    "/web.config", "/wp-config.php",
    # Source code leaks
    "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
    "/.svn/entries", "/.hg/hgrc",
    "/source", "/source.php", "/src",
    "/download", "/download.php",
    "/robots.txt", "/sitemap.xml",
    # Proc / system
    "/proc/self/environ", "/proc/1/environ",
    "/etc/passwd", "/etc/hosts",
    # Upload / files
    "/upload", "/uploads/", "/files/", "/data/",
    "/static/flag.txt", "/assets/flag.txt",
    "/public/flag.txt", "/download/flag.txt",
    # Various flag locations in containers
    "/home/ctf/flag.txt", "/home/user/flag.txt",
    "/root/flag.txt", "/var/flag.txt",
    "/opt/flag.txt", "/app/flag.txt",
    "/srv/flag.txt", "/challenge/flag.txt",
    # Endpoints
    "/ping", "/health", "/status", "/version",
    "/whoami", "/id", "/info",
    # PHP wrappers (for some PHP challenges)
    "/index.php?file=flag.txt", "/index.php?page=flag",
    "/index.php?id=1'",
    # JWT / auth
    "/token", "/tokens", "/auth", "/authenticate",
    "/login", "/register",
    # CTF platform-specific
    "/chal", "/challenge", "/task", "/problem",
    "/note", "/notes", "/comment", "/comments",
    "/message", "/messages",
]

SUCCESS_CODES = {200, 201, 301, 302, 307, 308}


class DirBruteModule(BaseModule):
    MODULE_NAME = "dirbrute"
    DESCRIPTION = "Directory & Endpoint Bruteforce (CTF-optimized)"

    def run(self) -> dict:
        self.log(f"[DIRBRUTE] Starting on {self.target_url}")

        from urllib.parse import urlparse
        parsed = urlparse(self.target_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        found_count = 0
        for path in CTF_PATHS:
            url = base + path
            r = self.requester.raw_get(url)
            if r is None:
                continue
            if r.status_code not in SUCCESS_CODES:
                continue

            found_count += 1
            self.log(f"[DIRBRUTE] HIT [{r.status_code}] {url}")
            flags = FlagHunter.hunt(r.text)
            if flags:
                for f in flags:
                    self.add_flag(f)
                self.add_vuln({"type": "flag_at_path", "url": url, "flags": flags})
                self.log(f"[DIRBRUTE] 🚩 FLAG at {url}: {flags}")

            # Check headers too
            for hval in r.headers.values():
                hflags = FlagHunter.hunt(hval)
                [self.add_flag(f) for f in hflags]

        self.log(f"[DIRBRUTE] Scanned {len(CTF_PATHS)} paths, {found_count} accessible")
        if self.results["status"] == "pending":
            self.results["status"] = "not_vulnerable" if not self.results["flags"] else "vulnerable"
        return self.results

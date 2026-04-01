"""
TAJ-CTF-Engine · Aggressive Site Crawler
Discovers all endpoints, forms, params, JS vars, comments, and API paths.
"""
import re
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from backend.core.flag_hunter import FlagHunter

COMMON_PATHS = [
    "/", "/index", "/index.php", "/index.html",
    "/flag", "/flag.txt", "/flag.php", "/flag/", "/flag/index",
    "/secret", "/secret.txt", "/secret/", "/hidden",
    "/admin", "/admin/", "/admin/panel", "/admin/dashboard",
    "/api", "/api/flag", "/api/flags", "/api/secret", "/api/admin",
    "/api/v1/flag", "/api/v1/user", "/api/v1/admin",
    "/debug", "/debug/", "/.env", "/config", "/config.php",
    "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.git/config",
    "/backup", "/backup.zip", "/backup.sql",
    "/source", "/source.php", "/src",
    "/console", "/shell", "/cmd", "/exec",
    "/login", "/register", "/logout", "/dashboard",
    "/user", "/users", "/profile", "/account",
    "/upload", "/uploads", "/files", "/download",
    "/search", "/query", "/find",
    "/page", "/view", "/read", "/show",
    "/note", "/notes", "/post", "/posts",
    "/comment", "/comments", "/message", "/messages",
    "/ticket", "/tickets", "/board",
    "/logs", "/log", "/error", "/errors",
    "/test", "/demo", "/dev", "/staging",
    "/health", "/status", "/ping", "/version",
    "/token", "/tokens", "/key", "/keys",
    "/static/flag.txt", "/data/flag.txt",
    "/var/flag.txt", "/tmp/flag.txt",
    "/home/flag.txt", "/root/flag.txt",
    "/proc/self/environ", "/proc/1/environ",
    "/etc/passwd", "/etc/hosts",
    "/app/flag.txt", "/srv/flag.txt",
    "/challenge/flag", "/challenge/flag.txt",
    "/ctf/flag", "/ctf/flag.txt",
    "/id_rsa", "/.ssh/id_rsa",
    "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/pma",
]

JS_SECRET_PATTERNS = [
    r"flag\s*[=:]\s*[\"']([^\"']{5,100})[\"']",
    r"FLAG\s*[=:]\s*[\"']([^\"']{5,100})[\"']",
    r"secret\s*[=:]\s*[\"']([^\"']{5,100})[\"']",
    r"password\s*[=:]\s*[\"']([^\"']{5,100})[\"']",
    r"api_key\s*[=:]\s*[\"']([^\"']{5,100})[\"']",
    r"token\s*[=:]\s*[\"']([^\"']{5,100})[\"']",
]

HTML_COMMENT_FLAG_PATTERN = re.compile(r"<!--(.*?)-->", re.DOTALL)
DATA_ATTR_PATTERN = re.compile(r'data-[a-z\-]+=["\']([^"\']*flag[^"\']*)["\']', re.IGNORECASE)


class Crawler:
    def __init__(self, base_url: str, requester, max_pages: int = 30):
        self.base_url  = base_url.rstrip("/")
        self.parsed    = urlparse(base_url)
        self.requester = requester
        self.max_pages = max_pages
        self.visited   = set()
        self.endpoints = []   # list of dicts: {url, forms, params, flags_found}
        self.all_flags = []
        self.all_forms = []
        self.all_links = []
        self.js_secrets = []
        self.logs      = []

    def log(self, msg):
        self.logs.append(msg)

    def crawl(self) -> dict:
        """Main crawl entry point. Returns summary."""
        self.log(f"[CRAWLER] Starting crawl on {self.base_url}")

        # 1. Brute-force common paths
        self._brute_common_paths()

        # 2. Spider from homepage
        self._spider(self.base_url, depth=3)

        self.log(f"[CRAWLER] Found {len(self.endpoints)} endpoints, "
                 f"{len(self.all_forms)} forms, {len(self.all_flags)} flags")
        return {
            "endpoints": self.endpoints,
            "flags":     list(set(self.all_flags)),
            "forms":     self.all_forms,
            "links":     list(set(self.all_links)),
            "js_secrets": self.js_secrets,
            "logs":      self.logs,
        }

    def _brute_common_paths(self):
        for path in COMMON_PATHS:
            if len(self.visited) >= self.max_pages:
                break
            url = self.base_url + path
            if url in self.visited:
                continue
            self.visited.add(url)
            r = self.requester.raw_get(url)
            if r is None or r.status_code in (404, 403, 400):
                continue
            self.log(f"[CRAWLER] Found: {url} [{r.status_code}]")
            self._process_response(url, r)

    def _spider(self, url: str, depth: int = 3):
        if depth == 0 or len(self.visited) >= self.max_pages:
            return
        if url in self.visited:
            return
        self.visited.add(url)
        r = self.requester.raw_get(url)
        if r is None or r.status_code == 404:
            return
        self._process_response(url, r)
        # Recurse on same-domain links
        links = self._extract_links(r.text, url)
        for link in links:
            self._spider(link, depth - 1)

    def _process_response(self, url: str, resp) -> None:
        from backend.core.parser import Parser
        if resp is None:
            return
        text = resp.text

        # Hunt flags in response
        flags = FlagHunter.hunt(text)
        self.all_flags.extend(flags)

        # Extract forms
        forms = Parser.extract_forms(text)
        for f in forms:
            f["source_url"] = url
        self.all_forms.extend(forms)

        # Extract links
        links = self._extract_links(text, url)
        self.all_links.extend(links)

        # Extract JS secrets
        for pat in JS_SECRET_PATTERNS:
            for m in re.finditer(pat, text, re.IGNORECASE):
                val = m.group(1)
                if len(val) > 4:
                    self.js_secrets.append({"url": url, "value": val, "pattern": pat})

        # Check HTML comments
        for m in HTML_COMMENT_FLAG_PATTERN.finditer(text):
            comment = m.group(1)
            cf = FlagHunter.hunt(comment)
            self.all_flags.extend(cf)
            if any(kw in comment.lower() for kw in ("flag", "secret", "password", "key", "token")):
                self.js_secrets.append({"url": url, "value": comment.strip()[:100], "pattern": "html_comment"})

        # URL params
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        self.endpoints.append({
            "url":    url,
            "forms":  forms,
            "params": list(params.keys()),
            "flags":  flags,
            "status": resp.status_code,
        })

    def _extract_links(self, html: str, base: str) -> list:
        from bs4 import BeautifulSoup
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return []
        links = []
        base_domain = self.parsed.netloc
        for tag in soup.find_all(["a", "form", "script"], href=True):
            href = tag.get("href") or tag.get("action") or tag.get("src", "")
            if not href:
                continue
            full = urljoin(base, href)
            parsed_link = urlparse(full)
            if parsed_link.netloc == base_domain and full not in self.visited:
                links.append(full)
        # Also extract from JS src= attributes
        for tag in soup.find_all("script", src=True):
            src = tag["src"]
            full = urljoin(base, src)
            if urlparse(full).netloc == base_domain:
                links.append(full)
        return links

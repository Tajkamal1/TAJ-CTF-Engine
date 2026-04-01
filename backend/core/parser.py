"""HTML and response parser utilities."""
import re
try:
    from bs4 import BeautifulSoup
    # BUG FIX: 'lxml' may not be installed in all environments.
    # Determine the best available parser at import time.
    try:
        import lxml  # noqa: F401
        _PARSER = "lxml"
    except ImportError:
        _PARSER = "html.parser"  # stdlib fallback — always available
except ImportError:
    raise ImportError("beautifulsoup4 is required: pip install beautifulsoup4")


class Parser:
    @staticmethod
    def parse_html(html: str) -> BeautifulSoup:
        return BeautifulSoup(html, _PARSER)

    @staticmethod
    def extract_forms(html: str) -> list:
        soup  = BeautifulSoup(html, _PARSER)
        forms = []
        for form in soup.find_all("form"):
            inputs = []
            for tag in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name":  tag.get("name", ""),
                    "type":  tag.get("type", "text"),
                    "value": tag.get("value", ""),
                })
            forms.append({
                "action":  form.get("action", ""),
                "method":  form.get("method", "get").upper(),
                "inputs":  inputs,
            })
        return forms

    @staticmethod
    def extract_links(html: str, base_url: str = "") -> list:
        soup  = BeautifulSoup(html, _PARSER)
        links = set()
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("http"):
                links.add(href)
            elif href.startswith("/"):
                links.add(base_url.rstrip("/") + href)
        return list(links)

    @staticmethod
    def find_error_messages(html: str) -> list:
        patterns = [
            r"(SQL syntax.*MySQL)",
            r"(Warning.*mysql_.*)",
            r"(MySQLSyntaxErrorException)",
            r"(valid MySQL result)",
            r"(check the manual that corresponds)",
            r"(ORA-\d{5})",
            r"(PostgreSQL.*ERROR)",
            r"(Driver.*SQL Server)",
            r"(syntax error.*unexpected)",
            r"(Uncaught.*Exception)",
        ]
        errors = []
        for pat in patterns:
            m = re.search(pat, html, re.IGNORECASE)
            if m:
                errors.append(m.group(0))
        return errors

    @staticmethod
    def extract_cookies(response) -> dict:
        return dict(response.cookies) if response else {}

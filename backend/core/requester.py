"""HTTP requester with session management, proxy support, and timeout handling."""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


DEFAULT_HEADERS = {
    "User-Agent": "TAJ-CTF-Engine/1.0 (CTF Automation Tool)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


class Requester:
    def __init__(self, base_url: str, options: dict = None):
        self.base_url = base_url
        self.options  = options or {}
        self.session  = self._build_session()

    def _build_session(self) -> requests.Session:
        s       = requests.Session()
        retry   = Retry(total=3, backoff_factor=0.3,
                        status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("http://",  adapter)
        s.mount("https://", adapter)
        s.headers.update(DEFAULT_HEADERS)
        if self.options.get("cookies"):
            s.cookies.update(self.options["cookies"])
        if self.options.get("headers"):
            s.headers.update(self.options["headers"])
        if self.options.get("proxy"):
            s.proxies = {"http": self.options["proxy"],
                         "https": self.options["proxy"]}
        return s

    def get(self, url: str = None, params: dict = None, **kwargs):
        url = url or self.base_url
        try:
            return self.session.get(url, params=params,
                                    timeout=self.options.get("timeout", 10),
                                    verify=False, **kwargs)
        except Exception:
            return None

    def post(self, url: str = None, data: dict = None,
             json_data: dict = None, **kwargs):
        url = url or self.base_url
        try:
            return self.session.post(url, data=data, json=json_data,
                                     timeout=self.options.get("timeout", 10),
                                     verify=False, **kwargs)
        except Exception:
            return None

    def raw_get(self, url: str, **kwargs):
        """GET using the session (BUG FIX: was requests.get() — session cookies/headers
        were lost, breaking authenticated SSTI targets)."""
        try:
            return self.session.get(url,
                                    timeout=self.options.get("timeout", 10),
                                    verify=False, **kwargs)
        except Exception:
            return None

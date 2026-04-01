"""Base class for all exploitation modules."""
import os, json
from abc import ABC, abstractmethod
from backend.core.requester import Requester


class BaseModule(ABC):
    MODULE_NAME = "base"
    DESCRIPTION = "Base exploitation module"

    def __init__(self, target_url: str, options: dict = None):
        self.target_url = target_url.rstrip("/")
        self.options    = options or {}
        self.requester  = Requester(target_url, options)
        self.results    = {"module": self.MODULE_NAME, "status": "pending",
                           "vulnerabilities": [], "flags": [], "logs": []}
        self._payloads  = self._load_payloads()

    def _load_payloads(self) -> dict:
        path = os.path.join(
            os.path.dirname(__file__), "..", "payloads",
            f"{self.MODULE_NAME}.json"
        )
        try:
            with open(path) as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def log(self, msg: str):
        self.results["logs"].append(msg)

    def add_vuln(self, vuln: dict):
        self.results["vulnerabilities"].append(vuln)
        self.results["status"] = "vulnerable"

    def add_flag(self, flag: str):
        # BUG FIX: deduplicate flags — prevent identical flags being added
        # multiple times when the same payload is tried across different code paths.
        if flag not in self.results["flags"]:
            self.results["flags"].append(flag)

    @abstractmethod
    def run(self) -> dict:
        """Execute the module and return results dict."""
        ...

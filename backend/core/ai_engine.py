"""AI-powered hint engine — powered by Claude API (future integration)."""
import os, json, re


class AIEngine:
    """
    Provides AI-assisted analysis hints.
    In production, wire ANTHROPIC_API_KEY env var to call Claude API.
    """

    PROMPT_TEMPLATE = """
You are a CTF web exploitation expert. Analyze the following scan result and suggest:
1. Whether the target is likely vulnerable.
2. What specific payloads or techniques to try next.
3. Any CTF flags hidden in the response.

Target URL: {url}
Module: {module}
Scan output:
{output}

Respond in JSON: {{ "vulnerable": bool, "next_steps": [...], "hints": [...] }}
"""

    def __init__(self):
        self.api_key = os.getenv("ANTHROPIC_API_KEY", "")

    def analyze(self, url: str, module: str, output: str) -> dict:
        if not self.api_key:
            return {"note": "Set ANTHROPIC_API_KEY to enable AI analysis.",
                    "vulnerable": None, "next_steps": [], "hints": []}
        try:
            import requests
            prompt = self.PROMPT_TEMPLATE.format(
                url=url, module=module, output=output[:3000])
            resp = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": self.api_key,
                         "anthropic-version": "2023-06-01",
                         "Content-Type": "application/json"},
                json={"model": "claude-sonnet-4-20250514",
                      "max_tokens": 512,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=30
            )
            text = resp.json()["content"][0]["text"]
            clean = re.sub(r"```json|```", "", text).strip()
            return json.loads(clean)
        except Exception as e:
            return {"error": str(e), "vulnerable": None,
                    "next_steps": [], "hints": []}

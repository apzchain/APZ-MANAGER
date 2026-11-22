import json
import os
import requests
from logger import get_logger

log = get_logger("ai")


class AIAnalyzer:
    def __init__(self):
        self.enabled = os.environ.get("APZ_AI_ENABLED", "0") == "1"
        self.ollama_host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self.model = os.environ.get("APZ_AI_MODEL", "qwen2.5:7b-instruct")
        self.timeout = int(os.environ.get("APZ_AI_TIMEOUT", "120"))

    def _generate(self, prompt, system=None):
        url = f"{self.ollama_host.rstrip('/')}/api/generate"
        payload = {"model": self.model, "prompt": prompt, "stream": False}
        if system:
            payload["system"] = system
        r = requests.post(url, json=payload, timeout=self.timeout)
        r.raise_for_status()
        return r.json().get("response", "").strip()

    def summarize(self, report):
        if not self.enabled:
            return {
                "summary": "AI disabled",
                "risk_explanation": "",
                "recommendations": [],
                "family": {"family_guess": "n/a", "confidence": 0},
            }

        top = sorted(report.get("findings", []),
                     key=lambda f: f.get("weight", 0), reverse=True)[:5]
        context = {
            "risk_score": report.get("risk_score"),
            "risk_level": report.get("risk_level"),
            "top_findings": [f.get("title_fa") or f.get("category") for f in top],
            "dangerous_permissions": report.get("manifest", {}).get(
                "dangerous_permissions", [])[:10],
            "yara_hits": [m.get("rule") for m in report.get("threat", {}).get("yara", [])],
            "mitre": [m.get("id") for m in report.get("threat", {}).get("mitre", [])],
        }

        system = "You are a mobile security analyst. Be concise and technical."
        prompt = f"""Analyze this APK security report and produce:
1. A short paragraph summary.
2. The single most important risk reason.
3. 3-5 concrete recommendations.
4. Best guess of malware family (or 'insufficient evidence').
5. Confidence 0-100.

Report context:
{json.dumps(context, ensure_ascii=False)}

Respond in JSON ONLY:
{{"summary": "...", "risk_explanation": "...", "recommendations": ["..."], "family": {{"family_guess": "...", "confidence": 0}}}}
"""
        try:
            raw = self._generate(prompt, system=system)
            start = raw.find("{")
            end = raw.rfind("}")
            if start >= 0 and end > start:
                raw = raw[start:end + 1]
            return json.loads(raw)
        except Exception as e:
            log.warning(f"AI summarize failed: {e}")
            return {
                "summary": "AI analysis failed",
                "risk_explanation": str(e),
                "recommendations": [],
                "family": {"family_guess": "n/a", "confidence": 0},
            }
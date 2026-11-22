import os
import requests
from logger import get_logger

log = get_logger("reputation")


class ReputationEngine:
    def __init__(self):
        self.vt_key = os.environ.get("APZ_VT_API_KEY", "").strip()
        self.ha_key = os.environ.get("APZ_HA_API_KEY", "").strip()
        self.md_key = os.environ.get("APZ_MD_API_KEY", "").strip()
        self.timeout = int(os.environ.get("APZ_REP_TIMEOUT", "20"))

    @property
    def any_enabled(self):
        return bool(self.vt_key or self.ha_key or self.md_key)

    def check(self, sha256):
        results = {}
        sources = []
        if self.vt_key:
            sources.append(("virustotal", self._vt))
        if self.ha_key:
            sources.append(("hybrid_analysis", self._ha))
        if self.md_key:
            sources.append(("metadefender", self._md))

        for name, fn in sources:
            try:
                results[name] = fn(sha256)
            except Exception as e:
                results[name] = {"error": str(e), "verdict": "unknown", "source": name}
        return results

    def _vt(self, sha256):
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        r = requests.get(url, headers={"x-apikey": self.vt_key}, timeout=self.timeout)
        if r.status_code == 404:
            return {"verdict": "unknown", "detections": 0, "source": "virustotal"}
        r.raise_for_status()
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) or 1
        if malicious >= 5:
            verdict = "malicious"
        elif malicious > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"
        return {
            "verdict": verdict,
            "detections": malicious,
            "total_engines": total,
            "names": data.get("meaningful_name"),
            "source": "virustotal",
        }

    def _ha(self, sha256):
        url = "https://www.hybrid-analysis.com/api/v2/search/hash"
        r = requests.post(
            url,
            headers={"api-key": self.ha_key, "User-Agent": "Falcon"},
            data={"hash": sha256},
            timeout=self.timeout,
        )
        r.raise_for_status()
        data = r.json()
        if not data:
            return {"verdict": "unknown", "source": "hybrid_analysis"}
        first = data[0]
        return {
            "verdict": (first.get("verdict") or "unknown").lower(),
            "threat_score": first.get("threat_score", 0),
            "family": first.get("vx_family"),
            "source": "hybrid_analysis",
        }

    def _md(self, sha256):
        url = f"https://api.metadefender.com/v4/hash/{sha256}"
        r = requests.get(url, headers={"apikey": self.md_key}, timeout=self.timeout)
        if r.status_code == 404:
            return {"verdict": "unknown", "source": "metadefender"}
        r.raise_for_status()
        data = r.json()
        scan = data.get("scan_results", {})
        detected = scan.get("total_detected_avs", 0)
        total = scan.get("total_avs", 0) or 1
        if detected >= 3:
            verdict = "malicious"
        elif detected > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"
        return {
            "verdict": verdict,
            "detections": detected,
            "total_engines": total,
            "source": "metadefender",
        }
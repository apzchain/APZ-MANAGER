import hashlib
import os
import time
from datetime import datetime

import axml_parser
import sandbox_adapter
import threat_platform
from ai_analyzer import AIAnalyzer
from database import Database
from logger import get_logger
from reputation_engine import ReputationEngine
from risk_fusion_engine import fuse

log = get_logger("orchestrator")

_FA_TITLES = {
    "reputation": "اعتبارسنجی چندمنبعی",
    "yara": "قوانین YARA",
    "ioc": "شاخص‌های نفوذ (IOC)",
    "manifest": "مجوزهای حساس",
    "mitre": "تکنیک‌های MITRE ATT&CK",
    "sandbox": "شبیه‌سازی Sandbox",
    "certificate": "گواهی امضا",
}


def _hash_file(path, algo, chunk=1 << 20):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


class Orchestrator:
    def __init__(self, db_path=None, rules_dir="rules",
                 enable_ai=None, enable_reputation=True, outdir=None):
        self.db = None if db_path is False else Database(db_path)
        self.rules_dir = rules_dir
        self.rep = ReputationEngine() if enable_reputation else None
        self.ai = AIAnalyzer()
        if enable_ai is False:
            self.ai.enabled = False
        self.outdir = outdir or os.environ.get(
            "APZ_DEFAULT_OUTDIR", os.path.expanduser("~/apz-reports")
        )

    def analyze(self, apk_path):
        t0 = time.time()
        log.info(f"analyzing {apk_path}")

        if not os.path.isfile(apk_path):
            raise FileNotFoundError(apk_path)

        size = os.path.getsize(apk_path)
        sha = _hash_file(apk_path, "sha256")
        md5 = _hash_file(apk_path, "md5")

        strings = threat_platform.extract_strings_from_apk(apk_path)
        static_info = {
            "size_bytes": size,
            "strings_extracted": len(strings),
        }

        manifest = axml_parser.parse_manifest(apk_path)
        threat = threat_platform.run(apk_path, strings=strings, rules_dir=self.rules_dir)
        threat["mitre"] = threat_platform.map_mitre(manifest, threat["yara"])

        reputation = {}
        if self.rep and self.rep.any_enabled:
            try:
                reputation = self.rep.check(sha)
            except Exception as e:
                log.warning(f"reputation error: {e}")
                reputation = {"error": str(e)}

        sandbox = sandbox_adapter.simulate(apk_path, manifest, threat)

        report = {
            "file": apk_path,
            "sha256": sha,
            "md5": md5,
            "size": size,
            "analyzed_at": datetime.utcnow().isoformat() + "Z",
            "static": static_info,
            "manifest": manifest,
            "threat": threat,
            "reputation": reputation,
            "sandbox": sandbox,
        }

        fusion = fuse(report, known_ioc_fn=self.db.is_known_ioc if self.db else None)
        report.update({
            "risk_score": fusion["risk_score"],
            "risk_level": fusion["risk_level"],
            "confidence": fusion["confidence"],
            "risk_components": fusion["components"],
            "explanations": fusion["explanations"],
        })

        findings = []
        for exp in fusion["explanations"]:
            findings.append({
                "category": exp["category"],
                "title_fa": _FA_TITLES.get(exp["category"], exp["category"]),
                "weight": exp["score"],
                "detail_fa": exp["reason"],
                "evidence": [],
            })
        for m in threat["yara"]:
            findings.append({
                "category": "yara",
                "title_fa": f"YARA: {m['rule']}",
                "weight": {"critical": 80, "high": 55,
                           "medium": 30, "low": 10}.get(m.get("severity"), 30),
                "detail_fa": m.get("description", ""),
                "evidence": [m["rule"]],
            })
        report["findings"] = findings

        report["ai"] = self.ai.summarize(report) if self.ai.enabled else None

        report["limitations"] = [
            "تحلیل static/heuristic است و ممکن است برخی رفتارهای داینامیک شناسایی نشوند.",
            "اعتبارسنجی چندمنبعی فقط در صورت وجود کلیدهای API انجام می‌شود.",
        ]

        if self.db:
            try:
                self.db.save_analysis(report)
                for kind, values in threat["iocs"].items():
                    for v in values:
                        self.db.save_ioc(kind, v)
            except Exception as e:
                log.warning(f"db save failed: {e}")

        report["elapsed_seconds"] = round(time.time() - t0, 2)
        log.info(f"done in {report['elapsed_seconds']}s "
                 f"(risk={report['risk_level']}, score={report['risk_score']})")
        return report
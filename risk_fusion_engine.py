from dataclasses import dataclass, asdict
from typing import Any

@dataclass
class Evidence:
    category: str
    score: float
    weight: float
    confidence: float
    severity: str
    title: str
    explanation: str
    source: str
    evidence_id: str

@dataclass
class RiskFusionResult:
    score: int
    level: str
    confidence: int
    verdict: str
    evidence: list
    category_scores: dict
    limitations: list
    recommendations: list

class RiskFusionEngine2:
    """
    Explainable Android risk fusion.
    Scores are intentionally capped and confidence-aware; a single weak
    indicator cannot force a malicious verdict.
    """
    WEIGHTS = {
        "reputation": 0.25,
        "yara": 0.20,
        "ioc": 0.15,
        "manifest": 0.15,
        "mitre": 0.10,
        "certificate": 0.05,
        "dynamic": 0.10,
    }

    def __init__(self, weights=None):
        self.weights = dict(weights or self.WEIGHTS)

    @staticmethod
    def _clamp(x, lo=0, hi=100):
        return max(lo, min(hi, float(x)))

    def _evidence(self, category, score, confidence, severity, title,
                  explanation, source, eid):
        return Evidence(
            category=category,
            score=self._clamp(score),
            weight=self.weights.get(category, 0),
            confidence=self._clamp(confidence) / 100,
            severity=severity,
            title=title,
            explanation=explanation,
            source=source,
            evidence_id=eid,
        )

    def reputation(self, rep):
        providers = rep.get("providers", [])
        malicious = sum(p.get("verdict") == "malicious" for p in providers)
        suspicious = sum(p.get("verdict") == "suspicious" for p in providers)
        available = sum(bool(p.get("available")) for p in providers)
        if malicious >= 2:
            score, sev = 100, "critical"
        elif malicious == 1:
            score, sev = 78, "high"
        elif suspicious >= 2:
            score, sev = 58, "medium"
        elif suspicious == 1:
            score, sev = 38, "low"
        elif available:
            score, sev = 5, "info"
        else:
            score, sev = 0, "unknown"
        conf = min(98, 35 + available * 15 + malicious * 18 + suspicious * 8)
        return self._evidence(
            "reputation", score, conf, sev,
            f"Multi-source reputation: {malicious} malicious / {suspicious} suspicious",
            "نتیجه Reputation از چند منبع مستقل ترکیب شده است.",
            "MultiReputationEngine", "REP-CONSENSUS"
        )

    def yara(self, hits):
        if not hits:
            return self._evidence("yara", 0, 75, "info",
                                  "No YARA findings",
                                  "Ruleهای فعال‌شده مورد مشکوکی پیدا نکردند.",
                                  "YaraScanner", "YARA-NONE")
        points = 0
        high = medium = 0
        for h in hits:
            sev = h.get("severity", "low")
            points += {"critical": 35, "high": 25, "medium": 14, "low": 6}.get(sev, 4)
            high += sev in ("high", "critical")
            medium += sev == "medium"
        score = min(100, points)
        conf = min(95, 55 + len(hits) * 7)
        return self._evidence("yara", score, conf,
                              "high" if high else ("medium" if medium else "low"),
                              f"{len(hits)} YARA finding(s)",
                              "YARA findings indicate suspicious code or behavior patterns.",
                              "YaraScanner", "YARA-FINDINGS")

    def ioc(self, iocs):
        real = [x for x in iocs if x.get("kind") != "error"]
        high = sum(x.get("severity") == "high" for x in real)
        med = sum(x.get("severity") == "medium" for x in real)
        score = min(100, high * 25 + med * 12 + max(0, len(real)-high-med) * 3)
        return self._evidence("ioc", score, min(90, 50 + len(real) * 4),
                              "high" if high else ("medium" if med else ("low" if real else "info")),
                              f"{len(real)} Android IOC(s)",
                              "IOCها از محتوای APK استخراج شده‌اند و نیازمند correlation هستند.",
                              "AndroidIOCExtractor", "IOC-STATIC")

    def manifest(self, manifest=None):
        m = manifest or {}
        exported = int(m.get("exported_dangerous", 0) or 0)
        dangerous = int(m.get("dangerous_permissions", 0) or 0)
        accessibility = bool(m.get("accessibility_service"))
        score = min(100, exported * 18 + dangerous * 8 + (25 if accessibility else 0))
        return self._evidence("manifest", score, 70,
                              "high" if accessibility else ("medium" if score >= 35 else "info"),
                              "Manifest / permission posture",
                              "امتیاز بر اساس مؤلفه‌های خطر Manifest و Permission محاسبه شده است.",
                              "AndroidManifestAnalyzer", "MANIFEST-POSTURE")

    def mitre(self, mappings):
        n = len(mappings or [])
        high = sum(x.get("severity") == "high" for x in (mappings or []))
        score = min(100, n * 12 + high * 10)
        return self._evidence("mitre", score, min(92, 55 + n * 6),
                              "high" if high else ("medium" if n else "info"),
                              f"{n} ATT&CK technique mapping(s)",
                              "این نگاشت‌ها شواهد رفتاری/استاتیک هستند، نه اثبات اجرای تکنیک.",
                              "MitreAndroidMapper", "MITRE-MAP")

    def certificate(self, cert=None):
        c = cert or {}
        anomalies = int(c.get("anomalies", 0) or 0)
        debug = bool(c.get("debug_signed"))
        score = min(100, anomalies * 20 + (30 if debug else 0))
        return self._evidence("certificate", score, 65,
                              "high" if debug else ("medium" if anomalies else "info"),
                              "Signing certificate posture",
                              "ناهنجاری‌های امضای APK یا debug signing بررسی می‌شوند.",
                              "CertificateAnalyzer", "CERT-POSTURE")

    def dynamic(self, dynamic=None):
        d = dynamic or {}
        if d.get("status") in (None, "not_configured"):
            return self._evidence("dynamic", 0, 20, "unknown",
                                  "Dynamic sandbox unavailable",
                                  "Sandbox پویا هنوز پیکربندی نشده است؛ نبود شواهد به معنی پاک بودن نیست.",
                                  "DynamicSandboxAdapter", "DYN-NOT-CONFIGURED")
        malicious = int(d.get("malicious_events", 0) or 0)
        suspicious = int(d.get("suspicious_events", 0) or 0)
        score = min(100, malicious * 35 + suspicious * 15)
        return self._evidence("dynamic", score, 85 if d.get("status") == "complete" else 55,
                              "high" if malicious else ("medium" if suspicious else "info"),
                              "Dynamic behavior",
                              "رفتار runtime از sandbox ایزوله دریافت شده است.",
                              "DynamicSandbox", "DYN-BEHAVIOR")

    def fuse(self, analysis):
        evidences = [
            self.reputation(analysis.get("reputation", {})),
            self.yara(analysis.get("yara_hits", [])),
            self.ioc(analysis.get("android_iocs", [])),
            self.manifest(analysis.get("manifest")),
            self.mitre(analysis.get("mitre_attack", [])),
            self.certificate(analysis.get("certificate")),
            self.dynamic(analysis.get("dynamic_sandbox")),
        ]

        raw = sum(e.score * e.weight for e in evidences)
        # Confidence-aware dampening prevents unknown categories from pretending
        # to be clean. Fully unavailable evidence reduces confidence, not risk.
        known_weight = sum(e.weight for e in evidences if e.confidence > 0.25)
        score = raw / known_weight if known_weight else 0
        score = int(round(self._clamp(score)))

        avg_conf = sum(e.confidence for e in evidences) / len(evidences)
        confidence = int(round(self._clamp(avg_conf * 100)))

        malicious_rep = any(
            e.category == "reputation" and e.score >= 78 for e in evidences
        )
        dynamic_high = any(
            e.category == "dynamic" and e.score >= 70 for e in evidences
        )
        if malicious_rep or dynamic_high:
            verdict = "malicious" if score >= 60 else "high_risk"
        elif score >= 70:
            verdict = "high_risk"
        elif score >= 45:
            verdict = "suspicious"
        elif score >= 20:
            verdict = "low_risk"
        else:
            verdict = "no_strong_indicator"

        level = (
            "critical" if score >= 85 else
            "high" if score >= 65 else
            "medium" if score >= 40 else
            "low"
        )

        limitations = []
        if not analysis.get("dynamic_sandbox") or analysis.get("dynamic_sandbox", {}).get("status") == "not_configured":
            limitations.append("Dynamic sandbox configured نیست.")
        if not analysis.get("manifest"):
            limitations.append("تحلیل کامل Manifest/Permission هنوز در داده ورودی وجود ندارد.")
        if not analysis.get("certificate"):
            limitations.append("تحلیل Certificate هنوز در داده ورودی وجود ندارد.")
        if not analysis.get("reputation", {}).get("providers"):
            limitations.append("داده Reputation چندمنبعه موجود نیست.")

        recommendations = []
        if score >= 65:
            recommendations.append("APK در sandbox ایزوله اجرا و رفتار شبکه/فرآیند بررسی شود.")
        if any(e.category == "yara" and e.score >= 50 for e in evidences):
            recommendations.append("Ruleهای YARA مرتبط با Dynamic Loading و Command Execution عمیق‌تر بررسی شوند.")
        if any(e.category == "ioc" and e.score >= 40 for e in evidences):
            recommendations.append("IOCها با Threat Intelligence داخلی و خارجی correlation شوند.")
        if not recommendations:
            recommendations.append("برای افزایش اطمینان، تحلیل Manifest، Certificate و Dynamic Sandbox تکمیل شود.")

        return RiskFusionResult(
            score=score,
            level=level,
            confidence=confidence,
            verdict=verdict,
            evidence=[asdict(e) for e in evidences],
            category_scores={e.category: round(e.score, 1) for e in evidences},
            limitations=limitations,
            recommendations=recommendations,
        )

def risk_fusion_json(analysis):
    return asdict(RiskFusionEngine2().fuse(analysis))

"""Risk Fusion Engine 2.0 – explainable risk scoring."""

DEFAULT_WEIGHTS = {
    "reputation": 0.25,
    "yara": 0.20,
    "ioc": 0.15,
    "manifest": 0.15,
    "mitre": 0.10,
    "certificate": 0.08,
    "sandbox": 0.07,
}


def _score_reputation(rep):
    if not rep:
        return 0, "no reputation data"
    total = 0
    n = 0
    for src, r in rep.items():
        if not isinstance(r, dict):
            continue
        n += 1
        v = r.get("verdict", "unknown")
        if v == "malicious":
            total += 80
        elif v == "suspicious":
            total += 40
    return min(100, total / max(n, 1)), f"checked {n} source(s)"


def _score_yara(yara):
    if not yara:
        return 0, "no YARA hits"
    severity_score = {"critical": 80, "high": 55, "medium": 30, "low": 10}
    best = max((severity_score.get(m.get("severity", "medium"), 30) for m in yara), default=0)
    return best, f"{len(yara)} rule(s) matched"


def _score_ioc(iocs, known_ioc_fn=None):
    total = 0
    counts = {"ip": 0, "domain": 0, "url": 0}
    for k in ("ip", "domain", "url"):
        for v in iocs.get(k, []):
            counts[k] += 1
            if known_ioc_fn and known_ioc_fn(v):
                total += 25
    if total == 0 and any(counts.values()):
        total += min(30, sum(counts.values()) * 2)
    return min(100, total), f"IOC counts: {counts}"


def _score_manifest(manifest):
    hint = manifest.get("score_hint", 0)
    return min(100, hint * 2), \
        f"{len(manifest.get('dangerous_permissions', []))} dangerous permission(s)"


def _score_mitre(mitre):
    n = len(mitre)
    return min(100, n * 15), f"{n} ATT&CK technique(s) mapped"


def _score_sandbox(sandbox):
    v = (sandbox or {}).get("verdict", "unknown")
    return {"malicious": 80, "suspicious": 45, "clean": 0}.get(v, 0), \
        f"sandbox verdict: {v}"


def fuse(report, weights=None, known_ioc_fn=None):
    weights = weights or DEFAULT_WEIGHTS
    components = {}
    explanations = []

    rep = report.get("reputation", {})
    yara = report.get("threat", {}).get("yara", [])
    iocs = report.get("threat", {}).get("iocs", {})
    manifest = report.get("manifest", {})
    mitre = report.get("threat", {}).get("mitre", [])
    sandbox = report.get("sandbox", {})

    def add(key, val):
        s, why = val
        components[key] = {"score": s, "weight": weights.get(key, 0), "reason": why}
        if s > 0:
            explanations.append({"category": key, "score": s, "reason": why})

    add("reputation", _score_reputation(rep))
    add("yara", _score_yara(yara))
    add("ioc", _score_ioc(iocs, known_ioc_fn))
    add("manifest", _score_manifest(manifest))
    add("mitre", _score_mitre(mitre))
    add("sandbox", _score_sandbox(sandbox))
    add("certificate", (0, "not analyzed"))

    total_weight = sum(c["weight"] for c in components.values()) or 1
    weighted = sum(c["score"] * c["weight"] for c in components.values()) / total_weight
    risk_score = round(weighted)

    if risk_score >= 75:
        level = "CRITICAL"
    elif risk_score >= 55:
        level = "HIGH"
    elif risk_score >= 35:
        level = "MEDIUM"
    elif risk_score >= 15:
        level = "LOW"
    else:
        level = "MINIMAL"

    sources = sum([
        bool(rep), bool(yara), any(iocs.values()),
        bool(manifest.get("permissions")), bool(mitre),
        bool(sandbox.get("verdict")),
    ])
    confidence = min(95, 40 + sources * 9)

    return {
        "risk_score": risk_score,
        "risk_level": level,
        "confidence": confidence,
        "components": components,
        "explanations": explanations,
    }
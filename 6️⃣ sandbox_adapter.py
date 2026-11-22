"""Lightweight static sandbox simulation – NO code execution."""


def simulate(apk_path, manifest, threat):
    findings = []
    risk = 0

    dex_files = 0
    native_libs = []
    try:
        import zipfile
        with zipfile.ZipFile(apk_path, "r") as z:
            names = z.namelist()
            dex_files = sum(1 for n in names if n.endswith(".dex"))
            native_libs = [n for n in names if n.endswith(".so")]
    except Exception:
        pass

    if dex_files > 1:
        findings.append(f"multiple DEX files ({dex_files}) – possible dropper/loader")
        risk += 10
    if native_libs:
        findings.append(f"native libraries present ({len(native_libs)})")
        risk += 5

    dperms = set(manifest.get("dangerous_permissions", []))
    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in dperms:
        findings.append("accessibility service requested – high abuse potential")
        risk += 20
    if "android.permission.SYSTEM_ALERT_WINDOW" in dperms:
        findings.append("overlay capability detected")
        risk += 15
    if "android.permission.REQUEST_INSTALL_PACKAGES" in dperms:
        findings.append("can install packages – dropper pattern")
        risk += 15
    if {"android.permission.READ_SMS", "android.permission.SEND_SMS"} & dperms:
        findings.append("SMS access – premium-rate / OTP theft possible")
        risk += 15

    if any(y.get("severity") == "critical" for y in threat.get("yara", [])):
        risk += 25
        findings.append("critical YARA hits")

    if risk >= 60:
        verdict = "malicious"
    elif risk >= 25:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "verdict": verdict,
        "simulated_score": risk,
        "findings": findings,
        "note": "static simulation – not a dynamic sandbox",
    }
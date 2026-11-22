import re
import zipfile
from pathlib import Path

from logger import get_logger

log = get_logger("threat")

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|cc|pw|onion|dev|app|me)\b",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

MITRE_MAP = {
    "android.permission.READ_SMS": ("T1636", "Protected User Data: SMS"),
    "android.permission.RECEIVE_SMS": ("T1636", "Protected User Data: SMS"),
    "android.permission.SEND_SMS": ("T1582", "SMS Control"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("T1417", "Input Capture"),
    "android.permission.SYSTEM_ALERT_WINDOW": ("T1417", "Input Capture: Overlay"),
    "android.permission.RECORD_AUDIO": ("T1429", "Audio Capture"),
    "android.permission.CAMERA": ("T1512", "Video Capture"),
    "android.permission.ACCESS_FINE_LOCATION": ("T1430", "Location Tracking"),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("T1544", "Ingress Tool Transfer"),
    "android.permission.READ_CONTACTS": ("T1636", "Protected User Data: Contacts"),
    "android.permission.READ_CALL_LOG": ("T1636", "Protected User Data: Call Log"),
    "android.permission.READ_PHONE_STATE": ("T1426", "System Information Discovery"),
}

YARA_MITRE = {
    "accessibility": ("T1417", "Input Capture"),
    "sms": ("T1636", "Protected User Data"),
    "overlay": ("T1417", "Input Capture: Overlay"),
    "dropper": ("T1544", "Ingress Tool Transfer"),
    "banking": ("T1417", "Input Capture"),
    "ransomware": ("T1486", "Data Encrypted for Impact"),
    "botnet": ("T1071", "Application Layer Protocol"),
    "miner": ("T1496", "Resource Hijacking"),
}


def extract_strings_from_apk(apk_path, max_strings=5000, min_length=5):
    strings = set()
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for name in z.namelist():
                if not name.endswith((".dex", ".so", ".xml", ".json", ".js")):
                    continue
                try:
                    data = z.read(name)
                except Exception:
                    continue
                for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_length, data):
                    s = m.group().decode("ascii", "ignore").strip()
                    if s:
                        strings.add(s)
                    if len(strings) >= max_strings:
                        return sorted(strings)
    except Exception as e:
        log.warning(f"extract_strings_from_apk failed: {e}")
    return sorted(strings)


def scan_yara(apk_path, rules_dir="rules"):
    try:
        import yara
    except ImportError:
        log.warning("yara-python not installed, skipping YARA")
        return []

    rules_path = Path(rules_dir)
    if not rules_path.exists():
        return []

    yar_files = list(rules_path.glob("*.yar")) + list(rules_path.glob("*.yara"))
    if not yar_files:
        return []

    filepaths = {f.stem: str(f) for f in yar_files}
    try:
        rules = yara.compile(filepaths=filepaths)
    except Exception as e:
        log.error(f"YARA compile error: {e}")
        return []

    matches = []
    try:
        for m in rules.match(apk_path):
            meta = m.meta or {}
            matches.append({
                "rule": m.rule,
                "severity": meta.get("severity", "medium"),
                "description": meta.get("description", ""),
                "tags": list(m.tags),
                "namespace": m.namespace,
            })
    except Exception as e:
        log.error(f"YARA scan failed: {e}")
    return matches


def extract_iocs(strings):
    iocs = {"ip": set(), "domain": set(), "url": set()}
    for s in strings:
        for m in URL_RE.finditer(s):
            iocs["url"].add(m.group()[:300])
        for m in IP_RE.finditer(s):
            ip = m.group()
            if ip.startswith(("127.", "0.", "10.", "192.168.", "255.")):
                continue
            if ip.startswith("172."):
                try:
                    if 16 <= int(ip.split(".")[1]) <= 31:
                        continue
                except Exception:
                    pass
            iocs["ip"].add(ip)
        for m in DOMAIN_RE.finditer(s):
            d = m.group().lower()
            if d.endswith((".android.com", ".google.com",
                           ".googleapis.com", ".gstatic.com", ".googlesource.com")):
                continue
            iocs["domain"].add(d)
    return {k: sorted(v)[:200] for k, v in iocs.items()}


def map_mitre(manifest, yara_matches):
    techniques = {}
    for perm in manifest.get("dangerous_permissions", []):
        if perm in MITRE_MAP:
            tid, name = MITRE_MAP[perm]
            techniques[tid] = name
    for m in yara_matches:
        rule = (m.get("rule") or "").lower()
        for key, (tid, name) in YARA_MITRE.items():
            if key in rule:
                techniques[tid] = name
    return [{"id": k, "name": v} for k, v in techniques.items()]


def run(apk_path, strings=None, rules_dir="rules"):
    if strings is None:
        strings = extract_strings_from_apk(apk_path)
    return {
        "yara": scan_yara(apk_path, rules_dir=rules_dir),
        "iocs": extract_iocs(strings),
        "strings_sample": strings[:500],
        "strings_count": len(strings),
    }
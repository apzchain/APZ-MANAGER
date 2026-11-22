from logger import get_logger

log = get_logger("axml")

DANGEROUS_PERMS = {
    "android.permission.READ_SMS": 30,
    "android.permission.SEND_SMS": 25,
    "android.permission.RECEIVE_SMS": 25,
    "android.permission.READ_CALL_LOG": 25,
    "android.permission.READ_CONTACTS": 20,
    "android.permission.CAMERA": 15,
    "android.permission.RECORD_AUDIO": 20,
    "android.permission.ACCESS_FINE_LOCATION": 15,
    "android.permission.ACCESS_COARSE_LOCATION": 10,
    "android.permission.SYSTEM_ALERT_WINDOW": 25,
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 35,
    "android.permission.REQUEST_INSTALL_PACKAGES": 30,
    "android.permission.READ_PHONE_STATE": 10,
    "android.permission.READ_EXTERNAL_STORAGE": 8,
    "android.permission.WRITE_EXTERNAL_STORAGE": 10,
    "android.permission.RECEIVE_BOOT_COMPLETED": 8,
    "android.permission.POST_NOTIFICATIONS": 5,
    "android.permission.ACCESS_BACKGROUND_LOCATION": 20,
    "android.permission.QUERY_ALL_PACKAGES": 15,
}


def parse_manifest(apk_path):
    """Decode AndroidManifest.xml with androguard when available."""
    result = {
        "package": None,
        "version_name": None,
        "version_code": None,
        "permissions": [],
        "dangerous_permissions": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "exported_components": [],
        "min_sdk": None,
        "target_sdk": None,
        "score_hint": 0,
        "parse_error": None,
    }

    try:
        from androguard.core.apk import APK
    except ImportError:
        result["parse_error"] = "androguard not installed"
        log.warning("androguard not available; manifest skipped")
        return result

    try:
        a = APK(apk_path)
        result["package"] = a.get_package()
        result["version_name"] = a.get_androidversion_name()
        result["version_code"] = a.get_androidversion_code()
        result["min_sdk"] = a.get_min_sdk_version()
        result["target_sdk"] = a.get_target_sdk_version()

        perms = set(a.get_permissions() or [])
        result["permissions"] = sorted(perms)
        dangerous = [p for p in perms if p in DANGEROUS_PERMS]
        result["dangerous_permissions"] = sorted(dangerous)
        result["score_hint"] = sum(DANGEROUS_PERMS[p] for p in dangerous)

        for kind, getter in (
            ("activities", a.get_activities),
            ("services", a.get_services),
            ("receivers", a.get_receivers),
            ("providers", a.get_providers),
        ):
            try:
                items = list(getter() or [])
                result[kind] = items
            except Exception as e:
                log.debug(f"component {kind} failed: {e}")

        # best-effort: detect exported components
        try:
            exported = []
            for name in (result["activities"] + result["services"]
                         + result["receivers"] + result["providers"]):
                if name and name != "None":
                    exported.append(name)
            result["exported_components"] = exported[:50]
        except Exception:
            pass

    except Exception as e:
        result["parse_error"] = str(e)
        log.warning(f"parse_manifest failed: {e}")

    return result
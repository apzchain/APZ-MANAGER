rule Android_Accessibility_Abuse
{
    meta:
        description = "App requests accessibility service – known malware abuse vector"
        severity = "critical"
    strings:
        $s1 = "BIND_ACCESSIBILITY_SERVICE" ascii
        $s2 = "AccessibilityService" ascii
        $s3 = "onAccessibilityEvent" ascii
    condition:
        2 of them
}

rule Android_SMS_Interception
{
    meta:
        description = "SMS interception patterns"
        severity = "high"
    strings:
        $s1 = "SmsManager" ascii
        $s2 = "READ_SMS" ascii
        $s3 = "RECEIVE_SMS" ascii
        $s4 = "abortBroadcast" ascii
    condition:
        2 of them
}

rule Android_Overlay_Attack
{
    meta:
        description = "Overlay / tapjacking patterns"
        severity = "high"
    strings:
        $s1 = "SYSTEM_ALERT_WINDOW" ascii
        $s2 = "TYPE_APPLICATION_OVERLAY" ascii
        $s3 = "setView" ascii
    condition:
        2 of them
}

rule Android_Dropper_Pattern
{
    meta:
        description = "Dynamic code loading / dropper"
        severity = "high"
    strings:
        $s1 = "DexClassLoader" ascii
        $s2 = "REQUEST_INSTALL_PACKAGES" ascii
        $s3 = "dalvik.system" ascii
        $s4 = "Ldalvik/system/DexClassLoader;" ascii
    condition:
        any of them
}

rule Android_Banking_Trojan
{
    meta:
        description = "Banking trojan indicators"
        severity = "critical"
    strings:
        $s1 = "overlay" ascii nocase
        $s2 = "keylog" ascii nocase
        $s3 = "phish" ascii nocase
        $s4 = "com.android.bank" ascii nocase
    condition:
        2 of them
}

rule Android_Ransomware_Pattern
{
    meta:
        description = "Ransomware-like patterns"
        severity = "critical"
    strings:
        $s1 = "EncryptFile" ascii
        $s2 = "ransom" ascii nocase
        $s3 = "/sdcard/" ascii
        $s4 = "AES/CBC/PKCS5Padding" ascii
    condition:
        2 of them
}

rule Android_Crypto_Miner
{
    meta:
        description = "Cryptocurrency miner indicators"
        severity = "high"
    strings:
        $s1 = "stratum+tcp" ascii
        $s2 = "minergate" ascii nocase
        $s3 = "xmrig" ascii nocase
        $s4 = "monero" ascii nocase
    condition:
        any of them
}
import hashlib, json, re, zipfile
from dataclasses import dataclass, asdict
from pathlib import Path
from risk_fusion_engine import RiskFusionEngine2

@dataclass
class IOC:
    kind: str
    value: str
    source: str
    severity: str
    evidence: str = ""

@dataclass
class YaraHit:
    rule: str
    severity: str
    namespace: str
    evidence: str

class AndroidIOCExtractor:
    URL = re.compile(r'https?://[^\s"\'<>]+', re.I)
    IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    DOMAIN = re.compile(r'\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|xyz|top|info|biz|cc|me)\b', re.I)
    PACKAGE = re.compile(r'\b(?:[a-z_][\w]*\.){2,}[A-Za-z_][\w$]*\b')

    def extract(self, apk_path):
        found=[]
        try:
            with zipfile.ZipFile(apk_path) as z:
                names=z.namelist()
                text_parts=[]
                for n in names:
                    if n.endswith((".xml",".json",".txt",".smali",".dex",".arsc")) or "classes" in n:
                        try:
                            b=z.read(n)
                            text_parts.append((n,b.decode("utf-8","ignore")))
                        except Exception:
                            pass
                for n,t in text_parts:
                    for rx,kind in [(self.URL,"url"),(self.IP,"ip"),(self.DOMAIN,"domain")]:
                        for m in rx.findall(t):
                            found.append(IOC(kind,m,"APK static","medium",n))
                    for m in self.PACKAGE.findall(t):
                        if any(x in m.lower() for x in ("http","socket","crypto","root","su","dex","payload","shell")):
                            found.append(IOC("package_or_class",m,"APK static","low",n))
        except Exception as e:
            found.append(IOC("error",str(e),"IOC extractor","info"))
        uniq={}
        for x in found:
            uniq[(x.kind,x.value)]=x
        return list(uniq.values())

class YaraLiteScanner:
    """
    Safe, dependency-free YARA-like rule layer for Windows builds.
    Optional real YARA can be added later without changing the rule format.
    """
    DEFAULT_RULES=[
        ("Android_DynamicCode","high",[r"classes\d*\.dex",r"dalvik.system.DexClassLoader",r"loadDex"]),
        ("Android_CommandExecution","high",[r"/system/bin/sh",r"\bsu\b",r"Runtime\.getRuntime"]),
        ("Android_NetworkPersistence","medium",[r"BOOT_COMPLETED",r"RECEIVE_BOOT_COMPLETED"]),
        ("Android_Crypto_Sensitive","medium",[r"Cipher\.getInstance",r"SecretKeySpec"]),
        ("Android_WebView_JS","medium",[r"addJavascriptInterface",r"setJavaScriptEnabled"]),
    ]
    def scan(self, apk_path):
        hits=[]
        try:
            with zipfile.ZipFile(apk_path) as z:
                names=z.namelist()
                blobs=[]
                for n in names:
                    if n.endswith((".xml",".json",".txt",".smali",".dex",".arsc")) or "classes" in n:
                        try: blobs.append((n,z.read(n).decode("utf-8","ignore")))
                        except Exception: pass
                whole="\n".join(t for _,t in blobs)
                for name,severity,patterns in self.DEFAULT_RULES:
                    matched=[p for p in patterns if re.search(p,whole,re.I)]
                    if matched:
                        hits.append(YaraHit(name,severity,"android-default",",".join(matched)))
        except Exception as e:
            hits.append(YaraHit("Scanner_Error","info","system",str(e)))
        return hits

class MitreAndroidMapper:
    MAP={
        "Android_DynamicCode":("T1620","Reflective Code Loading"),
        "Android_CommandExecution":("T1059.004","Unix Shell"),
        "Android_NetworkPersistence":("T1547","Boot or Logon Autostart Execution"),
        "Android_Crypto_Sensitive":("T1027","Obfuscated/Compressed Files and Information"),
        "Android_WebView_JS":("T1059","Command and Scripting Interpreter"),
    }
    def map(self, yara_hits, iocs):
        out=[]
        for h in yara_hits:
            if h.rule in self.MAP:
                tid,name=self.MAP[h.rule]
                out.append({"technique":tid,"name":name,"rule":h.rule,"severity":h.severity})
        if any(x.kind=="ip" for x in iocs):
            out.append({"technique":"T1071","name":"Application Layer Protocol","rule":"network IOC","severity":"medium"})
        return out

class DynamicSandboxAdapter:
    """
    Adapter interface only. It intentionally does not execute untrusted APKs
    locally. A production deployment can connect this adapter to an isolated
    Android emulator/sandbox service.
    """
    def submit(self, apk_path):
        raise RuntimeError("No isolated sandbox configured. Configure a remote/isolated sandbox adapter.")

class ThreatPlatform:
    def __init__(self, reputation_engine):
        self.reputation=reputation_engine
        self.ioc=AndroidIOCExtractor()
        self.yara=YaraLiteScanner()
        self.mitre=MitreAndroidMapper()
        self.fusion=RiskFusionEngine2()

    def analyze(self, apk_path, sha256):
        iocs=self.ioc.extract(apk_path)
        hits=self.yara.scan(apk_path)
        mitre=self.mitre.map(hits,iocs)
        rep=self.reputation.lookup(sha256)
        result = {
            "sha256":sha256,
            "reputation":rep,
            "yara_hits":[asdict(x) for x in hits],
            "mitre_attack":[x for x in mitre],
            "android_iocs":[asdict(x) for x in iocs],
            "dynamic_sandbox":{"status":"not_configured","safe_by_default":True}
        }
        result["risk_fusion"] = self.fusion.fuse(result).__dict__
        return result

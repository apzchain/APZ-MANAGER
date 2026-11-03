import os, json, csv, urllib.request, urllib.error
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass
class ProviderResult:
    provider: str
    available: bool
    status: str
    verdict: str = "unknown"
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    score: int | None = None
    report_url: str | None = None
    details: dict | None = None
    error: str | None = None

class ReputationProvider:
    name = "base"
    def lookup_sha256(self, sha256: str) -> ProviderResult:
        raise NotImplementedError

class VirusTotalProvider(ReputationProvider):
    name = "VirusTotal"
    def __init__(self, key=None):
        self.key = key or os.getenv("APZ_VT_API_KEY","")
    def lookup_sha256(self, sha256):
        if not self.key:
            return ProviderResult(self.name, False, "API_KEY_MISSING", error="APZ_VT_API_KEY")
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": self.key, "Accept":"application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                a=json.loads(r.read().decode()).get("data",{}).get("attributes",{})
            s=a.get("last_analysis_stats",{}) or {}
            mal=int(s.get("malicious",0) or 0); sus=int(s.get("suspicious",0) or 0)
            verdict="malicious" if mal else ("suspicious" if sus else "no_threat")
            return ProviderResult(self.name, True, "OK", verdict, mal, sus,
                int(s.get("harmless",0) or 0), int(s.get("undetected",0) or 0),
                a.get("reputation") if isinstance(a.get("reputation"),int) else None,
                f"https://www.virustotal.com/gui/file/{sha256}", a.get("sandbox_verdicts"))
        except urllib.error.HTTPError as e:
            st={404:"HASH_NOT_FOUND",401:"INVALID_API_KEY",429:"RATE_LIMITED"}.get(e.code,f"HTTP_{e.code}")
            return ProviderResult(self.name,False,st,error=str(e))
        except Exception as e:
            return ProviderResult(self.name,False,"NETWORK_ERROR",error=str(e))

class HybridAnalysisProvider(ReputationProvider):
    name = "Hybrid Analysis"
    def __init__(self, key=None, host=None):
        self.key = key or os.getenv("APZ_HA_API_KEY","")
        self.host = host or os.getenv("APZ_HA_API_HOST","https://hybrid-analysis.com")
    def lookup_sha256(self, sha256):
        if not self.key:
            return ProviderResult(self.name,False,"API_KEY_MISSING",error="APZ_HA_API_KEY")
        url=self.host.rstrip("/")+"/api/v2/search/hash"
        req=urllib.request.Request(url, method="GET",
            headers={"api-key":self.key,"user-agent":"APZ-Manager/1.0","accept":"application/json"})
        # API v2 documents GET /search/hash; hash is supplied as query.
        from urllib.parse import urlencode
        req.full_url=url+"?"+urlencode({"hash":sha256})
        try:
            with urllib.request.urlopen(req,timeout=30) as r:
                data=json.loads(r.read().decode())
            rows=data if isinstance(data,list) else data.get("data",data.get("results",[]))
            if not rows:
                return ProviderResult(self.name,True,"NOT_FOUND","unknown")
            row=rows[0] if isinstance(rows,list) else rows
            verdict=str(row.get("verdict",row.get("status","unknown"))).lower()
            if "malicious" in verdict or "threat" in verdict: v="malicious"
            elif "suspicious" in verdict: v="suspicious"
            elif "no_threat" in verdict or "benign" in verdict or "clean" in verdict: v="no_threat"
            else: v="unknown"
            return ProviderResult(self.name,True,"OK",v,details=row)
        except urllib.error.HTTPError as e:
            return ProviderResult(self.name,False,f"HTTP_{e.code}",error=str(e))
        except Exception as e:
            return ProviderResult(self.name,False,"NETWORK_ERROR",error=str(e))

class MetaDefenderProvider(ReputationProvider):
    name = "MetaDefender Cloud"
    def __init__(self,key=None,base=None):
        self.key=key or os.getenv("APZ_MD_API_KEY","")
        self.base=base or os.getenv("APZ_MD_API_HOST","https://api.metadefender.com/v4")
    def lookup_sha256(self,sha256):
        if not self.key:
            return ProviderResult(self.name,False,"API_KEY_MISSING",error="APZ_MD_API_KEY")
        req=urllib.request.Request(
            self.base.rstrip()+"/hash/"+sha256,
            headers={"apikey":self.key,"Accept":"application/json"})
        try:
            with urllib.request.urlopen(req,timeout=30) as r:
                data=json.loads(r.read().decode())
            s=data.get("scan_results",data)
            details=s.get("scan_details",{}) if isinstance(s,dict) else {}
            detected=int(data.get("total_detected_avs",0) or 0)
            total=int(data.get("total_avs",0) or 0)
            overall=str(data.get("scan_all_result_a",data.get("overall_verdict","unknown"))).lower()
            v="malicious" if detected>0 or "infected" in overall or "malicious" in overall else ("no_threat" if total else "unknown")
            return ProviderResult(self.name,True,"OK",v,detected,0,max(0,total-detected),0,
                None,None,{"total_avs":total,"scan_details":details,"raw_verdict":overall})
        except urllib.error.HTTPError as e:
            return ProviderResult(self.name,False,f"HTTP_{e.code}",error=str(e))
        except Exception as e:
            return ProviderResult(self.name,False,"NETWORK_ERROR",error=str(e))

class LocalIOCProvider(ReputationProvider):
    name="Local IOC"
    def __init__(self, path=None):
        self.path=Path(path or os.getenv("APZ_IOC_DB",Path.home()/".apz_manager"/"iocs.csv"))
    def lookup_sha256(self,sha256):
        if not self.path.exists():
            return ProviderResult(self.name,False,"DB_NOT_FOUND")
        try:
            with self.path.open(newline="",encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    h=(row.get("sha256") or row.get("hash") or "").strip().lower()
                    if h==sha256.lower():
                        verdict=(row.get("verdict") or "malicious").lower()
                        return ProviderResult(self.name,True,"MATCH",verdict,
                            details={k:v for k,v in row.items() if k})
            return ProviderResult(self.name,True,"NO_MATCH","unknown")
        except Exception as e:
            return ProviderResult(self.name,False,"DB_ERROR",error=str(e))

class MultiReputationEngine:
    def __init__(self, providers=None):
        self.providers=providers or [VirusTotalProvider(),HybridAnalysisProvider(),
                                     MetaDefenderProvider(),LocalIOCProvider()]
    def lookup(self,sha256):
        results=[p.lookup_sha256(sha256) for p in self.providers]
        malicious=sum(r.verdict=="malicious" for r in results)
        suspicious=sum(r.verdict=="suspicious" for r in results)
        available=sum(r.available for r in results)
        # Conservative consensus: provider count matters more than one weak hit.
        if malicious>=2: overall="malicious"
        elif malicious==1: overall="likely_malicious"
        elif suspicious>=2: overall="suspicious"
        elif suspicious==1: overall="suspicious"
        elif available: overall="no_threat"
        else: overall="unknown"
        confidence=min(98, 40 + available*15 + max(0,malicious-1)*15 + max(0,suspicious-1)*8)
        return {"sha256":sha256,"overall_verdict":overall,"confidence":confidence,
                "providers":[asdict(r) for r in results]}

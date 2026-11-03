import json, os, re, hashlib, zipfile, threading, urllib.request, urllib.error
from pathlib import Path
import tkinter as tk
from reputation_engine import MultiReputationEngine
from tkinter import ttk, filedialog, messagebox

APP = "APZ Manager Windows"
APP_DIR = Path.home() / ".apz_manager"
REPORT_DIR = APP_DIR / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

SENSITIVE = {
    "android.permission.READ_SMS": ("SMS", 9, "خواندن پیامک؛ داده حساس و بالقوه قابل سوءاستفاده."),
    "android.permission.RECEIVE_SMS": ("SMS", 8, "دریافت پیامک؛ در برخی برنامه‌ها می‌تواند برای کدهای تأیید حساس باشد."),
    "android.permission.SEND_SMS": ("SMS", 10, "ارسال پیامک؛ می‌تواند هزینه یا سوءاستفاده ایجاد کند."),
    "android.permission.RECORD_AUDIO": ("Microphone", 8, "دسترسی به میکروفون؛ برای برنامه‌های غیرمرتبط حساس است."),
    "android.permission.CAMERA": ("Camera", 6, "دسترسی به دوربین؛ علت نیاز باید بررسی شود."),
    "android.permission.ACCESS_FINE_LOCATION": ("Location", 6, "موقعیت دقیق کاربر."),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("Background Location", 9, "موقعیت حتی در پس‌زمینه."),
    "android.permission.READ_CONTACTS": ("Contacts", 7, "خواندن دفترچه مخاطبین."),
    "android.permission.WRITE_CONTACTS": ("Contacts", 7, "تغییر دفترچه مخاطبین."),
    "android.permission.READ_CALL_LOG": ("Call Log", 9, "خواندن سابقه تماس."),
    "android.permission.WRITE_CALL_LOG": ("Call Log", 9, "تغییر سابقه تماس."),
    "android.permission.SYSTEM_ALERT_WINDOW": ("Overlay", 10, "نمایش روی برنامه‌های دیگر؛ در سوءاستفاده می‌تواند برای فیشینگ به کار رود."),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("Installer", 10, "توانایی درخواست نصب APK؛ منبع و زنجیره اعتماد مهم است."),
}

TOKENS = [
    "keylogger","stealer","spyware","ransom","credential","password",
    "injector","hook","frida","xposed","rootkit","miner","cryptominer"
]

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def printable_hits(data):
    text = data.decode("utf-8", errors="ignore")
    return [t for t in TOKENS if re.search(r"(?i)" + re.escape(t), text)]

def analyze_apk(path):
    path = Path(path)
    if not zipfile.is_zipfile(path):
        raise ValueError("فایل APK معتبر یا ZIP نیست.")

    findings, positives, perms, exported = [], [], [], []
    native = set()
    suspicious = set()
    classes = []
    size = path.stat().st_size
    sha = sha256_file(path)

    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        native.update(n.split("/")[1] for n in names if n.startswith("lib/") and n.count("/") >= 2)
        classes = [n for n in names if n.endswith(".dex")]
        manifest = b""
        if "AndroidManifest.xml" in names:
            manifest = z.read("AndroidManifest.xml")
        for n in names:
            if n.endswith((".dex",".txt",".json",".xml")):
                try:
                    data = z.read(n)
                    if len(data) > 2_000_000:
                        data = data[:2_000_000]
                    for token in printable_hits(data):
                        suspicious.add(f"{token} ← {n}")
                except Exception:
                    pass

    # Binary AndroidManifest.xml cannot be fully decoded without Android build tools.
    # We still provide strong ZIP/content analysis and a transparent limitation.
    if "AndroidManifest.xml" in names:
        positives.append("AndroidManifest.xml در APK وجود دارد.")
    if classes:
        positives.append(f"{len(classes)} فایل DEX پیدا شد.")
    if native:
        positives.append("Native library: " + ", ".join(sorted(native)))

    if suspicious:
        findings.append(("رشته‌های مشکوک", 20, "الگوهای حساس در محتوای APK دیده شد؛ این به‌تنهایی اثبات بدافزار نیست.", list(sorted(suspicious))[:12]))

    if size > 250 * 1024 * 1024:
        findings.append(("حجم غیرمعمول APK", 5, "APK بسیار بزرگ است؛ می‌تواند کاملاً مشروع باشد و به‌تنهایی نشانه بدافزار نیست.", [f"{size/1024/1024:.1f} MB"]))

    # Heuristic permission discovery from decoded text/resources where available.
    permission_text = []
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if n.endswith((".xml",".txt",".json",".dex")):
                try:
                    d = z.read(n)
                    s = d.decode("utf-8", errors="ignore")
                    permission_text.append(s)
                except Exception:
                    pass
    blob = "\n".join(permission_text)
    for p, (cat, weight, explanation) in SENSITIVE.items():
        if p in blob:
            perms.append((p, cat, weight, explanation))
    if perms:
        total = min(45, sum(x[2] for x in perms))
        findings.append(("مجوزهای حساس", total, "مجوزهای پراثر در محتوای قابل خواندن APK پیدا شد.", [x[0] for x in perms]))
    else:
        positives.append("مجوز حساس قابل شناسایی در بخش‌های متنی APK پیدا نشد؛ ممکن است Manifest باینری باشد.")

    score = min(100, sum(x[1] for x in findings))
    if score >= 80: level = "CRITICAL"
    elif score >= 55: level = "HIGH"
    elif score >= 30: level = "MEDIUM"
    else: level = "LOW"
    confidence = min(92, 55 + len(findings)*9)

    summary = {
        "file": str(path),
        "file_size": size,
        "sha256": sha,
        "dex_count": len(classes),
        "native_abis": sorted(native),
        "permissions": [dict(permission=p, category=c, severity=w, explanation_fa=e) for p,c,w,e in perms],
        "suspicious_strings": sorted(suspicious),
        "findings": [
            {"title_fa": a, "weight": b, "detail_fa": c, "evidence": d}
            for a,b,c,d in findings
        ],
        "positives": positives,
        "risk_score": score,
        "risk_level": level,
        "confidence": confidence,
        "limitations": [
            "تحلیل فعلی static/heuristic است.",
            "برای decode کامل AndroidManifest.xml به aapt/aapt2 یا ابزار APK parser نیاز است.",
            "یافتن یک رشته مشکوک به معنی بدافزار قطعی نیست."
        ]
    }
    return summary

def local_explanation(r):
    lead = {
        "LOW":"ریسک کلی پایین ارزیابی شده است.",
        "MEDIUM":"چند نشانه قابل توجه دیده شده و بررسی بیشتر توصیه می‌شود.",
        "HIGH":"چند عامل مهم ریسک دیده شده و قبل از اعتماد باید منبع APK بررسی شود.",
        "CRITICAL":"عوامل پرخطر متعددی دیده شده؛ بدون بررسی بیشتر نصب/اجرا توصیه نمی‌شود."
    }[r["risk_level"]]
    factors = " ".join(f'«{x["title_fa"]}»: {x["detail_fa"]}' for x in r["findings"][:4])
    return f"{lead} امتیاز {r['risk_score']}/100 و اطمینان {r['confidence']}٪ است. {factors}"

def ai_answer(r, question, endpoint, key, model):
    prompt = {
        "role": "Android security analyst",
        "language": "Persian",
        "question": question,
        "report": r,
        "rule": "Treat heuristics as evidence, not proof of malware."
    }
    payload = json.dumps({
        "model": model,
        "temperature": 0.1,
        "messages": [
            {"role":"system","content":"تو دستیار امنیت Android هستی. فقط بر اساس شواهد گزارش پاسخ بده و عدم قطعیت را شفاف بگو. پاسخ فارسی."},
            {"role":"user","content":json.dumps(prompt, ensure_ascii=False)}
        ]
    }).encode("utf-8")
    req = urllib.request.Request(endpoint, data=payload, method="POST",
        headers={"Content-Type":"application/json","Authorization":"Bearer "+key})
    with urllib.request.urlopen(req, timeout=45) as resp:
        obj = json.loads(resp.read().decode("utf-8"))
    return obj["choices"][0]["message"]["content"]

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP)
        self.geometry("1180x760")
        self.minsize(950,650)
        self.report = None
        self.reputation = None
        self._build()

    def _build(self):
        style = ttk.Style(self)
        try: style.theme_use("vista")
        except Exception: pass

        top = ttk.Frame(self, padding=12)
        top.pack(fill="x")
        ttk.Label(top, text="APZ Manager", font=("Segoe UI", 22, "bold")).pack(side="left")
        ttk.Label(top, text="  Windows AI Security Suite", font=("Segoe UI", 11)).pack(side="left", pady=(9,0))

        buttons = ttk.Frame(self, padding=(12,0))
        buttons.pack(fill="x")
        ttk.Button(buttons, text="انتخاب و تحلیل APK", command=self.pick).pack(side="left", padx=4)
        ttk.Button(buttons, text="ذخیره گزارش JSON", command=self.save_report).pack(side="left", padx=4)
        ttk.Button(buttons, text="AI Assistant", command=self.ask_ai).pack(side="left", padx=4)
        ttk.Button(buttons, text="Multi-Reputation", command=self.multi_reputation).pack(side="left", padx=4)

        self.score = ttk.Label(buttons, text="Risk: —", font=("Segoe UI", 12, "bold"))
        self.score.pack(side="right")

        body = ttk.PanedWindow(self, orient="horizontal")
        body.pack(fill="both", expand=True, padx=12, pady=12)

        left = ttk.Frame(body, padding=8)
        right = ttk.Frame(body, padding=8)
        body.add(left, weight=1); body.add(right, weight=2)

        ttk.Label(left, text="Security Report", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        self.tree = ttk.Treeview(left, columns=("weight","detail"), show="headings")
        self.tree.heading("weight", text="Weight")
        self.tree.heading("detail", text="Finding")
        self.tree.column("weight", width=70)
        self.tree.column("detail", width=310)
        self.tree.pack(fill="both", expand=True, pady=8)

        ttk.Label(right, text="تحلیل و شواهد", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        self.text = tk.Text(right, wrap="word", font=("Segoe UI", 10))
        self.text.pack(fill="both", expand=True)
        self.text.insert("1.0", "یک APK انتخاب کنید تا تحلیل شروع شود.\n\nنکته: این نسخه Windows مستقل از Google/Android SDK اجرا می‌شود و برای تحلیل اولیه APK از ZIP/static analysis استفاده می‌کند.")

        bottom = ttk.Frame(self, padding=(12,0,12,12))
        bottom.pack(fill="x")
        ttk.Label(bottom, text="AI endpoint (اختیاری):").pack(side="left")
        self.endpoint = ttk.Entry(bottom, width=42)
        self.endpoint.insert(0, "https://api.openai.com/v1/chat/completions")
        self.endpoint.pack(side="left", padx=5)
        ttk.Label(bottom, text="Model:").pack(side="left")
        self.model = ttk.Entry(bottom, width=18)
        self.model.insert(0, "gpt-4.1-mini")
        self.model.pack(side="left", padx=5)

    def pick(self):
        p = filedialog.askopenfilename(title="Select APK", filetypes=[("Android APK","*.apk"),("All files","*.*")])
        if not p: return
        self.text.delete("1.0","end")
        self.text.insert("end", "در حال تحلیل APK…\n")
        self.update_idletasks()
        try:
            self.report = analyze_apk(p)
            self.render()
        except Exception as e:
            messagebox.showerror("APZ Manager", str(e))

    def render(self):
        r = self.report
        self.score.config(text=f"Risk: {r['risk_score']}/100 • {r['risk_level']} • {r['confidence']}%")
        for x in self.tree.get_children(): self.tree.delete(x)
        for f in r["findings"]:
            self.tree.insert("", "end", values=(f["weight"], f["title_fa"]))
        self.text.delete("1.0","end")
        self.text.insert("end", local_explanation(r) + "\n\n")
        self.text.insert("end", "SHA-256:\n" + r["sha256"] + "\n\n")
        self.text.insert("end", "مثبت‌ها:\n")
        for x in r["positives"]: self.text.insert("end", "✓ " + x + "\n")
        self.text.insert("end", "\nشواهد:\n")
        for f in r["findings"]:
            self.text.insert("end", f"\n[{f['weight']}] {f['title_fa']}\n{f['detail_fa']}\n")
            for e in f["evidence"]: self.text.insert("end", "  • " + e + "\n")
        self.text.insert("end", "\nمحدودیت‌ها:\n")
        for x in r["limitations"]: self.text.insert("end", "• " + x + "\n")

    def save_report(self):
        if not self.report:
            messagebox.showinfo("APZ Manager", "ابتدا APK را تحلیل کنید.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".json", initialfile="apz-security-report.json",
                                         filetypes=[("JSON","*.json")])
        if p:
            export=dict(self.report)
            if self.reputation: export["multi_reputation"]=self.reputation
            Path(p).write_text(json.dumps(export, ensure_ascii=False, indent=2), encoding="utf-8")
            messagebox.showinfo("APZ Manager", "گزارش ذخیره شد.")


    def multi_reputation(self):
        if not self.report:
            messagebox.showinfo("Reputation","ابتدا APK را تحلیل کنید."); return
        self.text.insert("end","\n\nMulti-Reputation: در حال بررسی ۴ منبع…\n")
        def work():
            result=MultiReputationEngine().lookup(self.report["sha256"])
            self.reputation=result
            self.after(0,lambda:self.render_reputation(result))
        threading.Thread(target=work,daemon=True).start()

    def render_reputation(self,r):
        self.text.insert("end","\n=== Multi-Source Reputation ===\n")
        self.text.insert("end",f"Overall: {r['overall_verdict']} • Confidence: {r['confidence']}%\n")
        for x in r["providers"]:
            self.text.insert("end",f"\n[{x['provider']}] {x['status']} → {x['verdict']}\n")
            if x.get("malicious") is not None:
                self.text.insert("end",f"malicious={x.get('malicious',0)}, suspicious={x.get('suspicious',0)}, harmless={x.get('harmless',0)}, undetected={x.get('undetected',0)}\n")
            if x.get("error"): self.text.insert("end",f"error={x['error']}\n")
            if x.get("report_url"): self.text.insert("end",f"report={x['report_url']}\n")
        self.text.insert("end","\nتوجه: موتور اجماع شواهد چند منبع را ترکیب می‌کند؛ نتیجه Reputation به‌تنهایی اثبات قطعی بدافزار نیست.\n")

    def ask_ai(self):
        if not self.report:
            messagebox.showinfo("APZ Manager", "ابتدا APK را تحلیل کنید.")
            return
        q = tk.simpledialog.askstring("AI Security Assistant", "سؤال خود را درباره APK بنویسید:",
                                      initialvalue="چرا این APK پرریسک است و قبل از نصب چه چیزهایی را بررسی کنم؟")
        if not q: return
        key = os.getenv("APZ_AI_API_KEY", "")
        endpoint = self.endpoint.get().strip()
        model = self.model.get().strip()
        if not key:
            self.text.insert("end", "\n\nAI محلی:\n" + local_explanation(self.report))
            return
        def work():
            try:
                ans = ai_answer(self.report, q, endpoint, key, model)
                self.after(0, lambda: self.text.insert("end", "\n\nAI:\n"+ans+"\n"))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("AI", str(e)))
        threading.Thread(target=work, daemon=True).start()

if __name__ == "__main__":
    import tkinter.simpledialog
    App().mainloop()

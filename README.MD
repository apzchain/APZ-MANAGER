📦 APZ Manager – راهنمای جامع ریپازیتوری

یک پلتفرم کامل تحلیل امنیتی APK برای ویندوز، لینوکس و macOS
ترکیب تحلیل ایستا، اعتبارسنجی چندمنبعی، YARA، MITRE ATT&CK، فیوژن ریسک، API، دیتابیس و زنجیره‌ی ابزارهای امنیتی

---

🔰 معرفی

APZ Manager یک ابزار قدرتمند و ماژولار برای تحلیل امنیتی فایل‌های APK (اپلیکیشن‌های اندروید) است که به‌صورت آفلاین و بدون نیاز به Android SDK کار می‌کند. این پروژه با ترکیب تکنیک‌های تحلیل ایستا، اعتبارسنجی چندمنبعی، قوانین YARA، نگاشت به MITRE ATT&CK، فیوژن ریسک قابل توضیح و شبیه‌سازی رفتار پویا، یک گزارش امنیتی جامع و قابل اعتماد ارائه می‌دهد.

ویژگی کلیدی این پلتفرم، قابلیت زنجیره‌ای شدن (Chain) است که به شما امکان می‌دهد:

· تحلیل‌ها را در پایگاه داده SQLite ذخیره کنید.
· از طریق API RESTful با CI/CD، SIEM و SOAR یکپارچه شوید.
· تحلیل‌های دسته‌ای و همزمان انجام دهید.
· گزارش‌های JSON، HTML و PDF تولید کنید.

---

✨ ویژگی‌های اصلی

ویژگی توضیح
🔍 تحلیل ایستای پیشرفته استخراج رشته‌های مشکوک، کتابخانه‌های native، فایل‌های DEX، و حجم فایل
📄 دیکودر AndroidManifest با استفاده از androguard مجوزها، فعالیت‌ها، سرویس‌ها و کامپوننت‌های exported را دقیقاً استخراج می‌کند.
🧠 موتور فیوژن ریسک ۲.۰ ترکیب ۷ دسته شواهد (Reputation، YARA، IOC، Manifest، MITRE، Certificate، Sandbox) با وزن‌دهی هوشمند و خروجی قابل توضیح
🌐 اعتبارسنجی چندمنبعی پشتیبانی از VirusTotal، Hybrid Analysis، MetaDefender Cloud و پایگاه محلی IOC
🐍 اسکنر YARA قوانین داخلی + امکان بارگذاری قوانین خارجی .yar با پشتیبانی از meta-data
🎯 نگاشت MITRE ATT&CK ارتباط یافته‌ها با تکنیک‌های شناخته‌شده‌ی ATT&CK
📊 گزارش‌دهی حرفه‌ای خروجی به فرمت‌های JSON، HTML (قابل چاپ) و PDF (با weasyprint)
🖥️ رابط کاربری گرافیکی (GUI) محیط ویندوزی با نمایش درخت‌واره، Progress Bar و دکمه‌های عملیاتی
⌨️ حالت خط فرمان (CLI) اجرای تحلیل بدون رابط کاربری برای اتوماسیون و اسکریپت‌نویسی
🗄️ پایگاه داده یکپارچه ذخیره‌سازی تاریخچه‌ی تحلیل‌ها، Reputation و IOCها در SQLite
🌐 API RESTful سرور Flask برای یکپارچه‌سازی با سیستم‌های خارجی
🧩 Orchestrator مدیریت زنجیره، پردازش همزمان چندین APK، و تولید خلاصه‌های آماری
🧪 شبیه‌ساز Sandbox (اختیاری) شبیه‌سازی رفتار پویا بدون اجرای واقعی کد (قابل اتصال به Sandbox واقعی)

---

📋 پیش‌نیازها

· Python 3.8 یا بالاتر
· اتصال به اینترنت (برای دانلود کتابخانه‌ها و استفاده از APIهای ابری)
· (اختیاری) کلید API برای سرویس‌های: VirusTotal، Hybrid Analysis، MetaDefender Cloud و OpenAI

---

⚙️ نصب و راه‌اندازی

۱. کلون کردن ریپازیتوری

```bash
git clone https://github.com/your-org/apz-manager.git
cd apz-manager
```

۲. ایجاد محیط مجازی (توصیه‌شده)

```bash
python -m venv venv
source venv/bin/activate      # Linux/macOS
venv\Scripts\activate         # Windows
```

۳. نصب وابستگی‌ها

```bash
pip install -r requirements.txt
```

فایل requirements.txt شامل:

```
androguard>=3.4.0
pyyaml>=6.0
weasyprint>=60.0   # اختیاری برای PDF
flask>=2.0         # برای API
sqlalchemy>=1.4    # برای دیتابیس
```

۴. تنظیم کلیدهای API (اختیاری)

برای استفاده از اعتبارسنجی چندمنبعی و AI Assistant، متغیرهای محیطی را تنظیم کنید:

```bash
# Windows (با setx)
setx APZ_VT_API_KEY "your_vt_key"
setx APZ_HA_API_KEY "your_ha_key"
setx APZ_MD_API_KEY "your_md_key"
setx APZ_AI_API_KEY "your_openai_key"

# Linux/macOS (در ~/.bashrc یا ~/.zshrc)
export APZ_VT_API_KEY="your_vt_key"
export APZ_HA_API_KEY="your_ha_key"
export APZ_MD_API_KEY="your_md_key"
export APZ_AI_API_KEY="your_openai_key"
```

برای راحتی، اسکریپت set_reputation_keys.bat در ویندوز موجود است.

---

🚀 نحوه‌ی استفاده

A. حالت رابط کاربری گرافیکی (GUI)

```bash
python apz_manager.py
```

· دکمه‌ی انتخاب و تحلیل APK را بزنید.
· پیشرفت تحلیل را در Progress Bar مشاهده کنید.
· یافته‌ها در درخت‌واره و گزارش کامل در بخش متنی نمایش داده می‌شود.
· با دکمه‌های ذخیره گزارش، AI Assistant، Multi-Reputation و Threat Platform از قابلیت‌های بیشتر استفاده کنید.

---

B. حالت خط فرمان (CLI)

تحلیل یک فایل:

```bash
python apz_manager.py --file malware.apk --output result.json --db
```

· --file: مسیر APK
· --output: مسیر ذخیره‌ی گزارش JSON
· --db: ذخیره‌سازی در دیتابیس

تحلیل دسته‌ای:

```bash
python apz_manager.py --batch list.txt --output batch_results.json
```

فایل list.txt شامل مسیر هر APK در یک خط است.

---

C. استفاده از Orchestrator در کد

```python
from apz_orchestrator import APZOrchestrator

orch = APZOrchestrator()
report = orch.analyze_single('app.apk', source='my_script')
summary = orch.generate_summary(['sha1', 'sha2'])
print(summary)
```

---

D. سرور API (RESTful)

اجرای سرور:

```bash
python apz_api.py
```

سپس درخواست POST به آدرس http://localhost:5000/analyze با JSON زیر بفرستید:

```json
{"apk_path": "/path/to/app.apk"}
```

پاسخ، گزارش کامل تحلیل خواهد بود.

دیگر Endpointها:

· POST /batch – تحلیل دسته‌ای
· GET /summary/<sha256> – خلاصه‌ی یک SHA خاص
· GET /stats – آمار کلی تحلیل‌ها

---

🏗️ معماری و زنجیره‌ی APZ

```
┌─────────────────────────────────────────────────────────────┐
│                      APZ Manager                           │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐   ┌──────────────┐   ┌───────────────┐  │
│  │    GUI      │   │     CLI      │   │    API        │  │
│  └──────┬──────┘   └──────┬───────┘   └───────┬───────┘  │
│         └─────────────────┼───────────────────┘          │
│                           ▼                                │
│  ┌─────────────────────────────────────────────────────┐  │
│  │               APZ Orchestrator                      │  │
│  └──────────────────────┬──────────────────────────────┘  │
│                         ▼                                  │
│  ┌─────────────────────────────────────────────────────┐  │
│  │                تحلیل ایستا (apz_manager)             │  │
│  │  - استخراج رشته‌ها، DEX، native ABI، حجم           │  │
│  │  - دیکودر AndroidManifest (androguard)             │  │
│  └──────────────────────┬──────────────────────────────┘  │
│                         ▼                                  │
│  ┌─────────────────────────────────────────────────────┐  │
│  │          اعتبارسنجی چندمنبعی (Reputation)           │  │
│  │  VirusTotal | Hybrid Analysis | MetaDefender | IOC │  │
│  └──────────────────────┬──────────────────────────────┘  │
│                         ▼                                  │
│  ┌─────────────────────────────────────────────────────┐  │
│  │    Threat Platform (YARA + IOC + MITRE)             │  │
│  │  - اسکنر YARA با قوانین داخلی/خارجی                │  │
│  │  - استخراج IOC (IP, Domain, URL, Package)          │  │
│  │  - نگاشت به MITRE ATT&CK                           │  │
│  └──────────────────────┬──────────────────────────────┘  │
│                         ▼                                  │
│  ┌─────────────────────────────────────────────────────┐  │
│  │        Risk Fusion Engine 2.0 (قابل توضیح)          │  │
│  │  - ۷ دسته شواهد با وزن‌دهی                         │  │
│  │  - خروجی: score, level, confidence, verdict,       │  │
│  │    evidence, recommendations, limitations          │  │
│  └──────────────────────┬──────────────────────────────┘  │
│                         ▼                                  │
│  ┌─────────────────────────────────────────────────────┐  │
│  │        پایگاه داده (SQLite) + گزارش‌سازی            │  │
│  │  - ذخیره‌سازی تاریخچه                              │  │
│  │  - تولید JSON / HTML / PDF                         │  │
│  └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

📁 ساختار پروژه

```
APZ-Manager/
├── apz_manager.py          # رابط کاربری (GUI) و حالت CLI
├── apz_orchestrator.py     # هماهنگ‌کننده‌ی زنجیره (مدیریت تحلیل‌ها، دیتابیس)
├── apz_api.py              # سرور RESTful API (Flask)
├── reputation_engine.py    # موتور اعتبارسنجی چندمنبعی
├── threat_platform.py      # لایه‌ی تحلیل تهدید (YARA, IOC, MITRE)
├── risk_fusion_engine.py   # موتور فیوژن ریسک ۲.۰
├── axml_parser.py          # دیکودر AndroidManifest.xml با androguard
├── sandbox_adapter.py      # آداپتور شبیه‌سازی Sandbox (قابل اتصال به سرویس واقعی)
├── report_generator.py     # تولید گزارش‌های HTML و PDF
├── database.py             # مدل‌های دیتابیس SQLite
├── logger.py               # مدیریت لاگ‌ها
├── config.yaml             # فایل پیکربندی مرکزی
├── requirements.txt        # وابستگی‌های پروژه
├── build_windows.bat       # ساخت فایل اجرایی EXE با PyInstaller
├── run_windows.bat         # اجرا در ویندوز
├── set_reputation_keys.bat # تنظیم کلیدهای API
├── rules/                  # پوشه‌ی قوانین YARA خارجی
│   └── android_rules.yar   # نمونه قوانین
├── docs/                   # مستندات تکمیلی
│   ├── USER_GUIDE.md
│   └── API_REFERENCE.md
└── tests/                  # تست‌های واحد
    ├── test_axml.py
    ├── test_fusion.py
    └── test_yara.py
```

---

🧪 نمونه خروجی JSON

```json
{
  "file": "C:/samples/malware.apk",
  "sha256": "a1b2c3d4e5f6...",
  "risk_score": 78,
  "risk_level": "HIGH",
  "confidence": 88,
  "sandbox_verdict": "suspicious",
  "findings": [
    {
      "title_fa": "مجوزهای حساس",
      "weight": 35,
      "detail_fa": "مجوزهای خطرناک شناسایی شد.",
      "evidence": ["android.permission.READ_SMS", "android.permission.CAMERA"]
    },
    {
      "title_fa": "YARA",
      "weight": 20,
      "detail_fa": "قوانین YARA فعال شدند.",
      "evidence": ["Android_Accessibility_Abuse (critical)", "Android_SMS_Interception (high)"]
    }
  ],
  "permissions": ["android.permission.READ_SMS", ...],
  "limitations": ["تحلیل static/heuristic است..."]
}
```

---

🤝 مشارکت

ما از مشارکت شما استقبال می‌کنیم! برای همکاری:

1. ریپازیتوری را Fork کنید.
2. یک شاخه‌ی جدید برای ویژگی یا رفع اشکال ایجاد کنید (git checkout -b feature/amazing-feature).
3. تغییرات خود را Commit کنید (git commit -m 'Add some amazing feature').
4. به شاخه‌ی اصلی Push کنید (git push origin feature/amazing-feature).
5. یک Pull Request باز کنید.

لطفاً پیش از ارسال PR، از اجرای تست‌ها و رعایت استانداردهای کد (PEP8) اطمینان حاصل کنید.

---

📜 مجوز

این پروژه تحت مجوز GNU General Public License v3.0 منتشر شده است. برای جزئیات بیشتر فایل LICENSE را ببینید.

---

📬 ارتباط با تیم

· ایمیل: support@apz-security.com
· گیت‌هاب: github.com/your-org/apz-manager
· مستندات آنلاین: docs.apz-security.com

---

🙏 قدردانی

از کتابخانه‌های متن‌باز زیر که در این پروژه استفاده شده‌اند، سپاسگزاریم:

· androguard – تحلیل فایل‌های APK
· yara-python – اسکنر YARA
· Flask – چارچوب وب
· SQLAlchemy – ORM دیتابیس
· WeasyPrint – تولید PDF

---

⚠️ نکات امنیتی مهم

· هرگز APKهای ناشناس را روی سیستم خود اجرا نکنید. این ابزار صرفاً تحلیل ایستا انجام می‌دهد و کد APK را اجرا نمی‌کند.
· کلیدهای API را در کد ذخیره نکنید. همیشه از متغیرهای محیطی یا فایل‌های پیکربندی خارج از ریپازیتوری استفاده کنید.
· گزارش‌ها را محرمانه نگه دارید. ممکن است شامل اطلاعات حساس (مثل IOCها یا SHA-256 فایل‌های مخرب) باشند.

---

🔧 عیب‌یابی سریع

مشکل راه‌حل
ModuleNotFoundError: No module named 'androguard' pip install -r requirements.txt را اجرا کنید.
خطای YARA compile error مطمئن شوید قوانین YARA در پوشه‌ی rules/ معتبر هستند.
API key missing متغیرهای محیطی مربوطه را تنظیم کنید (به بخش نصب مراجعه کنید).
Permission denied در ویندوز برنامه را به‌عنوان Administrator اجرا کنید.
گزارش‌های HTML نمایش داده نمی‌شوند مرورگر را به‌روز کنید یا از مرورگر دیگری استفاده کنید.

---


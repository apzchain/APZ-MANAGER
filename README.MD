📦 فایل کامل README.md — APZ Manager

```markdown
<div align="center">

# 🛡️ APZ Manager

### پلتفرم جامع تحلیل امنیتی APK

**ترکیب تحلیل ایستا، اعتبارسنجی چندمنبعی، YARA، MITRE ATT&CK، فیوژن ریسک، AI محلی، Kubernetes، GitOps و Observability**

[![License](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-24%2B-2496ED.svg)](https://docker.com)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.27%2B-326CE5.svg)](https://kubernetes.io)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](VERSION)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android-lightgrey.svg)](#-نصب-و-راهاندازی)

[معرفی](#-معرفی) • [ویژگی‌ها](#-ویژگیهای-اصلی) • [نصب](#-نصب-و-راهاندازی) • [استفاده](#-نحوهی-استفاده) • [معماری](#-معماری-و-زنجیرهی-apz) • [مستندات](#-مستندات-کامل)

</div>

---

## 📋 فهرست مطالب

- [معرفی](#-معرفی)
- [ویژگی‌های اصلی](#-ویژگیهای-اصلی)
- [معماری و زنجیره‌ی APZ](#-معماری-و-زنجیرهی-apz)
- [پیش‌نیازها](#-پیشنیازها)
- [نصب و راه‌اندازی](#-نصب-و-راهاندازی)
  - [نصب روی PC / Server](#نصب-روی-pc--server)
  - [نصب روی Android (Termux)](#نصب-روی-android-termux)
  - [نصب با Docker](#نصب-با-docker)
  - [نصب با Docker + GPU (AI محلی)](#نصب-با-docker--gpu-ai-محلی)
  - [نصب روی Kubernetes](#نصب-روی-kubernetes)
  - [Provision با Terraform](#provision-با-terraform)
- [نحوه‌ی استفاده](#-نحوهی-استفاده)
  - [حالت CLI](#a-حالت-cli)
  - [حالت GUI](#b-حالت-gui)
  - [RESTful API](#c-restful-api)
  - [Kubernetes / GitOps](#d-kubernetes--gitops)
- [پکیج‌های تکمیلی](#-پکیجهای-تکمیلی)
  - [AIOps – تشخیص ناهنجاری](#1-aiops--تشخیص-ناهنجاری)
  - [ML Training – آموزش مدل اختصاصی](#2-ml-training--آموزش-مدل-اختصاصی)
  - [Forensics – جرم‌شناسی خودکار](#3-forensics--جرمشناسی-خودکار)
  - [Compliance – ISO 27001 / SOC 2](#4-compliance--iso-27001--soc-2-as-code)
  - [Red-Team – تست نفوذ خودکار](#5-red-team--تست-نفوذ-خودکار)
  - [Cost – Kubecost + FinOps](#6-cost--kubecost--finops)
  - [Chaos – Chaos Mesh](#7-chaos--chaos-mesh)
  - [SBOM – Syft + Grype](#8-sbom--syft--grype)
  - [Secrets – Vault + ESO](#9-secrets--vault--external-secrets)
  - [OnCall – PagerDuty + Opsgenie](#10-oncall--pagerduty--opsgenie)
  - [ArgoCD – GitOps](#11-argocd--gitops)
  - [Policy – OPA / Gatekeeper](#12-policy--opa--gatekeeper)
  - [Metrics – Prometheus + Grafana](#13-metrics--prometheus--grafana)
  - [Backup – CronJob + Velero](#14-backup--cronjob--velero)
- [ساختار پروژه](#-ساختار-پروژه)
- [پیکربندی](#-پیکربندی)
- [نمونه‌ی خروجی](#-نمونهی-خروجی)
- [مستندات کامل](#-مستندات-کامل)
- [نکات امنیتی](#-نکات-امنیتی-مهم)
- [عملکرد و مقیاس](#-عملکرد-و-مقیاس)
- [عیب‌یابی](#-عیبیابی-سریع)
- [مشارکت](#-مشارکت)
- [مجوز](#-مجوز)
- [ارتباط با تیم](#-ارتباط-با-تیم)
- [قدردانی](#-قدردانی)

---

## 🔰 معرفی

**APZ Manager** یک پلتفرم جامع، ماژولار و متن‌باز برای **تحلیل امنیتی APK** است که به‌صورت **آفلاین** و **بدون نیاز به Android SDK** کار می‌کند. این ابزار با ترکیب:

- تحلیل ایستای پیشرفته
- اعتبارسنجی چندمنبعی (VirusTotal، Hybrid Analysis، MetaDefender)
- موتور YARA با قوانین سفارشی
- نگاشت به MITRE ATT&CK
- موتور فیوژن ریسک قابل توضیح (XAI)
- شبیه‌سازی رفتار پویا (Sandbox)
- **قابلیت اجرا روی Android، Docker، Kubernetes و Clusterهای Cloud**
- **AI محلی با Ollama (بدون ارسال داده به بیرون)**
- **Observability کامل (Metrics + Logs + Traces)**
- **GitOps، Policy as Code، Compliance as Code**

یک **گزارش امنیتی جامع، قابل اعتماد و مقیاس‌پذیر** ارائه می‌دهد.

### 🎯 چرا APZ Manager؟

| چالش | راه‌حل APZ |
|---|---|
| داده‌های حساس را نمی‌توان به سرویس‌های ابری فرستاد | **AI محلی با Ollama** – هیچ داده‌ای خارج نمی‌شود |
| تحلیل دسته‌ای APKها زمان‌بر است | **پردازش موازی + Queue** با Redis |
| نیاز به استقرار روی cloud/on-prem | **Docker + K8s + Terraform** |
| Compliance و Audit | **ISO 27001 / SOC 2 as Code** |
| مقیاس‌پذیری و پایداری | **ArgoCD + HPA + Chaos Engineering** |
| تحلیل فوری روی دستگاه | **اجرا روی Android با Termux** |

---

## ✨ ویژگی‌های اصلی

| ویژگی | توضیح |
|---|---|
| 🔍 **تحلیل ایستای پیشرفته** | استخراج رشته‌های مشکوک، کتابخانه‌های native، فایل‌های DEX، ABI، حجم و entropy |
| 📄 **دیکودر AndroidManifest** | با `androguard` – مجوزها، فعالیت‌ها، سرویس‌ها، receiverها و کامپوننت‌های exported |
| 🧠 **موتور فیوژن ریسک ۲.۰** | ترکیب ۷ دسته شواهد با وزن‌دهی هوشمند و خروجی قابل توضیح (XAI) |
| 🌐 **اعتبارسنجی چندمنبعی** | VirusTotal، Hybrid Analysis، MetaDefender Cloud، IOC محلی |
| 🐍 **اسکنر YARA** | قوانین داخلی + قوانین سفارشی `.yar` با پشتیبانی از meta-data |
| 🎯 **نگاشت MITRE ATT&CK** | اتصال یافته‌ها به تکنیک‌های شناخته‌شده |
| 📊 **گزارش‌دهی حرفه‌ای** | JSON، HTML (قابل چاپ)، PDF (با weasyprint) |
| 🖥️ **رابط گرافیکی (GUI)** | محیط Tkinter با درخت‌واره، Progress Bar و دکمه‌های عملیاتی |
| ⌨️ **CLI کامل** | اجرا بدون رابط برای اتوماسیون و CI/CD |
| 🗄️ **پایگاه داده SQLite** | ذخیره‌سازی تاریخچه، Reputation و IOCها |
| 🌐 **RESTful API** | سرور Flask برای یکپارچگی با SIEM/SOAR |
| 🧩 **Orchestrator** | مدیریت زنجیره، پردازش همزمان، خلاصه‌های آماری |
| 🧪 **Sandbox (اختیاری)** | شبیه‌سازی رفتار بدون اجرای واقعی کد |
| 🤖 **AI محلی (Ollama)** | خلاصه، توضیح ریسک، توصیه‌ها، طبقه‌بندی family |
| 📱 **اجرا روی Android** | با Termux – نصب یک‌دستوری با `make install` |
| 🐳 **Docker + GPU** | ایمیج‌های slim / main / gpu / aiops / ml-training / redteam |
| ☸️ **Kubernetes Native** | Manifestهای کامل + HPA + PDB + NetworkPolicy |
| 🚀 **GitOps با ArgoCD** | ApplicationSet برای dev/staging/prod |
| 🔐 **Secrets Management** | Vault + External Secrets Operator |
| 📈 **Observability کامل** | Prometheus + Grafana + Loki + AIOps |
| 💰 **FinOps** | Kubecost + گزارش هزینه به تفکیک namespace |
| 🧪 **Chaos Engineering** | Chaos Mesh با ۱۰ experiment آماده |
| 📜 **Compliance as Code** | Conftest + ISO 27001 + SOC 2 |
| 🕵️ **Forensics** | Volatility + Velero + Memory Dump خودکار |
| 🔴 **Self Red-Team** | ۸ ماژول تست نفوذ خودکار روی خود APZ |

---

## 🏗️ معماری و زنجیره‌ی APZ

```

┌──────────────────────────────────────────────────────────────────────┐
│                          APZ Manager Stack                            │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ╔═══════════════ Entrypoints ═══════════════╗                      │
│   ║   CLI    │    GUI    │   REST API   │  K8s  ║                    │
│   ╚══════════════╤════════════════════════════╝                      │
│                  ▼                                                    │
│   ┌─────────────────────────────────────────────────────┐            │
│   │              APZ Orchestrator                        │            │
│   └────────────────────┬────────────────────────────────┘            │
│                        ▼                                             │
│   ┌─────────────────────────────────────────────────────┐            │
│   │         تحلیل ایستا (androguard + strings)          │            │
│   └────────────────────┬────────────────────────────────┘            │
│                        ▼                                             │
│   ┌─────────────────────────────────────────────────────┐            │
│   │         اعتبارسنجی چندمنبعی (Reputation)             │            │
│   │    VT | HA | MD | IOC Local                          │            │
│   └────────────────────┬────────────────────────────────┘            │
│                        ▼                                             │
│   ┌─────────────────────────────────────────────────────┐            │
│   │         Threat Platform (YARA + IOC + MITRE)        │            │
│   └────────────────────┬────────────────────────────────┘            │
│                        ▼                                             │
│   ┌─────────────────────────────────────────────────────┐            │
│   │         Risk Fusion Engine 2.0 (XAI)                │            │
│   │   7 categories × smart weighting                     │            │
│   └────────────────────┬────────────────────────────────┘            │
│                        ▼                                             │
│   ┌─────────────────────────────────────────────────────┐            │
│   │         AI Enrichment (Ollama)                       │            │
│   │   Summary | Risk Explain | Family | Recommends       │            │
│   └────────────────────┬────────────────────────────────┘            │
│                        ▼                                             │
│   ┌─────────────────────────────────────────────────────┐            │
│   │    Database (SQLite) + Report (JSON/HTML/PDF)       │            │
│   └─────────────────────────────────────────────────────┘            │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘

```

### 🧩 معماری پلتفرمی (K8s + Observability + AIOps)

```

┌──────────────────────────────────────────────────────────────────────┐
│                       Kubernetes Cluster                              │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   GitHub ──► ArgoCD ──► [apz-dev, apz-staging, apz-prod]            │
│                            │                                         │
│   ┌────────────────────────▼────────────────────────────┐           │
│   │              apz namespace                          │           │
│   │   API • Worker • Ollama • Redis • Metrics Exporter  │           │
│   └────────────────────────┬────────────────────────────┘           │
│                            │                                         │
│   ┌────────────────────────▼────────────────────────────┐           │
│   │           Observability Layer                       │           │
│   │  Prometheus ──► Alertmanager ──► OnCall             │           │
│   │      │             │                                │           │
│   │      ▼             ▼                                │           │
│   │  Grafana    PagerDuty/Opsgenie/Slack                │           │
│   │      │                                              │           │
│   │      └─► Dashboards: Overview, Security, Cost, AIOps│           │
│   └─────────────────────────────────────────────────────┘           │
│                                                                      │
│   ┌────────────┐  ┌────────────┐  ┌──────────────┐                  │
│   │  Kubecost  │  │ Chaos Mesh │  │ Gatekeeper   │                  │
│   │  (FinOps)  │  │  (Chaos)   │  │  (Policy)    │                  │
│   └────────────┘  └────────────┘  └──────────────┘                  │
│                                                                      │
│   ┌────────────┐  ┌────────────┐  ┌──────────────┐                  │
│   │   Vault    │  │   Velero   │  │   Syft +     │                  │
│   │  + ESO     │  │  (Backup)  │  │   Grype      │                  │
│   └────────────┘  └────────────┘  └──────────────┘                  │
│                                                                      │
│   ┌────────────┐  ┌────────────┐  ┌──────────────┐                  │
│   │   AIOps    │  │  ML Train  │  │  Forensics   │                  │
│   │ Prophet/L  │  │  (GPU)     │  │ (Volatility) │                  │
│   └────────────┘  └────────────┘  └──────────────┘                  │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘

```

---

## 📋 پیش‌نیازها

### عمومی
- **Python 3.8+** (توصیه: 3.11+)
- **اتصال اینترنت** (برای دانلود کتابخانه‌ها)
- **کلیدهای API** (اختیاری): VirusTotal، Hybrid Analysis، MetaDefender، OpenAI

### برای Android (Termux)
- **Termux** از [F-Droid](https://f-droid.org/packages/com.termux/)
- ~2 GB حافظه‌ی آزاد
- Android 7+

### برای Docker
- **Docker 24+**
- **Docker Compose 2.20+**
- (برای GPU): **NVIDIA Driver 535+** + **nvidia-container-toolkit**

### برای Kubernetes
- **Kubernetes 1.27+**
- **kubectl 1.27+**
- **Helm 3.13+**
- (اختیاری) **ArgoCD 2.10+**

---

## ⚙️ نصب و راه‌اندازی

### نصب روی PC / Server

```bash
# 1) کلون
git clone https://github.com/your-org/apz-manager.git
cd apz-manager

# 2) محیط مجازی
python -m venv venv
source venv/bin/activate      # Linux/macOS
venv\Scripts\activate         # Windows

# 3) نصب وابستگی‌ها
pip install -r requirements.txt

# 4) تنظیم کلیدهای API (اختیاری)
cp .env.android.example .env
nano .env
```

نصب روی Android (Termux)

```bash
# 1) نصب پیش‌نیازها
pkg install -y python git make
git clone https://github.com/your-org/apz-manager.git
cd apz-manager

# 2) نصب کامل با یک دستور
make install

# 3) دسترسی به حافظه
make storage

# 4) تحلیل APK
make run APK=/sdcard/Download/app.apk
```

راهنمای کامل: docs/ANDROID.md

نصب با Docker

```bash
# 1) ساخت فایل‌های Docker
bash docker_setup.sh gen

# 2) Build و اجرا
bash docker_setup.sh build
bash docker_setup.sh run

# 3) API روی http://localhost:5000
curl http://localhost:5000/stats
```

نصب با Docker + GPU (AI محلی)

```bash
# 1) پیش‌نیاز: nvidia-container-toolkit
sudo apt install -y nvidia-container-toolkit
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker

# 2) راه‌اندازی کامل
bash setup_gpu.sh

# 3) سرویس‌ها:
#    - Ollama:  http://localhost:11434
#    - APZ API: http://localhost:5000
#    - Web UI:  http://localhost:3000
```

نصب روی Kubernetes

```bash
# 1) نصب APZ
bash k8s_setup.sh apply

# 2) اجرای ArgoCD (GitOps)
bash argocd/argocd_setup.sh bootstrap

# 3) نصب Policyها (Gatekeeper)
bash policy/policy_setup.sh bootstrap

# 4) نصب Observability
bash metrics/metrics_setup.sh apply
bash cost/cost_setup.sh install

# 5) نصب Secrets
bash secrets/secrets_setup.sh install

# 6) نصب OnCall
bash oncall/oncall_setup.sh apply
```

Provision با Terraform

```bash
# 1) تنظیم متغیرها
cd terraform
cp terraform.tfvars.example terraform.tfvars
nano terraform.tfvars

# 2) ساخت زیرساخت
bash terraform_setup.sh apply

# 3) اتصال به سرور
bash terraform_setup.sh ssh
```

---

🚀 نحوه‌ی استفاده

A) حالت CLI

```bash
# --- تحلیل یک فایل ---
python apz_manager.py --file malware.apk --output result.json --db

# --- تحلیل دسته‌ای ---
echo "/samples/a.apk" > list.txt
echo "/samples/b.apk" >> list.txt
python apz_manager.py --batch list.txt --output batch.json

# --- اسکن پوشه‌ای ---
./scan.sh --dir /samples --once

# --- مانیتور دائمی ---
./scan.sh --watch /samples

# --- ارسال به API به‌جای تحلیل محلی ---
./scan.sh --dir /samples --api http://apz:5000

# --- AI Enrichment روی گزارش ---
python ai_analyzer.py --report result.json --mode all
```

B) حالت GUI

```bash
python apz_manager.py
```

· دکمه‌ی «انتخاب و تحلیل APK» را بزنید
· پیشرفت را در Progress Bar ببینید
· یافته‌ها در درخت‌واره نمایش داده می‌شوند
· دکمه‌های ذخیره گزارش، AI Assistant، Multi-Reputation و Threat Platform در دسترس

C) RESTful API

```bash
# اجرای سرور
python apz_api.py
# یا
python apz_manager.py --api
```

نمونه درخواست:

```bash
curl -X POST http://localhost:5000/analyze \
    -H 'Content-Type: application/json' \
    -d '{"apk_path": "/samples/app.apk"}'
```

Endpoint متد توضیح
/analyze POST تحلیل یک APK
/batch POST تحلیل دسته‌ای
/summary/<sha256> GET خلاصه‌ی یک SHA
/stats GET آمار کلی
/metrics GET متریک‌های Prometheus
/health GET بررسی سلامت

D) Kubernetes / GitOps

```bash
# سینک دستی
argocd app sync apz-prod

# مشاهده وضعیت
argocd app list

# مشاهده لاگ
kubectl -n apz logs -l app.kubernetes.io/name=apz-api -f
```

---

🧩 پکیج‌های تکمیلی

1) AIOps – تشخیص ناهنجاری

تشخیص ناهنجاری روی متریک‌های Prometheus با Prophet + LSTM.

```bash
cd aiops
bash aiops_setup.sh install
bash aiops_setup.sh list
```

ویژگی‌ها:

· Prophet (روند + فصلی)
· LSTM Autoencoder (الگوهای پیچیده)
· Ensemble (ترکیب هر دو)
· آستانه‌ی پویا بر اساس MAD
· Alert به Alertmanager + Slack

2) ML Training – آموزش مدل اختصاصی

Fine-tune مدل Transformer روی دیتاست malware برای طبقه‌بندی family.

```bash
cd ml-training
bash ml_training_setup.sh install
bash ml_training_setup.sh extract        # استخراج دیتاست از گزارش‌های APZ
bash ml_training_setup.sh train          # آموزش
bash ml_training_setup.sh eval models/apz-xxx  # ارزیابی
```

ویژگی‌ها:

· استخراج خودکار feature از گزارش‌های APZ
· Class weighting برای داده‌های نامتوازن
· Early stopping + MLflow tracking
· Export به ONNX + INT8 Quantization
· Fine-tune روی GPU

3) Forensics – جرم‌شناسی خودکار

جمع‌آوری و تحلیل شواهد از Podهای مشکوک.

```bash
cd forensics
bash forensics_setup.sh install
bash forensics_setup.sh case CASE-2026-001
bash forensics_setup.sh analyze CASE-2026-001
bash forensics_setup.sh list
```

ویژگی‌ها:

· Memory dump با gcore یا /proc/kcore
· Volatility 3 با ۱۰ پلاگین
· استخراج خودکار IOC
· Hash + Sign با Cosign
· آپلود به S3
· Chain of Custody

4) Compliance – ISO 27001 / SOC 2 as Code

بررسی انطباق با Conftest + Rego.

```bash
cd compliance
bash compliance_setup.sh install
bash compliance_setup.sh check       # همه
bash compliance_setup.sh iso         # فقط ISO
bash compliance_setup.sh soc2        # فقط SOC 2
bash compliance_setup.sh evidence    # جمع‌آوری شواهد
```

کنترل‌های پیاده‌سازی‌شده:

ISO 27001 SOC 2
A.8 Asset Management CC6 Logical Access
A.9 Access Control CC7 System Operations
A.10 Cryptography CC8 Change Management

5) Red-Team – تست نفوذ خودکار

۸ ماژول تست نفوذ روی خود APZ.

```bash
cd red-team
bash redteam_setup.sh dry-run
bash redteam_setup.sh scan http://apz-dev:5000
bash redteam_setup.sh module auth_bypass
```

ماژول‌ها:

ماژول شدت توضیح
api_fuzz medium-high Fuzzing پارامترها
auth_bypass critical دور زدن احراز هویت
rate_limit medium نبود rate limit
info_disclosure high مسیرهای حساس
ssrf critical SSRF به metadata
injection critical SQLi و Command
k8s_rbac high بررسی RBAC
secret_scan high جستجوی secret

6) Cost – Kubecost + FinOps

```bash
cd cost
bash cost_setup.sh install
bash cost_setup.sh dashboard
```

· گزارش هزینه به تفکیک namespace، component، pod
· هزینه‌ی GPU جدا
· Alert روی spike هزینه
· Dashboard در Grafana

7) Chaos – Chaos Mesh

```bash
cd chaos
bash chaos_setup.sh install
bash chaos_setup.sh apply     # experimentها
bash chaos_setup.sh list
bash chaos_setup.sh stop <name>
```

۱۰ Experiment آماده:

· Network partition, delay, DNS error
· CPU/Memory/IO stress
· Pod kill, failure
· HTTP abort
· Workflow ترکیبی (سناریوی واقعی)

8) SBOM – Syft + Grype

```bash
cd sbom
bash sbom_setup.sh install-tools
bash sbom_setup.sh ci apz-manager:latest
bash sbom_setup.sh k8s
```

· تولید SBOM از ایمیج + سورس
· اسکن آسیب‌پذیری با Grype
· Export به SARIF
· امضا با Cosign
· آپلود به S3

9) Secrets – Vault + External Secrets

```bash
cd secrets
bash secrets_setup.sh install
bash secrets_setup.sh populate
bash secrets_setup.sh apply
bash secrets_setup.sh verify
```

· Vault به‌عنوان Source of Truth
· ExternalSecretها به K8s Secret sync می‌کنند
· چرخش خودکار با rotate
· هیچ secret در Git نیست

10) OnCall – PagerDuty + Opsgenie

```bash
cd oncall
bash oncall_setup.sh apply
bash oncall_setup.sh test critical
bash oncall_setup.sh runbooks
bash oncall_setup.sh show api-down.md
```

· AlertmanagerConfig با routeهای تفصیلی
· PagerDuty + Opsgenie + Slack
· ۹ Runbook آماده
· Postmortem template

11) ArgoCD – GitOps

```bash
cd argocd
bash argocd_setup.sh bootstrap
bash argocd_setup.sh password
bash argocd_setup.sh port
```

· ApplicationSet برای dev/staging/prod
· App of Apps
· Sync Waves
· Notifications به Slack
· PostSync Smoke Test

12) Policy – OPA / Gatekeeper

```bash
cd policy
bash policy_setup.sh bootstrap
bash policy_setup.sh audit
bash policy_setup.sh test
```

۱۰ Constraint:

· :latest ممنوع
· Resources اجباری
· Privileged ممنوع
· runAsNonRoot اجباری
· Registry مجاز
· Labels اجباری
· NodePort ممنوع
· StorageClass اجباری
· Root user ممنوع
· hostPort ممنوع

13) Metrics – Prometheus + Grafana

```bash
cd metrics
bash metrics_setup.sh apply
bash metrics_setup.sh verify
bash metrics_setup.sh dashboard
bash metrics_setup.sh port-graf
```

۳ داشبورد آماده:

· apz-main – Overview
· apz-security – Security deep dive
· apz-cost – Cost / FinOps
· apz-aiops – Anomaly detection

14) Backup – CronJob + Velero

```bash
cd backup
bash backup_setup.sh apply
bash backup_setup.sh test
bash backup_setup.sh list
bash backup_setup.sh restore
```

· SQLite online backup (.backup)
· integrity check
· tar.gz گزارش‌ها + rules
· آپلود به S3 (daily/weekly/monthly)
· Retention + Glacier برای weekly
· Velero برای namespace snapshot

---

📁 ساختار پروژه

```
APZ-Manager/
├── README.md                    ← همین فایل
├── LICENSE                      ← GPLv3
├── VERSION                      ← 1.0.0
├── Makefile                     ← اهداف اصلی (install, run, dist)
├── requirements.txt
├── requirements-android.txt
├── .env.android.example
├── .gitignore
├── .dockerignore
│
├── apz_manager.py               ← CLI + GUI
├── apz_orchestrator.py          ← هماهنگ‌کننده
├── apz_api.py                   ← سرور RESTful
├── ai_analyzer.py               ← پل به Ollama
├── reputation_engine.py         ← اعتبارسنجی چندمنبعی
├── threat_platform.py           ← YARA + IOC + MITRE
├── risk_fusion_engine.py        ← فیوژن ریسک 2.0
├── axml_parser.py               ← دیکودر Manifest
├── sandbox_adapter.py           ← آداپتور Sandbox
├── report_generator.py          ← JSON/HTML/PDF
├── database.py                  ← SQLite
├── logger.py
├── config.yaml
│
├── scripts/                     ← اسکریپت‌های کمکی
│   ├── bootstrap.sh             ← ساخت کل پکیج روی PC
│   ├── release.sh               ← انتشار خودکار
│   ├── ci_setup.sh              ← راه‌اندازی CI/CD
│   ├── docker_setup.sh          ← Docker + Compose
│   ├── setup_gpu.sh             ← GPU + Ollama
│   ├── scan.sh                  ← مانیتور پوشه APK
│   ├── k8s_setup.sh             ← Kubernetes
│   ├── terraform_setup.sh       ← Terraform
│   └── build_zip.sh
│
├── docker/
│   ├── entrypoint.sh
│   ├── healthcheck.sh
│   └── healthcheck-gpu.sh
│
├── Dockerfile                   ← ایمیج اصلی
├── Dockerfile.slim              ← Alpine
├── Dockerfile.proot             ← PDF/weasyprint
├── Dockerfile.gpu               ← CUDA
├── docker-compose.yml
├── docker-compose.gpu.yml
├── docker-compose.ci.yml
├── Makefile.docker
│
├── k8s/                         ← Kubernetes manifests
│   ├── 00-namespace.yaml
│   ├── 01-configmap.yaml
│   ├── 02-secret.example.yaml
│   ├── 03-storage.yaml
│   ├── 10-redis.yaml
│   ├── 11-ollama.yaml
│   ├── 20-api.yaml
│   ├── 21-worker.yaml
│   ├── 30-ingress.yaml
│   └── kustomization.yaml
│
├── terraform/                   ← Infrastructure as Code
│   ├── versions.tf
│   ├── variables.tf
│   ├── main.tf
│   ├── outputs.tf
│   ├── cloud-init.yaml.tftpl
│   └── terraform.tfvars.example
│
├── argocd/                      ← GitOps
│   ├── 00-project.yaml
│   ├── 01-appset-base.yaml
│   ├── 02-appset-addons.yaml
│   ├── 03-notifications.yaml
│   ├── 04-sync-waves-demo.yaml
│   ├── 05-post-sync-smoke.yaml
│   ├── kustomization.yaml
│   └── argocd_setup.sh
│
├── policy/                      ← OPA / Gatekeeper
│   ├── 00-constraint-templates.yaml
│   ├── 01-constraints.yaml
│   ├── 02-psp-alternative.yaml
│   ├── 03-audit-script.sh
│   ├── kustomization.yaml
│   └── policy_setup.sh
│
├── metrics/                     ← Prometheus + Grafana
│   ├── 00-servicemonitor.yaml
│   ├── 01-podmonitor.yaml
│   ├── 02-prometheusrule.yaml
│   ├── 03-grafana-dashboards.yaml
│   ├── 04-grafana-datasource.yaml
│   ├── 05-apz-metrics-exporter.yaml
│   ├── kustomization.yaml
│   └── metrics_setup.sh
│
├── backup/                      ← CronJob + Velero
│   ├── 00-namespace.yaml
│   ├── 01-rbac.yaml
│   ├── 02-secret.example.yaml
│   ├── 03-configmap.yaml
│   ├── 10-cronjob-daily.yaml
│   ├── 11-cronjob-weekly.yaml
│   ├── 12-velero-schedule.yaml
│   ├── 13-restore-job.yaml
│   ├── 14-serviceaccount-irsa.yaml
│   ├── kustomization.yaml
│   └── backup_setup.sh
│
├── cost/                        ← Kubecost
│   ├── 00-namespace.yaml
│   ├── 01-values.yaml
│   ├── 02-grafana-dashboard.yaml
│   ├── 03-prometheusrule.yaml
│   └── cost_setup.sh
│
├── chaos/                       ← Chaos Mesh
│   ├── 00-namespace.yaml
│   ├── 01-install.sh
│   ├── 02-experiments.yaml
│   ├── 03-schedule.yaml
│   └── chaos_setup.sh
│
├── sbom/                        ← Syft + Grype
│   ├── 00-config.yaml
│   ├── 01-scripts.yaml
│   ├── 02-cronjob.yaml
│   ├── 03-github-workflow.yml
│   └── sbom_setup.sh
│
├── secrets/                     ← Vault + ESO
│   ├── 00-namespace.yaml
│   ├── 01-install.sh
│   ├── 02-vault-secrets.yaml
│   ├── 03-secretstore.yaml
│   ├── 04-externalsecrets.yaml
│   ├── 05-vault-config.yaml
│   ├── 06-external-secrets-in-apz.yaml
│   └── secrets_setup.sh
│
├── oncall/                      ← PagerDuty + Opsgenie
│   ├── 00-namespace.yaml
│   ├── 01-alertmanagerconfig.yaml
│   ├── 02-runbooks.yaml
│   ├── 03-runbook-links.yaml
│   ├── 04-pagerduty-setup.md
│   ├── 05-opsgenie-setup.md
│   ├── 06-postmortem-template.md
│   └── oncall_setup.sh
│
├── aiops/                       ← Anomaly Detection
│   ├── requirements.txt
│   ├── 00-namespace.yaml
│   ├── 01-config.yaml
│   ├── 02-cronjob.yaml
│   ├── 03-grafana-dashboard.yaml
│   ├── alert_rules.yaml
│   ├── anomaly_detector.py
│   ├── Dockerfile.aiops
│   └── aiops_setup.sh
│
├── ml-training/                 ← Fine-tune
│   ├── requirements.txt
│   ├── config.yaml
│   ├── extract_features.py
│   ├── train.py
│   ├── evaluate.py
│   ├── export_onnx.py
│   ├── 03-training-job.yaml
│   ├── Dockerfile.ml-training
│   └── ml_training_setup.sh
│
├── forensics/                   ← Volatility + Velero
│   ├── 00-namespace.yaml
│   ├── 01-rbac.yaml
│   ├── 02-config.yaml
│   ├── 03-scripts.yaml
│   ├── 04-case-collector.yaml
│   ├── 05-velero-hooks.yaml
│   ├── 06-case-cr.yaml
│   ├── 07-analysis-job-template.yaml
│   └── forensics_setup.sh
│
├── compliance/                  ← ISO 27001 / SOC 2
│   ├── policies/
│   │   ├── iso27001/
│   │   │   ├── a.8_asset_management.rego
│   │   │   ├── a.9_access_control.rego
│   │   │   └── a.10_cryptography.rego
│   │   └── soc2/
│   │       ├── cc6_logical_access.rego
│   │       ├── cc7_monitoring.rego
│   │       └── cc8_change_management.rego
│   ├── conftest.yaml
│   ├── evidence-collector.sh
│   ├── run-checks.sh
│   ├── report-generator.py
│   ├── github-workflow.yml
│   └── compliance_setup.sh
│
├── red-team/                    ← Self Red-Team
│   ├── 00-config.yaml
│   ├── 01-namespace.yaml
│   ├── 02-cronjob.yaml
│   ├── api_fuzzer.py
│   ├── Dockerfile.redteam
│   ├── README.md
│   └── redteam_setup.sh
│
├── rules/                       ← قوانین YARA
│   └── android_rules.yar
│
├── tests/                       ← Unit Tests
│   ├── test_axml.py
│   ├── test_fusion.py
│   └── test_yara.py
│
└── docs/                        ← مستندات
    ├── USER_GUIDE.md
    ├── API_REFERENCE.md
    ├── ANDROID.md
    ├── ARCHITECTURE.md
    ├── DEPLOYMENT.md
    ├── SECURITY.md
    ├── RUNBOOKS.md
    ├── CONTRIBUTING.md
    └── CHANGELOG.md
```

---

⚙️ پیکربندی

متغیرهای محیطی

متغیر پیش‌فرض توضیح
APZ_DEFAULT_OUTDIR ~/apz-reports پوشه‌ی گزارش‌ها
APZ_DB_PATH ~/apz-reports/apz.db مسیر SQLite
APZ_LOG_LEVEL INFO سطح لاگ
APZ_HTTP_HOST 0.0.0.0 آدرس bind API
APZ_HTTP_PORT 5000 پورت API
APZ_VT_API_KEY – VirusTotal
APZ_HA_API_KEY – Hybrid Analysis
APZ_MD_API_KEY – MetaDefender
APZ_AI_API_KEY – OpenAI (اختیاری)
APZ_AI_ENABLED 0 فعال‌سازی AI
APZ_AI_BACKEND ollama backend AI
OLLAMA_HOST http://ollama:11434 آدرس Ollama
APZ_AI_MODEL qwen2.5:7b-instruct مدل پیش‌فرض
APZ_USE_GPU 0 استفاده از GPU
APZ_SLACK_WEBHOOK – Slack
APZ_WEBHOOK_URL – Webhook عمومی

فایل config.yaml

```yaml
analysis:
  max_file_size_mb: 500
  max_strings: 1000
  timeout_seconds: 300

risk_fusion:
  weights:
    reputation: 0.25
    yara: 0.20
    ioc: 0.15
    manifest: 0.15
    mitre: 0.10
    certificate: 0.08
    sandbox: 0.07

reputation:
  virustotal: true
  hybrid_analysis: true
  metadefender: true
  timeout_seconds: 30

ai:
  enabled: true
  backend: ollama
  summarize: true
  explain_risk: true
  recommend: true
  family_classification: true

reporting:
  formats: [json, html, pdf]
  include_raw: false
```

---

📊 نمونه‌ی خروجی

JSON

```json
{
  "file": "/samples/malware.apk",
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
      "evidence": [
        "android.permission.READ_SMS",
        "android.permission.CAMERA"
      ]
    },
    {
      "title_fa": "YARA",
      "weight": 20,
      "detail_fa": "قوانین YARA فعال شدند.",
      "evidence": [
        "Android_Accessibility_Abuse (critical)",
        "Android_SMS_Interception (high)"
      ]
    }
  ],
  "permissions": ["android.permission.READ_SMS"],
  "mitre": [
    {"id": "T1417", "name": "Input Capture"},
    {"id": "T1636", "name": "Protected User Data"}
  ],
  "iocs": {
    "ip": ["1.2.3.4"],
    "domain": ["malicious.example.com"],
    "url": ["http://malicious.example.com/payload"]
  },
  "ai": {
    "summary": "این APK با ریسک بالا...",
    "risk_explanation": "دلیل اصلی، ترکیب READ_SMS با...",
    "recommendations": ["..."],
    "family": {
      "family_guess": "شواهد کافی نیست",
      "confidence": 45
    }
  },
  "limitations": [
    "تحلیل static/heuristic است و ممکن است برخی رفتارهای داینامیک شناسایی نشوند."
  ]
}
```

HTML

گزارش HTML با Tailwind-like CSS، قابل چاپ و ایمیل، شامل:

· کارت خلاصه‌ی ریسک با رنگ‌بندی
· جدول یافته‌ها
· لیست مجوزها، IOCها، MITRE
· توصیه‌های AI
· محدودیت‌ها

PDF

با weasyprint (فقط روی Docker proot یا Ubuntu). مناسب برای ارسال رسمی.

---

📚 مستندات کامل

سند توضیح
docs/USER_GUIDE.md راهنمای کاربری کامل
docs/API_REFERENCE.md مستندات API
docs/ANDROID.md اجرا روی اندروید
docs/ARCHITECTURE.md معماری داخلی
docs/DEPLOYMENT.md استقرار در محیط‌های مختلف
docs/SECURITY.md ملاحظات امنیتی
docs/RUNBOOKS.md کتاب‌های واکنش به حادثه
docs/CONTRIBUTING.md راهنمای مشارکت
docs/CHANGELOG.md تاریخچه‌ی تغییرات

---

🔐 نکات امنیتی مهم

⚠️ هرگز APKهای ناشناس را روی سیستم خود اجرا نکنید. این ابزار صرفاً تحلیل ایستا انجام می‌دهد و کد APK را اجرا نمی‌کند.

· 🔒 کلیدهای API را در کد ذخیره نکنید – همیشه از متغیرهای محیطی یا Vault استفاده کنید.
· 📁 گزارش‌ها را محرمانه نگه دارید – ممکن است شامل IOC یا SHA-256 فایل‌های مخرب باشند.
· 🐳 Docker containerها را با کاربر non-root اجرا کنید (در همه‌ی Dockerfileها رعایت شده).
· ☸️ Kubernetes را با Gatekeeper + NetworkPolicy + PSA محافظت کنید.
· 🔑 Secrets را در Vault نگهداری کنید، نه در Git.
· 🕵️ Red-Team را فقط روی dev/staging اجرا کنید.
· 📜 Compliance را به‌صورت پیوسته بررسی کنید (روزانه).
· 🧪 Chaos را با احتیاط و در ساعات کم‌ترافیک اجرا کنید.

---

🚀 عملکرد و مقیاس

سرعت تحلیل

فاز زمان (APK 50MB)
تحلیل ایستا ~2s
YARA (500 rule) ~1s
Manifest decode ~0.5s
Reputation (3 API) ~5s (موازی)
AI (Ollama 7B روی T4) ~8s
کل ~16s

مقیاس‌پذیری

سناریو راهکار
< 100 APK/روز Single node + SQLite
100–10K APK/روز K8s + Redis + 3 replicas
10K–1M APK/روز K8s + HPA (8 replicas) + S3 برای گزارش‌ها
1M APK/روز Multi-cluster + Kafka + Celery

منابع

Component CPU RAM GPU Storage
APZ API 500m – 4 1 – 8 Gi – –
Ollama (7B) 4 8 Gi 6 GB VRAM 30 GB
ML Training (fine-tune) 8 24 Gi 16 GB VRAM 50 GB
AIOps 500m – 2 1 – 4 Gi (اختیاری) 10 GB
Forensics (Volatility) 2 – 4 2 – 8 Gi – 100 GB

---

🔧 عیب‌یابی سریع

مشکل راه‌حل
ModuleNotFoundError: androguard pip install -r requirements.txt
خطای YARA compile قوانین در rules/ را بررسی کنید
API key missing متغیرهای محیطی را تنظیم کنید
Permission denied (ویندوز) به‌عنوان Administrator اجرا کنید
weasyprint روی Android از Ubuntu proot استفاده کنید یا PDF را نادیده بگیرید
GPU detected but not used nvidia-container-toolkit را نصب/پیکربندی کنید
Gatekeeper pod را رد می‌کند bash policy/policy_setup.sh audit
ArgoCD OutOfSync argocd app diff <app>
Pod CrashLoopBackOff kubectl describe pod + kubectl logs --previous
Ollama slow APZ_AI_MODEL=llama3.2:3b-instruct (سبک‌تر)
PVC Pending بررسی StorageClass و kubectl get pv
Backup failed kubectl -n apz-backup logs job/<latest>

راهنمای کامل: docs/TROUBLESHOOTING.md

---

🤝 مشارکت

ما از مشارکت شما استقبال می‌کنیم! برای همکاری:

1. Fork کنید
2. شاخه‌ی جدید بسازید: git checkout -b feature/amazing-feature
3. Commit کنید: git commit -m 'feat: add amazing feature'
4. Push کنید: git push origin feature/amazing-feature
5. Pull Request باز کنید

استانداردها

· PEP 8 برای Python
· Conventional Commits برای پیام‌های commit
· Pytest برای تست‌ها
· Ruff + Black برای formatting
· Conftest برای policyها

Workflow

```bash
# 1) نصب dev dependencies
pip install -r requirements.txt
pip install pytest ruff black

# 2) اجرای تست‌ها
make test

# 3) بررسی lint
ruff check .
black --check .

# 4) بررسی policy
bash compliance/run-checks.sh all

# 5) ساخت ZIP برای تست
make dist
```

Code of Conduct

لطفاً CODE_OF_CONDUCT.md را بخوانید.

---

📜 مجوز

این پروژه تحت مجوز GNU General Public License v3.0 منتشر شده است.

```
APZ Manager – APK Security Analysis Platform
Copyright (C) 2026  APZ Security Team

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
```

برای جزئیات بیشتر LICENSE را ببینید.

---

📬 ارتباط با تیم

کانال آدرس
📧 ایمیل support@apz-security.com
🌐 GitHub github.com/your-org/apz-manager
📚 مستندات docs.apz-security.com
🐛 Issues GitHub Issues
💬 Discussions GitHub Discussions
🔒 Security security@apz-security.com (PGP: key)

---

🙏 قدردانی

از کتابخانه‌ها و پروژه‌های متن‌باز زیر سپاسگزاریم:

هسته

· androguard – تحلیل APK
· yara-python – اسکنر YARA
· Flask – چارچوب وب
· SQLAlchemy – ORM
· WeasyPrint – تولید PDF

AI / ML

· Ollama – سرور LLM محلی
· PyTorch – Deep Learning
· HuggingFace Transformers – مدل‌ها
· Prophet – Time Series

Cloud Native

· Kubernetes
· ArgoCD
· Prometheus
· Grafana
· Chaos Mesh
· Gatekeeper
· Velero
· Vault
· Kubecost

Security

· Syft / Grype
· Volatility 3
· Cosign
· Conftest

---

<div align="center">

🛡️ APZ Manager

ساخته شده با ❤️ برای تیم‌های امنیت

⬆ بازگشت به بالا

---

Version: 1.0.0 | Last Updated: 2026-10-06 | License: GPLv3

</div>
```

---

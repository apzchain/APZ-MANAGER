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

[معرفی](#-معرفی) • [ویژگیها](#-ویژگیهای-اصلی) • [نصب](#-نصب-و-راهاندازی) • [استفاده](#-نحوهی-استفاده) • [معماری](#-معماری-و-زنجیرهی-apz) • [مستندات](#-مستندات-کامل)

</div>

---

## 📋 فهرست مطالب

- [معرفی](#-معرفی)
- [ویژگیهای اصلی](#-ویژگیهای-اصلی)
- [معماری و زنجیرهی APZ](#-معماری-و-زنجیرهی-apz)
- [پیشنیازها](#-پیشنیازها)
- [نصب و راهاندازی](#-نصب-و-راهاندازی)
  - [نصب روی PC / Server](#نصب-روی-pc--server)
  - [نصب روی Android (Termux)](#نصب-روی-android-termux)
  - [نصب با Docker](#نصب-با-docker)
  - [نصب با Docker + GPU (AI محلی)](#نصب-با-docker--gpu-ai-محلی)
  - [نصب روی Kubernetes](#نصب-روی-kubernetes)
  - [Provision با Terraform](#provision-با-terraform)
- [نحوهی استفاده](#-نحوهی-استفاده)
  - [حالت CLI](#a-حالت-cli)
  - [حالت GUI](#b-حالت-gui)
  - [RESTful API](#c-restful-api)
  - [Kubernetes / GitOps](#d-kubernetes--gitops)
- [پکیجهای تکمیلی](#-پکیجهای-تکمیلی)
  - [AIOps – تشخیص ناهنجاری](#1-aiops--تشخیص-ناهنجاری)
  - [ML Training – آموزش مدل اختصاصی](#2-ml-training--آموزش-مدل-اختصاصی)
  - [Forensics – جرمشناسی خودکار](#3-forensics--جرمشناسی-خودکار)
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
- [نمونهی خروجی](#-نمونهی-خروجی)
- [مستندات کامل](#-مستندات-کامل)
- [نکات امنیتی](#-نکات-امنیتی-مهم)
- [عملکرد و مقیاس](#-عملکرد-و-مقیاس)
- [عیبیابی](#-عیبیابی-سریع)
- [مشارکت](#-مشارکت)
- [مجوز](#-مجوز)
- [ارتباط با تیم](#-ارتباط-با-تیم)
- [قدردانی](#-قدردانی)

---

## 🔰 معرفی

**APZ Manager** یک پلتفرم جامع، ماژولار و متنباز برای **تحلیل امنیتی APK** است که بهصورت **آفلاین** و **بدون نیاز به Android SDK** کار میکند. این ابزار با ترکیب:

- تحلیل ایستای پیشرفته
- اعتبارسنجی چندمنبعی (VirusTotal، Hybrid Analysis، MetaDefender)
- موتور YARA با قوانین سفارشی
- نگاشت به MITRE ATT&CK
- موتور فیوژن ریسک قابل توضیح (XAI)
- شبیهسازی رفتار پویا (Sandbox)
- **قابلیت اجرا روی Android، Docker، Kubernetes و Clusterهای Cloud**
- **AI محلی با Ollama (بدون ارسال داده به بیرون)**
- **Observability کامل (Metrics + Logs + Traces)**
- **GitOps، Policy as Code، Compliance as Code**

یک **گزارش امنیتی جامع، قابل اعتماد و مقیاسپذیر** ارائه میدهد.

### 🎯 چرا APZ Manager؟

| چالش | راهحل APZ |
|---|---|
| دادههای حساس را نمیتوان به سرویسهای ابری فرستاد | **AI محلی با Ollama** – هیچ دادهای خارج نمیشود |
| تحلیل دستهای APKها زمانبر است | **پردازش موازی + Queue** با Redis |
| نیاز به استقرار روی cloud/on-prem | **Docker + K8s + Terraform** |
| Compliance و Audit | **ISO 27001 / SOC 2 as Code** |
| مقیاسپذیری و پایداری | **ArgoCD + HPA + Chaos Engineering** |
| تحلیل فوری روی دستگاه | **اجرا روی Android با Termux** |

---

## ✨ ویژگیهای اصلی

| ویژگی | توضیح |
|---|---|
| 🔍 **تحلیل ایستای پیشرفته** | استخراج رشتههای مشکوک، کتابخانههای native، فایلهای DEX، ABI، حجم و entropy |
| 📄 **دیکودر AndroidManifest** | با `androguard` – مجوزها، فعالیتها، سرویسها، receiverها و کامپوننتهای exported |
| 🧠 **موتور فیوژن ریسک ۲.۰** | ترکیب ۷ دسته شواهد با وزندهی هوشمند و خروجی قابل توضیح (XAI) |
| 🌐 **اعتبارسنجی چندمنبعی** | VirusTotal، Hybrid Analysis، MetaDefender Cloud، IOC محلی |
| 🐍 **اسکنر YARA** | قوانین داخلی + قوانین سفارشی `.yar` با پشتیبانی از meta-data |
| 🎯 **نگاشت MITRE ATT&CK** | اتصال یافتهها به تکنیکهای شناختهشده |
| 📊 **گزارشدهی حرفهای** | JSON، HTML (قابل چاپ)، PDF (با weasyprint) |
| 🖥️ **رابط گرافیکی (GUI)** | محیط Tkinter با درختواره، Progress Bar و دکمههای عملیاتی |
| ⌨️ **CLI کامل** | اجرا بدون رابط برای اتوماسیون و CI/CD |
| 🗄️ **پایگاه داده SQLite** | ذخیرهسازی تاریخچه، Reputation و IOCها |
| 🌐 **RESTful API** | سرور Flask برای یکپارچگی با SIEM/SOAR |
| 🧩 **Orchestrator** | مدیریت زنجیره، پردازش همزمان، خلاصههای آماری |
| 🧪 **Sandbox (اختیاری)** | شبیهسازی رفتار بدون اجرای واقعی کد |
| 🤖 **AI محلی (Ollama)** | خلاصه، توضیح ریسک، توصیهها، طبقهبندی family |
| 📱 **اجرا روی Android** | با Termux – نصب یکدستوری با `make install` |
| 🐳 **Docker + GPU** | ایمیجهای slim / main / gpu / aiops / ml-training / redteam |
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
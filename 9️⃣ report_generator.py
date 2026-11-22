import json
import os
from pathlib import Path

from logger import get_logger

log = get_logger("report")

RISK_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#65a30d",
    "MINIMAL": "#16a34a",
}


def write_json(report, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return path


def write_html(report, path):
    findings_html = "".join(
        f"<tr><td>{f.get('title_fa') or f.get('category', '')}</td>"
        f"<td>{f.get('weight', 0)}</td>"
        f"<td>{f.get('detail_fa', '')}</td></tr>"
        for f in report.get("findings", [])
    ) or "<tr><td colspan='3'>—</td></tr>"

    perms_html = "".join(
        f"<li><code>{p}</code></li>"
        for p in report.get("manifest", {}).get("dangerous_permissions", [])
    ) or "<li>—</li>"

    iocs = report.get("threat", {}).get("iocs", {})
    ioc_html = "".join(
        f"<li><b>{k}</b>: {', '.join(v) if v else '—'}</li>"
        for k, v in iocs.items()
    ) or "<li>—</li>"

    mitre_html = "".join(
        f"<li><code>{m['id']}</code> — {m['name']}</li>"
        for m in report.get("threat", {}).get("mitre", [])
    ) or "<li>—</li>"

    ai = report.get("ai") or {}
    ai_block = ""
    if ai:
        recs = "".join(f"<li>{r}</li>" for r in ai.get("recommendations", []))
        ai_block = f"""
        <div class="card"><h2>تحلیل AI</h2>
        <p><b>خلاصه:</b> {ai.get('summary', '')}</p>
        <p><b>توضیح ریسک:</b> {ai.get('risk_explanation', '')}</p>
        <p><b>خانواده‌ی احتمالی:</b> {ai.get('family', {}).get('family_guess', '')}
           (اطمینان: {ai.get('family', {}).get('confidence', 0)})</p>
        <h3>توصیه‌ها</h3><ul>{recs or '<li>—</li>'}</ul></div>"""

    color = RISK_COLORS.get(report.get("risk_level"), "#6b7280")
    html = f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<title>APZ Report – {report.get('sha256', '')[:12]}</title>
<style>
body{{font-family:system-ui,-apple-system,sans-serif;margin:2rem;background:#f9fafb;color:#111827}}
.card{{background:#fff;padding:1.5rem;border-radius:.75rem;box-shadow:0 1px 3px rgba(0,0,0,.1);margin-bottom:1rem}}
.risk{{background:{color};color:#fff;padding:1rem 1.5rem;border-radius:.75rem}}
.risk h1{{margin:0;font-size:2rem}}
table{{width:100%;border-collapse:collapse}}
th,td{{padding:.6rem;text-align:right;border-bottom:1px solid #e5e7eb}}
th{{background:#f3f4f6}}
code{{background:#f3f4f6;padding:.1rem .35rem;border-radius:.25rem}}
</style></head>
<body>
<div class="risk">
  <h1>ریسک: {report.get('risk_level', '—')} ({report.get('risk_score', 0)}/100)</h1>
  <p>اطمینان: {report.get('confidence', 0)}% &nbsp;|&nbsp; SHA256: <code>{report.get('sha256', '')}</code></p>
</div>

<div class="card"><h2>فایل</h2>
  <p><b>مسیر:</b> {report.get('file', '')}</p>
  <p><b>حجم:</b> {report.get('size', 0):,} بایت</p>
  <p><b>زمان تحلیل:</b> {report.get('analyzed_at', '')}</p>
</div>

<div class="card"><h2>یافته‌ها</h2>
<table><thead><tr><th>عنوان</th><th>وزن</th><th>جزئیات</th></tr></thead>
<tbody>{findings_html}</tbody></table></div>

<div class="card"><h2>مجوزهای خطرناک</h2><ul>{perms_html}</ul></div>
<div class="card"><h2>IOCها</h2><ul>{ioc_html}</ul></div>
<div class="card"><h2>MITRE ATT&CK</h2><ul>{mitre_html}</ul></div>
{ai_block}
<div class="card"><h2>محدودیت‌ها</h2>
<ul>{''.join(f'<li>{x}</li>' for x in report.get('limitations', []))}</ul></div>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


def write_pdf(report, path):
    try:
        from weasyprint import HTML
    except ImportError:
        log.warning("weasyprint not installed; skipping PDF")
        return None

    tmp = str(path).replace(".pdf", ".tmp.html")
    write_html(report, tmp)
    try:
        HTML(filename=tmp).write_pdf(path)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    return path


def generate(report, outdir, formats=("json", "html", "pdf")):
    Path(outdir).mkdir(parents=True, exist_ok=True)
    base = report.get("sha256", "unknown")[:16]
    written = {}
    if "json" in formats:
        written["json"] = write_json(report, os.path.join(outdir, f"{base}.json"))
    if "html" in formats:
        written["html"] = write_html(report, os.path.join(outdir, f"{base}.html"))
    if "pdf" in formats:
        p = write_pdf(report, os.path.join(outdir, f"{base}.pdf"))
        if p:
            written["pdf"] = p
    return written
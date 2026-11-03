# APZ Manager — Android Threat Intelligence & Malware Analysis Platform

Pipeline:

APK
 -> SHA-256
 -> Static APK/DEX/Manifest analysis
 -> Android IOC extraction
 -> YARA rule layer
 -> MITRE ATT&CK evidence mapping
 -> Multi-source Reputation
 -> Isolated Dynamic Sandbox adapter
 -> AI Security Assistant
 -> Risk / confidence / explainable report

## Safety boundary

Untrusted APK execution is isolated from the Windows GUI. The current package
does static analysis only and reports dynamic sandbox as not configured.

## Risk fusion

The next risk engine should combine:
- reputation consensus
- YARA severity
- IOC confidence
- manifest/permission risk
- ATT&CK technique evidence
- dynamic behavior evidence
- signing/certificate anomalies
- package/update lineage

No single indicator should automatically label an APK malicious.

## Production dynamic sandbox

Use a dedicated Android emulator/VM or remote sandbox with snapshot restore,
restricted networking and telemetry collection. The APZ desktop app should
only submit jobs and consume signed JSON results.

## AI layer

AI should explain evidence, correlate findings and produce Persian analyst
narratives. It should not invent detections and should cite the underlying
evidence IDs.

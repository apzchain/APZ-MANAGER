# APZ Android YARA Rules

The Windows baseline uses a dependency-free rule layer so the application can
run without native YARA dependencies.

For production, these rule definitions should be migrated to real YARA rules
and scanned in an isolated worker.

Recommended rule families:
- dynamic code loading
- command execution
- accessibility abuse
- SMS/OTP interception
- boot persistence
- suspicious WebView JavaScript
- native library loading
- credential/token theft
- anti-analysis
- known Android malware families

Do not run untrusted APKs in the desktop process.

# APZ Manager — Windows Edition

## What this is
A native Windows desktop security manager focused on APK static analysis and
an AI Security Assistant. It does not require Android Studio or Google Play
services.

## Run
Install Python 3.11+ on Windows, then double-click `run_windows.bat`.

## Build EXE
Double-click `build_windows.bat`.

It installs PyInstaller and creates:
`dist\APZ-Manager.exe`

The EXE is an unpackaged single-file desktop application. For enterprise or
Store distribution, Microsoft recommends modern packaging such as MSIX in
many scenarios. MSIX packages must be signed for trusted installation.

## AI
Without an API key, the app uses its local Persian explanation engine.
For an OpenAI-compatible endpoint:
1. Set Windows environment variable `APZ_AI_API_KEY`.
2. Start the app.
3. Enter endpoint/model in the bottom bar.
4. Use AI Assistant.

Do not put API keys into source code.

## APK analysis
The Windows edition currently performs:
- APK/ZIP validation
- SHA-256
- DEX inventory
- native ABI inventory
- suspicious-string heuristics
- partial permission discovery from readable content
- weighted risk score
- confidence score
- Persian evidence report
- JSON export

A full Android binary Manifest decoder is intentionally not bundled in this
portable edition. For a next build, integrate aapt2/apkanalyzer or a pure
Python binary-AXML parser to expose exact permissions/components/exported
flags.

## Important
Static heuristics are not proof of malware. A suspicious string can be a
legitimate library or documentation. Treat the result as triage evidence.

## Windows packaging
Microsoft documents MSIX as a modern packaging/deployment format and also
provides the MSIX Packaging Tool for converting existing EXE/MSI applications.
For direct distribution, a signed installer is recommended.

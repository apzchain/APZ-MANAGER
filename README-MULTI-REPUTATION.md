# APZ Manager — Multi-Source Reputation Engine

Providers:
- VirusTotal API v3: SHA-256 file report lookup.
- Hybrid Analysis Falcon Sandbox API v2: hash search.
- MetaDefender Cloud API v4: SHA-256 hash lookup.
- Local IOC CSV database.

Environment variables:
- APZ_VT_API_KEY
- APZ_HA_API_KEY
- APZ_MD_API_KEY
- APZ_IOC_DB (optional custom path)

Run `set_reputation_keys.bat` to configure cloud API keys.

## Privacy
The reputation workflow is hash-first. It sends the SHA-256 to the configured
cloud providers. It does not upload the APK through these reputation lookup
calls.

## Consensus
The engine reports:
- malicious: 2+ independent malicious providers
- likely_malicious: exactly 1 malicious provider
- suspicious: one or more suspicious providers without a malicious consensus
- no_threat: available providers found no malicious/suspicious verdict
- unknown: no usable provider result

This is deliberately conservative and is not a substitute for dynamic
sandboxing or human review.

## Local IOC format

```csv
sha256,verdict,source,note
0123...abcd,malicious,internal-feed,known Android sample
```

Keep the local IOC file private if it contains proprietary intelligence.

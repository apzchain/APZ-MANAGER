# APZ Risk Fusion Engine 2.0

## Evidence model

Risk is fused from seven categories:

| Category | Weight |
|---|---:|
| Reputation | 25% |
| YARA | 20% |
| Android IOC | 15% |
| Manifest / Permission | 15% |
| MITRE ATT&CK | 10% |
| Certificate | 5% |
| Dynamic Sandbox | 10% |

The score is explainable. Each category creates an Evidence object containing:
category, score, weight, confidence, severity, source and evidence ID.

## Verdict bands

- 0–19: no strong indicator
- 20–39: low risk
- 40–64: medium/suspicious
- 65–84: high risk
- 85–100: critical

Malicious reputation consensus or strong dynamic malicious behavior can elevate
the verdict even when the weighted score is lower.

## Important semantics

"Unknown" is not "clean". Missing evidence lowers confidence rather than
automatically lowering the risk.

The engine is deliberately conservative and explainable. It does not claim
malware solely because an APK requests a permission or triggers one heuristic.

## AI integration

The AI Security Assistant should receive only the structured `risk_fusion`
object plus supporting evidence. The model should:
1. explain why each category contributed to the score;
2. distinguish facts from hypotheses;
3. mention limitations;
4. never invent detections;
5. cite evidence IDs in its Persian explanation.

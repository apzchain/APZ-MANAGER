from risk_fusion_engine import RiskFusionEngine2

sample = {
    "reputation":{"providers":[
        {"available":True,"verdict":"malicious"},
        {"available":True,"verdict":"suspicious"},
        {"available":True,"verdict":"no_threat"},
    ]},
    "yara_hits":[{"severity":"high","rule":"Android_DynamicCode"}],
    "android_iocs":[{"kind":"url","value":"https://example.invalid","severity":"medium"}],
    "manifest":{"dangerous_permissions":3,"exported_dangerous":1},
    "mitre_attack":[{"technique":"T1620","severity":"high"}],
    "certificate":{"anomalies":1},
    "dynamic_sandbox":{"status":"not_configured"}
}

r=RiskFusionEngine2().fuse(sample)
print("score:",r.score)
print("level:",r.level)
print("confidence:",r.confidence)
print("verdict:",r.verdict)
print("categories:",r.category_scores)

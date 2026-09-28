import json

from ai.fraud_ai import FRAUD_TYPES, FraudAIAnalyzer, build_ai_context


class FakeBob:
    model = "test-model"

    def chat_text(self, messages, **kwargs):
        return json.dumps({
            "fraud_type_prediction": {
                "primary_type": "Money Mule / Layering",
                "estimated_probability_pct": 72,
                "distribution": [
                    {"fraud_type": FRAUD_TYPES[0], "estimated_probability_pct": 5, "reasons": ["payment activity"]},
                    {"fraud_type": FRAUD_TYPES[1], "estimated_probability_pct": 3, "reasons": ["SIM evidence"]},
                    {"fraud_type": FRAUD_TYPES[2], "estimated_probability_pct": 4, "reasons": ["communication evidence"]},
                    {"fraud_type": FRAUD_TYPES[3], "estimated_probability_pct": 72, "reasons": ["rapid redistribution"]},
                    {"fraud_type": FRAUD_TYPES[4], "estimated_probability_pct": 6, "reasons": ["device evidence"]},
                    {"fraud_type": FRAUD_TYPES[5], "estimated_probability_pct": 10, "reasons": ["identity evidence"]},
                ],
                "explanation": "Synthetic test response",
            },
            "role_analysis": {
                "prime_suspect": {"subject_id": "S001", "name": "Suspect Alpha", "confidence_pct": 82, "reasons": ["high network activity"], "evidence_ids": ["E1"]},
                "kingpin_candidate": {"subject_id": "S001", "name": "Suspect Alpha", "confidence_pct": 64, "reasons": ["central coordinator pattern"], "evidence_ids": ["E1"]},
                "mule_candidates": [{"subject_id": "M001", "name": "Mule 1", "confidence_pct": 88, "reasons": ["rapid fan-out"], "evidence_ids": ["E2"]}],
            },
            "cross_checks": ["Check original CDR"],
            "limitations": ["Synthetic test"],
        })


analysis = {
    "analysis": {"case_id": "CASE001", "case_title": "Test", "analysis_version": "1.0"},
    "subject_profiles": [
        {"subject_id": "S001", "name": "Suspect Alpha", "role": "SUSPECT", "role_hypotheses": [{"role": "COORDINATOR_CANDIDATE"}],
         "identifiers": {"person_ids": ["S001"], "account_ids": [], "phone_numbers": [], "sim_ids": [], "device_ids": [], "imeis": [], "ip_addresses": []},
         "statistics": {"unique_counterparties": 8, "money_out_inr": 90000}, "relationships": [], "sim_events": [], "timeline": [], "evidence_ids": ["E1"]},
        {"subject_id": "M001", "name": "Mule 1", "role": "MULE", "role_hypotheses": [{"role": "MULE"}],
         "identifiers": {"person_ids": ["M001"], "account_ids": [], "phone_numbers": [], "sim_ids": [], "device_ids": [], "imeis": [], "ip_addresses": []},
         "statistics": {"unique_counterparties": 5, "money_out_inr": 80000}, "relationships": [], "sim_events": [], "timeline": [], "evidence_ids": ["E2"]},
    ],
    "findings": [{"finding_id": "F1", "subject_id": "M001", "pattern_type": "RAPID_FAN_OUT", "confidence": 0.9, "summary": "Rapid redistribution", "evidence_ids": ["E2"], "details": {}}],
    "case_brief": {"summary": {}},
    "data_quality": {},
}

ctx = build_ai_context(analysis)
assert {x["subject_id"] for x in ctx["top_candidate_profiles"]} == {"S001", "M001"}
result = FraudAIAnalyzer(FakeBob()).analyze(analysis)
assert result["fraud_type_prediction"]["primary_type"] in FRAUD_TYPES
assert round(sum(x["estimated_probability_pct"] for x in result["fraud_type_prediction"]["distribution"]), 1) == 100.0
assert result["role_analysis"]["prime_suspect"]["subject_id"] == "S001"
print("AI integration tests passed")

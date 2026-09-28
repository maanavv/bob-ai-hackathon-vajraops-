from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
import re
from typing import Any, Dict, Iterable, List, Optional

from .bob_client import BobClient, BobAPIError


FRAUD_TYPES = [
    "UPI / Payment Fraud",
    "SIM Swap / Account Takeover",
    "Phishing / Vishing / Smishing",
    "Money Mule / Layering",
    "Remote Access / Device Takeover",
    "Identity / Impersonation Fraud",
]

ROLE_NAMES = ("PRIME_SUSPECT", "KINGPIN_CANDIDATE", "MULE_CANDIDATE")


SYSTEM_PROMPT = f"""
You are an explainable cyber-fraud network analysis model.
You will receive an ANALYZED CASE produced by deterministic evidence-processing code.
You are NOT receiving raw evidence.

Your job:
1. Classify the most plausible primary fraud pattern from EXACTLY these six classes:
   {json.dumps(FRAUD_TYPES)}
2. Give an estimated probability percentage for each class. These are model estimates,
   not statistically calibrated probabilities. They must sum to 100.
3. Identify a PRIME_SUSPECT candidate, a KINGPIN_CANDIDATE if evidence supports one,
   and up to 5 MULE_CANDIDATEs.
4. Give a confidence percentage for every role hypothesis.
5. Ground every role and fraud conclusion in the supplied finding IDs, evidence IDs,
   relationships, transaction statistics, SIM/device indicators, or explicit source role.
6. Never invent a name, identifier, transaction, evidence ID, relationship, or fact.
7. Treat all role labels as investigative hypotheses, not declarations of guilt.
8. If the evidence is insufficient, return null candidate fields and explain why.

Return ONLY valid JSON with this exact top-level structure:
{{
  "fraud_type_prediction": {{
    "primary_type": "string",
    "estimated_probability_pct": 0,
    "distribution": [
      {{"fraud_type":"string","estimated_probability_pct":0,"reasons":["..."]}}
    ],
    "explanation": "string"
  }},
  "role_analysis": {{
    "prime_suspect": {{"subject_id":"string|null","name":"string|null","confidence_pct":0,"reasons":[],"evidence_ids":[]}},
    "kingpin_candidate": {{"subject_id":"string|null","name":"string|null","confidence_pct":0,"reasons":[],"evidence_ids":[]}},
    "mule_candidates": [
      {{"subject_id":"string","name":"string","confidence_pct":0,"reasons":[],"evidence_ids":[]}}
    ]
  }},
  "cross_checks": [],
  "limitations": []
}}
""".strip()


def _clean_json_text(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.I)
        text = re.sub(r"\s*```$", "", text)
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return text[start : end + 1]
    return text


def _pct(value: Any, default: float = 0.0) -> float:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return default
    return round(max(0.0, min(100.0, n)), 1)


def _top(items: Iterable[Dict[str, Any]], n: int) -> List[Dict[str, Any]]:
    return list(items)[:n]


def _profile_signal_score(profile: Dict[str, Any], findings_by_subject: Dict[str, List[Dict[str, Any]]]) -> float:
    sid = profile.get("subject_id", "")
    stats = profile.get("statistics", {})
    role = str(profile.get("role") or "").upper()
    hyps = {str(x.get("role", "")).upper() for x in profile.get("role_hypotheses", [])}
    finding_types = {str(f.get("pattern_type", "")).upper() for f in findings_by_subject.get(sid, [])}

    score = 0.0
    score += {"SUSPECT": 35, "ACCUSED": 35, "KINGPIN": 50, "MULE": 30, "VICTIM": 5}.get(role, 0)
    score += 25 if "COORDINATOR_CANDIDATE" in hyps else 0
    score += 20 if "MULE" in hyps else 0
    score += 15 if "SIM_SWAP_ASSOCIATED" in hyps else 0
    score += 18 if "RAPID_FAN_OUT" in finding_types else 0
    score += 12 if "RAPID_FAN_IN" in finding_types else 0
    score += 12 if "CIRCULAR_MONEY_FLOW" in finding_types else 0
    score += 8 if "SHARED_DEVICE" in finding_types else 0
    score += 6 if "SHARED_IP" in finding_types else 0
    score += min(18, stats.get("unique_counterparties", 0) * 1.5)
    score += min(20, stats.get("money_out_inr", 0) / 10000)
    return score


def build_ai_context(analysis: Dict[str, Any], *, max_candidates: int = 12) -> Dict[str, Any]:
    """Create a compact, evidence-grounded view for Bob.

    The full analysis.json can be large. Sending this compact summary reduces
    inference cost and forces Bob to work from the derived evidence rather than
    hallucinating around irrelevant raw records.
    """
    profiles = analysis.get("subject_profiles", [])
    findings = analysis.get("findings", [])
    findings_by_subject: Dict[str, List[Dict[str, Any]]] = {}
    for finding in findings:
        findings_by_subject.setdefault(str(finding.get("subject_id", "")), []).append(finding)

    ranked = sorted(
        profiles,
        key=lambda p: _profile_signal_score(p, findings_by_subject),
        reverse=True,
    )[:max_candidates]

    compact_profiles = []
    for p in ranked:
        ids = p.get("identifiers", {})
        stats = p.get("statistics", {})
        rels = _top(p.get("relationships", []), 12)
        compact_profiles.append({
            "subject_id": p.get("subject_id", ""),
            "name": p.get("name", ""),
            "source_role": p.get("role", ""),
            "role_hypotheses": p.get("role_hypotheses", []),
            "identifier_counts": {
                "person_ids": len(ids.get("person_ids", [])),
                "account_ids": len(ids.get("account_ids", [])),
                "phone_numbers": len(ids.get("phone_numbers", [])),
                "sim_ids": len(ids.get("sim_ids", [])),
                "devices": len(ids.get("device_ids", [])) + len(ids.get("imeis", [])),
                "ips": len(ids.get("ip_addresses", [])),
            },
            "statistics": stats,
            "relationships": rels,
            "sim_events": _top(p.get("sim_events", []), 8),
            "recent_timeline": _top(p.get("timeline", []), 10),
            "evidence_ids": _top(p.get("evidence_ids", []), 20),
            "derived_findings": _top(findings_by_subject.get(str(p.get("subject_id", "")), []), 10),
        })

    finding_summary = []
    for f in findings:
        finding_summary.append({
            "finding_id": f.get("finding_id", ""),
            "subject_id": f.get("subject_id", ""),
            "pattern_type": f.get("pattern_type", ""),
            "confidence": f.get("confidence", 0),
            "summary": f.get("summary", ""),
            "evidence_ids": _top(f.get("evidence_ids", []), 10),
            "details": f.get("details", {}),
        })

    case_meta = analysis.get("analysis", {})
    brief = analysis.get("case_brief", {})
    return {
        "case": {
            "case_id": case_meta.get("case_id", ""),
            "case_title": case_meta.get("case_title", ""),
            "analysis_version": case_meta.get("analysis_version", ""),
        },
        "summary": brief.get("summary", {}),
        "pattern_types_detected": sorted({str(f.get("pattern_type", "")) for f in findings if f.get("pattern_type")}),
        "findings": finding_summary,
        "top_candidate_profiles": compact_profiles,
        "data_quality": analysis.get("data_quality", {}),
    }


class FraudAIAnalyzer:
    def __init__(self, client: BobClient):
        self.client = client

    def analyze(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        context = build_ai_context(analysis)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": "ANALYZED CASE (JSON):\n" + json.dumps(context, ensure_ascii=False, separators=(",", ":")),
            },
        ]
        raw = self.client.chat_text(messages, temperature=0.05, max_tokens=2800)
        parsed = self._parse_and_validate(raw)
        parsed["ai_metadata"] = {
            "provider": "IBM Bob",
            "model": self.client.model,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input_scope": "derived_analysis_only",
            "probability_note": "Estimated model probabilities; not statistically calibrated.",
        }
        return parsed

    def _parse_and_validate(self, raw: str) -> Dict[str, Any]:
        try:
            data = json.loads(_clean_json_text(raw))
        except json.JSONDecodeError as exc:
            raise BobAPIError(f"Bob did not return the required JSON schema: {raw[:1500]}") from exc

        prediction = data.get("fraud_type_prediction") or {}
        distribution = prediction.get("distribution") or []
        normalized = []
        by_type = {str(x.get("fraud_type")): x for x in distribution if isinstance(x, dict)}
        for fraud_type in FRAUD_TYPES:
            row = by_type.get(fraud_type, {})
            normalized.append({
                "fraud_type": fraud_type,
                "estimated_probability_pct": _pct(row.get("estimated_probability_pct")),
                "reasons": [str(x) for x in (row.get("reasons") or [])][:4],
            })
        total = sum(x["estimated_probability_pct"] for x in normalized)
        if total <= 0:
            raise BobAPIError("Bob returned zero probability across all fraud types.")
        # Normalize the six outputs to exactly 100 for UI consistency.
        for row in normalized:
            row["estimated_probability_pct"] = round(row["estimated_probability_pct"] * 100 / total, 1)
        correction = round(100.0 - sum(x["estimated_probability_pct"] for x in normalized), 1)
        normalized[-1]["estimated_probability_pct"] = round(normalized[-1]["estimated_probability_pct"] + correction, 1)

        primary = prediction.get("primary_type")
        if primary not in FRAUD_TYPES:
            primary = max(normalized, key=lambda x: x["estimated_probability_pct"])["fraud_type"]

        data["fraud_type_prediction"] = {
            "primary_type": primary,
            "estimated_probability_pct": _pct(prediction.get("estimated_probability_pct")),
            "distribution": normalized,
            "explanation": str(prediction.get("explanation") or ""),
        }
        if not data["fraud_type_prediction"]["estimated_probability_pct"]:
            primary_row = next(x for x in normalized if x["fraud_type"] == primary)
            data["fraud_type_prediction"]["estimated_probability_pct"] = primary_row["estimated_probability_pct"]

        roles = data.get("role_analysis") or {}
        prime = self._normalize_candidate(roles.get("prime_suspect"))
        kingpin = self._normalize_candidate(roles.get("kingpin_candidate"))
        mules = [self._normalize_candidate(x) for x in (roles.get("mule_candidates") or []) if isinstance(x, dict)]
        mules = [x for x in mules if x.get("subject_id")][:5]
        data["role_analysis"] = {
            "prime_suspect": prime,
            "kingpin_candidate": kingpin,
            "mule_candidates": mules,
        }
        data["cross_checks"] = [str(x) for x in (data.get("cross_checks") or [])][:10]
        data["limitations"] = [str(x) for x in (data.get("limitations") or [])][:10]
        return data

    @staticmethod
    def _normalize_candidate(candidate: Any) -> Dict[str, Any]:
        if not isinstance(candidate, dict):
            return {"subject_id": None, "name": None, "confidence_pct": 0.0, "reasons": [], "evidence_ids": []}
        return {
            "subject_id": candidate.get("subject_id"),
            "name": candidate.get("name"),
            "confidence_pct": _pct(candidate.get("confidence_pct")),
            "reasons": [str(x) for x in (candidate.get("reasons") or [])][:5],
            "evidence_ids": [str(x) for x in (candidate.get("evidence_ids") or [])][:15],
        }
